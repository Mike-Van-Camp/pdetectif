"""
Command-line interface for PDetectiF.

Provides a comprehensive CLI for PDF security analysis with
multiple analysis modes, extraction capabilities, and output options.
"""

import argparse
import csv as csv_module
import io
import json
import sys
import os

from . import __version__
from .core.parser import parse_file, PDFParseError
from .analysis.scanner import scan_document, format_scan_report
from .analysis.entropy import analyze_document_entropy, format_entropy_report
from .analysis.anomaly import detect_anomalies, format_anomaly_report
from .extraction.javascript import extract_javascript, format_javascript_report
from .extraction.urls import (
    extract_urls, extract_emails, extract_domains,
    format_url_report, format_email_report,
)
from .extraction.metadata import extract_metadata, format_metadata_report
from .extraction.embedded import (
    extract_embedded_files, extract_streams_info, extract_images_info,
    save_embedded_files, format_embedded_files_report,
    format_streams_report, format_images_report,
)
from .extraction.forms import extract_form_fields, format_forms_report
from .extraction.fonts import analyze_fonts, format_fonts_report
from .extraction.qrcodes import detect_qr_codes, format_qr_report
from .utils import hex_dump, format_object_tree, format_raw_object

# ANSI color codes
_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "dim": "\033[2m",
}

_use_color = True


def _color(text, color_name):
    """Wrap text in ANSI color codes if color is enabled."""
    if not _use_color:
        return text
    code = _COLORS.get(color_name, "")
    return f"{code}{text}{_COLORS['reset']}" if code else text


def _colorize_severity(text, level):
    """Color text based on severity/risk level."""
    if not _use_color:
        return text
    level_upper = level.upper() if isinstance(level, str) else ""
    if level_upper in ("CRITICAL", "critical"):
        return _color(text, "red")
    elif level_upper in ("HIGH", "high"):
        return _color(text, "yellow")
    elif level_upper in ("MEDIUM", "medium"):
        return _color(text, "cyan")
    return text


def main(argv=None):
    """Main entry point for the CLI."""
    global _use_color
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Color support
    if args.no_color or not sys.stdout.isatty():
        _use_color = False

    # Batch mode
    if args.batch:
        return _run_batch(args)

    # Diff mode
    if args.diff:
        if not args.pdf_file:
            print("Error: --diff requires a primary PDF file", file=sys.stderr)
            return 1
        return _run_diff(args)

    if not args.pdf_file:
        parser.print_help()
        return 1

    if not os.path.isfile(args.pdf_file):
        print(f"Error: File not found: {args.pdf_file}", file=sys.stderr)
        return 1

    try:
        doc = parse_file(args.pdf_file)
    except (PDFParseError, OSError) as e:
        print(f"Error parsing PDF: {e}", file=sys.stderr)
        return 1

    if doc.encrypted and not args.quiet:
        print(_color(
            "Warning: PDF is encrypted. Stream decoding is skipped. "
            "Analysis is limited to structural data.",
            "yellow"), file=sys.stderr)

    # Dispatch table: (arg_name, handler) checked in order
    _DISPATCH = [
        ("full",          _full_analysis),
        ("scan",          _run_scan),
        ("entropy",       _run_entropy),
        ("anomaly",       _run_anomaly),
        ("javascript",    _run_javascript),
        ("urls",          _run_urls),
        ("emails",        _run_emails),
        ("metadata",      _run_metadata),
        ("embedded",      _run_embedded),
        ("streams",       _run_streams),
        ("images",        _run_images),
        ("forms",         _run_forms),
        ("fonts",         _run_fonts),
        ("qr",            _run_qr),
        ("object",        _run_object),
        ("dump_object",   _run_dump_object),
        ("raw",           _run_raw),
        ("hexdump",       _run_hexdump),
        ("tree",          _run_tree),
        ("extract_files", _run_extract_files),
        ("domains",       _run_domains),
    ]

    exit_code = 0
    for attr, handler in _DISPATCH:
        val = getattr(args, attr, None)
        if val is not None and val is not False:
            exit_code = handler(doc, args)
            break
    else:
        exit_code = _run_scan(doc, args)

    # --fail-above: override exit code if risk score exceeds threshold
    if args.fail_above is not None and exit_code == 0:
        scan_result = scan_document(doc)
        if scan_result.risk_score > args.fail_above:
            if not args.quiet:
                print(
                    _color(
                        f"\nRisk score {scan_result.risk_score} exceeds "
                        f"threshold {args.fail_above}",
                        "red",
                    ),
                    file=sys.stderr,
                )
            return 1

    return exit_code


def _build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pdetectif",
        description="PDetectiF - Pure Python PDF Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pdetectif document.pdf                  Security scan (default)
  pdetectif -f document.pdf               Full analysis
  pdetectif -s document.pdf               Security keyword scan
  pdetectif -j document.pdf               Extract JavaScript
  pdetectif -u document.pdf               Extract URLs
  pdetectif -m document.pdf               Extract metadata
  pdetectif -e document.pdf               Extract emails
  pdetectif -E document.pdf               List embedded files
  pdetectif --entropy document.pdf        Entropy analysis
  pdetectif --anomaly document.pdf        Anomaly detection
  pdetectif --forms document.pdf          Extract form fields
  pdetectif --fonts document.pdf          Analyze fonts
  pdetectif --qr document.pdf             QR code detection
  pdetectif -o 5 document.pdf             Show object #5
  pdetectif -D 5 document.pdf             Hex dump of object #5 stream
  pdetectif --tree document.pdf           Object tree view
  pdetectif --streams document.pdf        List all streams
  pdetectif --images document.pdf         List all images
  pdetectif --extract-files out/ doc.pdf  Extract embedded files
  pdetectif --json -f document.pdf        Full analysis as JSON
  pdetectif --batch dir/                  Batch analyze directory
  pdetectif --diff a.pdf b.pdf            Compare two PDFs
  pdetectif --fail-above 50 document.pdf  Exit 1 if risk > 50
        """,
    )

    # Analysis modes
    analysis = parser.add_argument_group("Analysis Modes")
    analysis.add_argument("-f", "--full", action="store_true",
                          help="Full analysis (all checks)")
    analysis.add_argument("-s", "--scan", action="store_true",
                          help="Security keyword scan (default)")
    analysis.add_argument("--entropy", action="store_true",
                          help="Entropy analysis of streams")
    analysis.add_argument("--anomaly", action="store_true",
                          help="Anomaly and polyglot detection")

    # Extraction modes
    extraction = parser.add_argument_group("Extraction")
    extraction.add_argument("-j", "--javascript", action="store_true",
                            help="Extract JavaScript")
    extraction.add_argument("-u", "--urls", action="store_true",
                            help="Extract URLs")
    extraction.add_argument("-e", "--emails", action="store_true",
                            help="Extract email addresses")
    extraction.add_argument("-m", "--metadata", action="store_true",
                            help="Extract document metadata")
    extraction.add_argument("-E", "--embedded", action="store_true",
                            help="List embedded files")
    extraction.add_argument("--domains", action="store_true",
                            help="Extract domains and IP addresses")
    extraction.add_argument("--extract-files", metavar="DIR",
                            help="Extract embedded files to directory")
    extraction.add_argument("--forms", action="store_true",
                            help="Extract form fields and actions")
    extraction.add_argument("--fonts", action="store_true",
                            help="Analyze embedded fonts")
    extraction.add_argument("--qr", action="store_true",
                            help="Detect and analyze potential QR code images")

    # Object inspection
    inspection = parser.add_argument_group("Object Inspection")
    inspection.add_argument("-o", "--object", type=int, metavar="NUM",
                            help="Display a specific object by number")
    inspection.add_argument("-D", "--dump-object", type=int, metavar="NUM",
                            help="Hex dump of object stream data")
    inspection.add_argument("--raw", action="store_true",
                            help="Show raw PDF content")
    inspection.add_argument("--hexdump", action="store_true",
                            help="Hex dump of entire file (first 4KB)")
    inspection.add_argument("--tree", action="store_true",
                            help="Object tree overview")
    inspection.add_argument("--streams", action="store_true",
                            help="List all streams")
    inspection.add_argument("--images", action="store_true",
                            help="List all images")

    # Batch and comparison
    multi = parser.add_argument_group("Multi-File")
    multi.add_argument("--batch", metavar="DIR",
                       help="Batch analyze all PDFs in directory")
    multi.add_argument("--diff", metavar="PDF2",
                       help="Compare with another PDF file")

    # Output options
    output = parser.add_argument_group("Output Options")
    output.add_argument("--json", action="store_true", dest="json_output",
                        help="Output results as JSON")
    output.add_argument("--csv", action="store_true", dest="csv_output",
                        help="Output results as CSV")
    output.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show zero-count keywords)")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="Minimal output")
    output.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    output.add_argument("--fail-above", type=int, metavar="N",
                        help="Exit with code 1 if risk score exceeds N")
    output.add_argument("--version", action="version",
                        version=f"PDetectiF {__version__}")

    # Positional argument last so dash-parameters are easier to change
    parser.add_argument("pdf_file", nargs="?", help="Path to the PDF file")

    return parser


def _output(data, args, format_func=None):
    """Handle output formatting (text or JSON)."""
    if args.json_output:
        print(json.dumps(data, indent=2, default=str))
    elif format_func:
        print(format_func(data))
    else:
        print(data)


def _full_analysis(doc, args):
    """Run all analysis modules."""
    scan_result = scan_document(doc)
    entropy_result = analyze_document_entropy(doc)
    anomaly_result = detect_anomalies(doc)
    js_result = extract_javascript(doc)
    url_result = extract_urls(doc)
    email_result = extract_emails(doc)
    meta_result = extract_metadata(doc)
    embedded_result = extract_embedded_files(doc)
    images = extract_images_info(doc)
    forms_result = extract_form_fields(doc)
    fonts_result = analyze_fonts(doc)
    qr_result = detect_qr_codes(doc)

    if args.json_output:
        combined = {
            "scan": {
                "document_info": scan_result.document_info,
                "structural_counts": dict(scan_result.structural_counts),
                "suspicious_counts": dict(scan_result.suspicious_counts),
                "dangerous_patterns": scan_result.dangerous_patterns,
                "obfuscated_names": scan_result.obfuscated_names,
                "risk_score": scan_result.risk_score,
                "risk_level": scan_result.risk_level,
                "risk_factors": scan_result.risk_factors,
                "warnings": scan_result.warnings,
            },
            "entropy": entropy_result,
            "anomalies": anomaly_result,
            "javascript": js_result,
            "urls": url_result,
            "emails": email_result,
            "metadata": meta_result,
            "embedded_files": embedded_result,
            "images": [img for img in images],
            "forms": forms_result,
            "fonts": fonts_result,
            "qr_codes": qr_result,
        }
        print(json.dumps(combined, indent=2, default=str))
    else:
        print(format_scan_report(scan_result, verbose=args.verbose))
        print()
        print(format_entropy_report(entropy_result))
        print()
        print(format_anomaly_report(anomaly_result))
        print()
        print(format_javascript_report(js_result))
        print()
        print(format_url_report(url_result))
        print()
        print(format_email_report(email_result))
        print()
        print(format_metadata_report(meta_result))
        print()
        print(format_embedded_files_report(embedded_result))
        print()
        print(format_images_report(images))
        print()
        print(format_forms_report(forms_result))
        print()
        print(format_fonts_report(fonts_result))
        print()
        print(format_qr_report(qr_result))

    return 0


def _run_scan(doc, args):
    """Run security scan."""
    result = scan_document(doc)
    if args.json_output:
        data = {
            "document_info": result.document_info,
            "structural_counts": dict(result.structural_counts),
            "suspicious_counts": dict(result.suspicious_counts),
            "dangerous_patterns": result.dangerous_patterns,
            "obfuscated_names": result.obfuscated_names,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "risk_factors": result.risk_factors,
            "warnings": result.warnings,
        }
        print(json.dumps(data, indent=2, default=str))
    else:
        print(format_scan_report(result, verbose=args.verbose))
    return 0


def _run_entropy(doc, args):
    """Run entropy analysis."""
    result = analyze_document_entropy(doc)
    _output(result, args, format_entropy_report)
    return 0


def _run_anomaly(doc, args):
    """Run anomaly detection."""
    result = detect_anomalies(doc)
    _output(result, args, format_anomaly_report)
    return 0


def _run_javascript(doc, args):
    """Extract JavaScript."""
    result = extract_javascript(doc)
    _output(result, args, format_javascript_report)
    return 0


def _run_urls(doc, args):
    """Extract URLs."""
    result = extract_urls(doc)
    _output(result, args, format_url_report)
    return 0


def _run_emails(doc, args):
    """Extract emails."""
    result = extract_emails(doc)
    _output(result, args, format_email_report)
    return 0


def _run_metadata(doc, args):
    """Extract metadata."""
    result = extract_metadata(doc)
    _output(result, args, format_metadata_report)
    return 0


def _run_embedded(doc, args):
    """List embedded files."""
    result = extract_embedded_files(doc)
    _output(result, args, format_embedded_files_report)
    return 0


def _run_streams(doc, args):
    """List all streams."""
    streams = extract_streams_info(doc)
    if args.json_output:
        print(json.dumps(streams, indent=2, default=str))
    else:
        print(format_streams_report(streams))
    return 0


def _run_images(doc, args):
    """List all images."""
    images = extract_images_info(doc)
    if args.json_output:
        print(json.dumps(images, indent=2, default=str))
    else:
        print(format_images_report(images))
    return 0


def _run_object(doc, args):
    """Display a specific object."""
    obj = doc.get_object(args.object)
    if not obj:
        print(f"Object {args.object} not found.", file=sys.stderr)
        return 1

    if args.json_output:
        data = {
            "object_number": obj.obj_num,
            "generation": obj.gen_num,
            "type": obj.type_name,
            "is_stream": obj.is_stream,
            "representation": repr(obj.value),
        }
        if obj.is_stream:
            data["stream_raw_size"] = len(obj.value.raw_data) if obj.value.raw_data else 0
            data["stream_decoded_size"] = len(obj.value.data) if obj.value.data else 0
        print(json.dumps(data, indent=2, default=str))
    else:
        print(format_object_tree(obj))
        if obj.is_stream and obj.value.data:
            print()
            try:
                text = obj.value.data.decode("latin-1", errors="replace")
                if len(text) > 3000:
                    text = text[:3000] + f"\n... ({len(text) - 3000} more chars)"
                print("  Decoded stream content:")
                print(text)
            except (UnicodeDecodeError, AttributeError):
                print("  Stream data (hex):")
                print(hex_dump(obj.value.data, length=512))
    return 0


def _run_dump_object(doc, args):
    """Hex dump of an object's stream data."""
    obj = doc.get_object(args.dump_object)
    if not obj:
        print(f"Object {args.dump_object} not found.", file=sys.stderr)
        return 1

    if not obj.is_stream:
        print(f"Object {args.dump_object} is not a stream.", file=sys.stderr)
        if obj.raw_data:
            print("\n  Raw object data:")
            print(hex_dump(obj.raw_data if isinstance(obj.raw_data, bytes)
                           else str(obj.raw_data).encode(), length=1024))
        return 1

    print(f"Object {args.dump_object} stream data:")
    if obj.value.raw_data:
        print("\n  Raw stream ({} bytes):".format(len(obj.value.raw_data)))
        print(hex_dump(obj.value.raw_data, length=1024))
    if obj.value.decoded_data is not None:
        print("\n  Decoded stream ({} bytes):".format(len(obj.value.decoded_data)))
        print(hex_dump(obj.value.decoded_data, length=1024))
    return 0


def _run_raw(doc, args):
    """Show raw PDF content."""
    try:
        text = doc.raw_data.decode("latin-1", errors="replace")
        if len(text) > 10000 and not args.verbose:
            text = text[:10000] + f"\n... ({len(text) - 10000} more characters, use -v for full)"
        print(text)
    except (UnicodeDecodeError, AttributeError):
        print(hex_dump(doc.raw_data, length=4096))
    return 0


def _run_hexdump(doc, args):
    """Hex dump of file."""
    length = len(doc.raw_data) if args.verbose else min(4096, len(doc.raw_data))
    print(f"Hex dump ({length} of {len(doc.raw_data)} bytes):")
    print(hex_dump(doc.raw_data, length=length))
    return 0


def _run_tree(doc, args):
    """Show object tree overview."""
    print("── Object Tree ──")
    print(f"  Total objects: {len(doc.objects)}\n")

    for (obj_num, gen_num) in sorted(doc.objects.keys()):
        obj = doc.objects[(obj_num, gen_num)]
        type_name = obj.type_name or ""
        is_stream = "stream" if obj.is_stream else ""

        parts = [f"  {obj_num:>5} {gen_num} obj"]
        if type_name:
            parts.append(f"  /Type /{type_name}")
        if is_stream:
            raw_len = len(obj.value.raw_data) if obj.value.raw_data else 0
            parts.append(f"  stream ({raw_len} bytes)")

            # Show filter
            d = obj.value.dictionary if obj.is_stream else None
            if d:
                filt = d.get("Filter")
                if filt:
                    parts.append(f"  [{filt}]")
        print("".join(parts))

    return 0


def _run_extract_files(doc, args):
    """Extract embedded files to directory."""
    output_dir = args.extract_files
    saved = save_embedded_files(doc, output_dir)
    if saved:
        print(f"Extracted {len(saved)} file(s) to {output_dir}:")
        for path in saved:
            print(f"  {path}")
    else:
        print("No embedded files to extract.")
    return 0


def _run_domains(doc, args):
    """Extract domains and IPs."""
    result = extract_domains(doc)
    if args.json_output:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("── Domains ──")
        print(f"  Total domains: {result['total_domains']}")
        for d in result["domains"]:
            print(f"    {d}")
        print(f"\n  Total IPs: {result['total_ips']}")
        for ip in result["ip_addresses"]:
            print(f"    {ip}")
    return 0


def _run_forms(doc, args):
    """Extract form fields."""
    result = extract_form_fields(doc)
    _output(result, args, format_forms_report)
    return 0


def _run_fonts(doc, args):
    """Analyze fonts."""
    result = analyze_fonts(doc)
    _output(result, args, format_fonts_report)
    return 0


def _run_qr(doc, args):
    """Detect QR codes."""
    result = detect_qr_codes(doc)
    _output(result, args, format_qr_report)
    return 0


def _run_batch(args):
    """Batch analyze all PDFs in a directory."""
    batch_dir = args.batch
    if not os.path.isdir(batch_dir):
        print(f"Error: Directory not found: {batch_dir}", file=sys.stderr)
        return 1

    pdf_files = sorted(
        os.path.join(batch_dir, f)
        for f in os.listdir(batch_dir)
        if f.lower().endswith(".pdf") and os.path.isfile(os.path.join(batch_dir, f))
    )

    if not pdf_files:
        print(f"No PDF files found in {batch_dir}")
        return 0

    results = []
    for pdf_path in pdf_files:
        try:
            doc = parse_file(pdf_path)
            scan_result = scan_document(doc)
            results.append({
                "file": os.path.basename(pdf_path),
                "size": doc.file_size,
                "objects": len(doc.objects),
                "risk_score": scan_result.risk_score,
                "risk_level": scan_result.risk_level,
                "js": scan_result.suspicious_counts.get("/JS", 0)
                    + scan_result.suspicious_counts.get("/JavaScript", 0),
                "patterns": len(scan_result.dangerous_patterns),
                "warnings": len(scan_result.warnings),
            })
        except (PDFParseError, OSError) as e:
            results.append({
                "file": os.path.basename(pdf_path),
                "error": str(e),
            })

    if args.json_output:
        print(json.dumps(results, indent=2, default=str))
    elif args.csv_output:
        buf = io.StringIO()
        fieldnames = ["file", "size", "objects", "risk_score",
                      "risk_level", "js", "patterns", "warnings", "error"]
        writer = csv_module.DictWriter(buf, fieldnames=fieldnames,
                                       extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
        print(buf.getvalue(), end="")
    else:
        print(f"── Batch Analysis: {len(pdf_files)} files ──\n")
        print(f"  {'File':<35} {'Size':>10} {'Objects':>8} "
              f"{'Risk':>6} {'Level':<10} {'JS':>4} {'Patterns':>9}")
        print("  " + "-" * 90)
        for r in results:
            if "error" in r:
                print(f"  {r['file']:<35} ERROR: {r['error']}")
            else:
                level = r["risk_level"]
                line = (
                    f"  {r['file']:<35} {r['size']:>10} {r['objects']:>8} "
                    f"{r['risk_score']:>6} {level:<10} "
                    f"{r['js']:>4} {r['patterns']:>9}"
                )
                print(_colorize_severity(line, level))
        print()

    return 0


def _run_diff(args):
    """Compare two PDF files."""
    file1 = args.pdf_file
    file2 = args.diff

    for f in (file1, file2):
        if not os.path.isfile(f):
            print(f"Error: File not found: {f}", file=sys.stderr)
            return 1

    try:
        doc1 = parse_file(file1)
        doc2 = parse_file(file2)
    except (PDFParseError, OSError) as e:
        print(f"Error parsing PDF: {e}", file=sys.stderr)
        return 1

    diff = {
        "file1": os.path.basename(file1),
        "file2": os.path.basename(file2),
        "structure": {},
        "object_diff": {},
    }

    # Compare structure
    for attr in ("version", "file_size", "eof_count", "encrypted", "linearized"):
        v1 = getattr(doc1, attr)
        v2 = getattr(doc2, attr)
        if v1 != v2:
            diff["structure"][attr] = {"file1": v1, "file2": v2}

    diff["structure"]["objects"] = {
        "file1": len(doc1.objects), "file2": len(doc2.objects)
    }

    # Compare objects
    keys1 = set(doc1.objects.keys())
    keys2 = set(doc2.objects.keys())
    diff["object_diff"]["only_in_file1"] = len(keys1 - keys2)
    diff["object_diff"]["only_in_file2"] = len(keys2 - keys1)
    diff["object_diff"]["common"] = len(keys1 & keys2)

    # Compare types in common objects
    type_changes = []
    for key in sorted(keys1 & keys2):
        t1 = doc1.objects[key].type_name or "none"
        t2 = doc2.objects[key].type_name or "none"
        if t1 != t2:
            type_changes.append({
                "object": f"{key[0]} {key[1]}",
                "file1_type": t1,
                "file2_type": t2,
            })
    diff["object_diff"]["type_changes"] = type_changes

    # Compare risk
    scan1 = scan_document(doc1)
    scan2 = scan_document(doc2)
    diff["risk"] = {
        "file1": {"score": scan1.risk_score, "level": scan1.risk_level},
        "file2": {"score": scan2.risk_score, "level": scan2.risk_level},
    }

    if args.json_output:
        print(json.dumps(diff, indent=2, default=str))
    else:
        print("── PDF Comparison ──")
        print(f"  File 1: {diff['file1']}")
        print(f"  File 2: {diff['file2']}")
        print()

        if diff["structure"]:
            print("  Structural differences:")
            for attr, vals in diff["structure"].items():
                if isinstance(vals, dict):
                    print(f"    {attr:<20} {vals['file1']} -> {vals['file2']}")

        print()
        od = diff["object_diff"]
        print(f"  Objects only in file 1: {od['only_in_file1']}")
        print(f"  Objects only in file 2: {od['only_in_file2']}")
        print(f"  Common objects:         {od['common']}")

        if type_changes:
            print(f"\n  Type changes ({len(type_changes)}):")
            for tc in type_changes[:20]:
                print(f"    Object {tc['object']}: "
                      f"{tc['file1_type']} -> {tc['file2_type']}")

        print()
        r = diff["risk"]
        print(f"  Risk: {r['file1']['score']}/100 [{r['file1']['level']}] -> "
              f"{r['file2']['score']}/100 [{r['file2']['level']}]")

    return 0
