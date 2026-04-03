"""
PDF anomaly detection.

Detects structural anomalies, format violations, and suspicious
patterns that may indicate malicious manipulation or exploitation
attempts. Includes polyglot detection and format conformance checks.
"""

import re
import hashlib

from ..core.objects import (
    PDFDictionary,
    PDFName,
    PDFStream,
    PDFArray,
    PDFReference,
    PDFInteger,
    PDFString,
    PDFHexString,
)


def detect_anomalies(doc):
    """
    Run all anomaly detection checks on a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Anomaly detection results.
    """
    results = {
        "anomalies": [],
        "polyglot_indicators": [],
        "format_violations": [],
        "structure_info": {},
        "hashes": {},
        "total_severity_score": 0,
    }

    _check_header_anomalies(doc, results)
    _check_polyglot(doc, results)
    _check_xref_anomalies(doc, results)
    _check_object_anomalies(doc, results)
    _check_trailer_anomalies(doc, results)
    _check_stream_anomalies(doc, results)
    _compute_hashes(doc, results)
    _check_structure_info(doc, results)

    # Calculate total severity
    severity_map = {"info": 1, "low": 2, "medium": 5, "high": 10, "critical": 20}
    for a in results["anomalies"]:
        results["total_severity_score"] += severity_map.get(a.get("severity", "info"), 1)

    return results


def _add_anomaly(results, title, description, severity="info"):
    """Add an anomaly finding."""
    results["anomalies"].append({
        "title": title,
        "description": description,
        "severity": severity,
    })


def _check_header_anomalies(doc, results):
    """Check for header-related anomalies."""
    data = doc.raw_data

    # PDF header position
    header_pos = data.find(b"%PDF-")
    if header_pos == -1:
        _add_anomaly(results, "Missing PDF header",
                     "No %PDF- header found in file", "critical")
    elif header_pos > 0:
        _add_anomaly(results, "PDF header not at offset 0",
                     f"Header found at offset {header_pos}. "
                     "Data before header may indicate polyglot file or prepended content.",
                     "high")
        results["polyglot_indicators"].append(
            f"Pre-header data ({header_pos} bytes)")

    # Check PDF version
    if doc.version:
        major, minor = doc.version.split(".")
        if int(major) > 2 or (int(major) == 2 and int(minor) > 0):
            _add_anomaly(results, "Unusual PDF version",
                         f"PDF version {doc.version} is unusual", "low")

    # Binary marker after header
    if header_pos >= 0:
        line_end = data.find(b"\n", header_pos)
        if line_end > 0 and line_end + 1 < len(data):
            next_bytes = data[line_end + 1:line_end + 5]
            if next_bytes and next_bytes[0:1] == b"%":
                # Check if binary marker bytes are >= 0x80
                has_high = any(b >= 0x80 for b in next_bytes[1:5] if b)
                if not has_high:
                    _add_anomaly(results, "Missing binary marker",
                                 "Second line comment doesn't contain high bytes. "
                                 "May cause issues with file transfer.", "info")


def _check_polyglot(doc, results):
    """Detect potential polyglot file indicators."""
    data = doc.raw_data
    prefix = data[:16]

    # Check for common file signatures before PDF header
    signatures = {
        b"\x89PNG": "PNG image",
        b"GIF87a": "GIF image",
        b"GIF89a": "GIF image",
        b"\xff\xd8\xff": "JPEG image",
        b"PK\x03\x04": "ZIP archive",
        b"Rar!": "RAR archive",
        b"\x7fELF": "ELF executable",
        b"MZ": "PE executable (Windows)",
        b"<!DOCTYPE": "HTML document",
        b"<html": "HTML document",
        b"<HTML": "HTML document",
        b"#!/": "Shell script",
    }

    for sig, desc in signatures.items():
        if prefix.startswith(sig):
            _add_anomaly(results, "Polyglot file detected",
                         f"File starts with {desc} signature before PDF data",
                         "critical")
            results["polyglot_indicators"].append(f"Starts with {desc} signature")
            break

    # Check for data after last %%EOF
    eof_positions = [m.end() for m in re.finditer(rb"%%EOF", data)]
    if eof_positions:
        last_eof = eof_positions[-1]
        trailing = data[last_eof:].strip()
        if trailing:
            _add_anomaly(results, "Data after %%EOF",
                         f"Found {len(trailing)} bytes of data after last %%EOF marker",
                         "medium")
            results["polyglot_indicators"].append(
                f"Trailing data after %%EOF ({len(trailing)} bytes)")

    # Check for embedded ZIP within PDF
    zip_sig_pos = data.find(b"PK\x03\x04", 10)
    if zip_sig_pos > 0:
        # Verify it's not just stream data by checking context
        _add_anomaly(results, "Embedded ZIP signature",
                     f"ZIP file signature found at offset {zip_sig_pos}",
                     "medium")


def _check_xref_anomalies(doc, results):
    """Check for cross-reference table anomalies."""
    # Multiple xref tables
    if len(doc.xref_tables) > 1:
        _add_anomaly(results, "Multiple xref tables",
                     f"Found {len(doc.xref_tables)} xref tables "
                     "(may indicate incremental updates or manipulation)",
                     "info")

    # Check for xref/trailer mismatch
    if doc.xref_tables and not doc.trailers:
        _add_anomaly(results, "Missing trailer",
                     "Xref table found but no trailer dictionary", "high")

    # Check for missing xref
    if not doc.xref_tables and not doc.xref_streams:
        _add_anomaly(results, "No xref table or stream",
                     "Document has no cross-reference table or stream", "medium")

    # Verify xref entries point to valid objects
    for xref_table in doc.xref_tables:
        for obj_num, entry in xref_table.items():
            if entry.in_use and entry.offset > doc.file_size:
                _add_anomaly(results, "Invalid xref offset",
                             f"Object {obj_num} xref offset ({entry.offset}) "
                             f"exceeds file size ({doc.file_size})",
                             "high")


def _check_object_anomalies(doc, results):
    """Check for object-level anomalies."""
    type_counts = {}

    for (obj_num, gen_num), obj in doc.objects.items():
        # Count object types
        type_name = obj.type_name or "unknown"
        type_counts[type_name] = type_counts.get(type_name, 0) + 1

        # Check for objects with very high generation numbers
        if gen_num > 0:
            _add_anomaly(results, "Non-zero generation number",
                         f"Object {obj_num} has generation {gen_num}",
                         "info")

        d = obj.dictionary
        if d is None:
            continue

        # Check for deeply nested actions
        action_depth = _measure_action_depth(d, doc)
        if action_depth > 5:
            _add_anomaly(results, "Deep action nesting",
                         f"Object {obj_num} has action nesting depth {action_depth}",
                         "high")

    results["structure_info"]["object_types"] = type_counts


def _measure_action_depth(dictionary, doc, depth=0, visited=None):
    """Measure the nesting depth of action chains."""
    if depth > 50 or not isinstance(dictionary, PDFDictionary):
        return depth
    if visited is None:
        visited = set()

    max_depth = depth

    next_action = dictionary.get("Next")
    if isinstance(next_action, PDFReference):
        ref_key = (next_action.obj_num, next_action.gen_num)
        if ref_key not in visited:
            visited.add(ref_key)
            resolved = doc.get_object(next_action.obj_num, next_action.gen_num)
            if resolved and resolved.dictionary:
                d = _measure_action_depth(resolved.dictionary, doc, depth + 1, visited)
                max_depth = max(max_depth, d)
    elif isinstance(next_action, PDFDictionary):
        d = _measure_action_depth(next_action, doc, depth + 1, visited)
        max_depth = max(max_depth, d)
    elif isinstance(next_action, PDFArray):
        for item in next_action:
            if isinstance(item, PDFDictionary):
                d = _measure_action_depth(item, doc, depth + 1, visited)
                max_depth = max(max_depth, d)

    return max_depth


def _check_trailer_anomalies(doc, results):
    """Check for trailer anomalies."""
    if not doc.trailers:
        return

    # Check for suspicious trailer entries
    for i, trailer in enumerate(doc.trailers):
        # Missing required keys
        if "Size" not in trailer and "Root" not in trailer:
            _add_anomaly(results, "Incomplete trailer",
                         f"Trailer {i} missing both /Size and /Root",
                         "medium")

        # Check for /Root pointing to non-existent object
        root = trailer.get("Root")
        if isinstance(root, PDFReference):
            if not doc.get_object(root.obj_num, root.gen_num):
                _add_anomaly(results, "Dangling Root reference",
                             f"Trailer /Root references object {root.obj_num} "
                             "which was not found",
                             "high")


def _check_stream_anomalies(doc, results):
    """Check for stream-level anomalies."""
    for (obj_num, _), obj in doc.objects.items():
        if not obj.is_stream:
            continue

        stream = obj.value
        d = stream.dictionary

        # Check for length mismatch
        if d:
            length_val = d.get("Length")
            if isinstance(length_val, PDFInteger):
                declared = length_val.value
                actual = len(stream.raw_data) if stream.raw_data else 0
                if declared != actual and abs(declared - actual) > 2:
                    _add_anomaly(results, "Stream length mismatch",
                                 f"Object {obj_num}: declared length {declared}, "
                                 f"actual length {actual}",
                                 "low")

        # Check for very large streams (potential resource exhaustion)
        if stream.raw_data and len(stream.raw_data) > 10 * 1024 * 1024:
            _add_anomaly(results, "Very large stream",
                         f"Object {obj_num}: stream is "
                         f"{len(stream.raw_data) / (1024*1024):.1f} MB",
                         "medium")


def _compute_hashes(doc, results):
    """Compute cryptographic hashes of the file for forensic purposes."""
    results["hashes"] = {
        "md5": hashlib.md5(doc.raw_data).hexdigest(),
        "sha1": hashlib.sha1(doc.raw_data).hexdigest(),
        "sha256": hashlib.sha256(doc.raw_data).hexdigest(),
    }


def _check_structure_info(doc, results):
    """Gather general structure information."""
    results["structure_info"]["file_size"] = doc.file_size
    results["structure_info"]["pdf_version"] = doc.version
    results["structure_info"]["total_objects"] = len(doc.objects)
    results["structure_info"]["total_streams"] = sum(
        1 for o in doc.objects.values() if o.is_stream
    )
    results["structure_info"]["xref_tables"] = len(doc.xref_tables)
    results["structure_info"]["xref_streams"] = len(doc.xref_streams)
    results["structure_info"]["trailers"] = len(doc.trailers)
    results["structure_info"]["eof_markers"] = doc.eof_count


def format_anomaly_report(results):
    """Format anomaly detection results as a human-readable report."""
    lines = []

    # Hashes
    lines.append("── File Hashes ──")
    for algo, value in results["hashes"].items():
        lines.append(f"  {algo.upper():<8} {value}")

    # Structure info
    lines.append("")
    lines.append("── Structure Info ──")
    for key, value in results["structure_info"].items():
        if key == "object_types":
            lines.append("  Object types:")
            for t, c in sorted(value.items(), key=lambda x: -x[1]):
                lines.append(f"    {t:<20} {c}")
        else:
            label = key.replace("_", " ").title()
            lines.append(f"  {label:<20} {value}")

    # Anomalies
    if results["anomalies"]:
        lines.append("")
        lines.append("── Anomalies ──")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_anomalies = sorted(
            results["anomalies"],
            key=lambda a: severity_order.get(a["severity"], 5),
        )
        for a in sorted_anomalies:
            sev = a["severity"].upper()
            lines.append(f"  [{sev}] {a['title']}")
            lines.append(f"         {a['description']}")
    else:
        lines.append("")
        lines.append("── Anomalies ──")
        lines.append("  No anomalies detected.")

    # Polyglot indicators
    if results["polyglot_indicators"]:
        lines.append("")
        lines.append("── Polyglot Indicators ──")
        for p in results["polyglot_indicators"]:
            lines.append(f"  ⚠ {p}")

    lines.append("")
    lines.append(f"  Total severity score: {results['total_severity_score']}")

    return "\n".join(lines)
