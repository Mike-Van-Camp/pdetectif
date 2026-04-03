"""
Font analysis for PDF documents.

Detects embedded fonts, font subsets, suspicious font objects,
and reports font metadata. Malicious PDFs sometimes use font
streams to hide shellcode or exploit font parsing vulnerabilities.
"""

from ..core.objects import (
    PDFDictionary,
    PDFName,
    PDFString,
    PDFHexString,
    PDFStream,
    PDFArray,
    PDFReference,
    PDFInteger,
)

# Standard PDF base 14 fonts
BASE_14_FONTS = {
    "Courier", "Courier-Bold", "Courier-Oblique", "Courier-BoldOblique",
    "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique",
    "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic",
    "Symbol", "ZapfDingbats",
}


def analyze_fonts(doc):
    """
    Analyze all fonts in a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Font analysis results.
    """
    results = {
        "fonts": [],
        "total": 0,
        "embedded": 0,
        "subset": 0,
        "suspicious": [],
    }

    seen = set()

    for (obj_num, gen_num), obj in doc.objects.items():
        d = obj.dictionary
        if d is None:
            continue

        type_val = d.get("Type")
        if not (isinstance(type_val, PDFName) and type_val.name == "Font"):
            continue

        if obj_num in seen:
            continue
        seen.add(obj_num)

        font = _analyze_font_object(doc, obj_num, d)
        results["fonts"].append(font)

        if font["embedded"]:
            results["embedded"] += 1
        if font["subset"]:
            results["subset"] += 1
        if font["suspicious_reasons"]:
            results["suspicious"].append({
                "object": obj_num,
                "name": font["name"],
                "reasons": font["suspicious_reasons"],
            })

    results["total"] = len(results["fonts"])
    return results


def _analyze_font_object(doc, obj_num, d):
    """Analyze a single font object."""
    subtype = d.get("Subtype")
    base_font = d.get("BaseFont")
    encoding = d.get("Encoding")

    font_name = base_font.name if isinstance(base_font, PDFName) else str(base_font) if base_font else "Unknown"
    font_subtype = subtype.name if isinstance(subtype, PDFName) else str(subtype) if subtype else "Unknown"
    enc_name = encoding.name if isinstance(encoding, PDFName) else "Custom" if isinstance(encoding, PDFDictionary) else str(encoding) if encoding else "Default"

    # Check for subset prefix (e.g., ABCDEF+FontName)
    is_subset = "+" in font_name and len(font_name.split("+")[0]) == 6

    # Check for embedded font data
    embedded = False
    embedded_size = 0
    embedded_obj = None
    suspicious_reasons = []

    desc = d.get("FontDescriptor")
    if isinstance(desc, PDFReference):
        desc_obj = doc.get_object(desc.obj_num, desc.gen_num)
        if desc_obj:
            desc = desc_obj.value

    if isinstance(desc, PDFDictionary):
        for key in ("FontFile", "FontFile2", "FontFile3"):
            ff_ref = desc.get(key)
            if isinstance(ff_ref, PDFReference):
                ff_obj = doc.get_object(ff_ref.obj_num, ff_ref.gen_num)
                if ff_obj and ff_obj.is_stream:
                    embedded = True
                    embedded_obj = ff_ref.obj_num
                    data = ff_obj.value.data
                    embedded_size = len(data) if data else 0

                    # Check for suspicious font content
                    if data:
                        # Very large font file
                        if embedded_size > 5 * 1024 * 1024:
                            suspicious_reasons.append(
                                f"Very large font file ({embedded_size / (1024*1024):.1f} MB)"
                            )

                        # Check for JavaScript-like content in font stream
                        try:
                            text = data[:4096].decode("latin-1", errors="replace")
                            js_indicators = ["eval(", "unescape(", "String.fromCharCode",
                                             "function(", "var ", "document."]
                            for indicator in js_indicators:
                                if indicator in text:
                                    suspicious_reasons.append(
                                        f"JavaScript-like content in font stream: {indicator}"
                                    )
                                    break
                        except (UnicodeDecodeError, AttributeError):
                            pass

        # Check for suspicious flags
        flags = desc.get("Flags")
        if isinstance(flags, PDFInteger) and flags.value == 0:
            suspicious_reasons.append("FontDescriptor Flags is 0 (unusual)")

    # Non-embedded non-standard font
    clean_name = font_name.split("+")[-1] if "+" in font_name else font_name
    if not embedded and clean_name not in BASE_14_FONTS and font_subtype != "Type3":
        pass  # Not suspicious on its own, common in many PDFs

    return {
        "object": obj_num,
        "name": font_name,
        "subtype": font_subtype,
        "encoding": enc_name,
        "subset": is_subset,
        "embedded": embedded,
        "embedded_size": embedded_size,
        "embedded_object": embedded_obj,
        "suspicious_reasons": suspicious_reasons,
    }


def format_fonts_report(results):
    """Format font analysis results."""
    lines = []
    lines.append("── Font Analysis ──")
    lines.append(f"  Total fonts:    {results['total']}")
    lines.append(f"  Embedded:       {results['embedded']}")
    lines.append(f"  Subset:         {results['subset']}")

    if results["fonts"]:
        lines.append("")
        lines.append(f"  {'Object':<8} {'Name':<30} {'Type':<12} "
                     f"{'Encoding':<15} {'Embed':>8} {'Subset'}")
        lines.append("  " + "-" * 85)
        for f in results["fonts"]:
            embed_info = f"{f['embedded_size']}" if f["embedded"] else "-"
            subset = "Yes" if f["subset"] else "-"
            lines.append(
                f"  {f['object']:<8} {f['name']:<30} {f['subtype']:<12} "
                f"{f['encoding']:<15} {embed_info:>8} {subset}"
            )

    if results["suspicious"]:
        lines.append("")
        lines.append("  Suspicious fonts:")
        for s in results["suspicious"]:
            lines.append(f"    Object {s['object']} ({s['name']}):")
            for reason in s["reasons"]:
                lines.append(f"      ! {reason}")

    if not results["fonts"]:
        lines.append("  No fonts found.")

    return "\n".join(lines)
