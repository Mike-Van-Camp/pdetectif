"""
PDF security scanner.

Scans PDF documents for security-relevant keywords, obfuscation
techniques, suspicious patterns, and generates risk scores.
Inspired by pdfid but goes significantly further.
"""

import re
import math
from collections import OrderedDict

from ..core.objects import (
    PDFName,
    PDFString,
    PDFHexString,
    PDFDictionary,
    PDFArray,
    PDFStream,
    PDFReference,
    PDFIndirectObject,
    PDFInteger,
)


# ── Security-relevant PDF keywords ──

STRUCTURAL_KEYWORDS = OrderedDict([
    ("obj", "Indirect object definitions"),
    ("endobj", "End of indirect object"),
    ("stream", "Stream data sections"),
    ("endstream", "End of stream data"),
    ("xref", "Cross-reference tables"),
    ("trailer", "Document trailers"),
    ("startxref", "Cross-reference offset pointers"),
    ("%%EOF", "End-of-file markers"),
])

SUSPICIOUS_KEYWORDS = OrderedDict([
    ("/JS", "JavaScript name reference"),
    ("/JavaScript", "JavaScript action"),
    ("/AA", "Additional actions (auto-triggered)"),
    ("/OpenAction", "Action on document open"),
    ("/Launch", "Launch external application"),
    ("/EmbeddedFile", "Embedded file"),
    ("/RichMedia", "Rich media (Flash/video)"),
    ("/XFA", "XML Forms Architecture"),
    ("/AcroForm", "Interactive form"),
    ("/JBIG2Decode", "JBIG2 decoder (historical exploits)"),
    ("/Colors", "Image color specification (potential exploit)"),
    ("/URI", "URI action"),
    ("/SubmitForm", "Form submission action"),
    ("/ImportData", "Data import action"),
    ("/GoTo", "Navigation action"),
    ("/GoToR", "Remote navigation action"),
    ("/GoToE", "Embedded file navigation"),
    ("/Named", "Named action"),
    ("/SetOCGState", "Layer state change action"),
    ("/Rendition", "Multimedia rendition action"),
    ("/ResetForm", "Form reset action"),
    ("/Thread", "Article thread action"),
    ("/Sound", "Sound action"),
    ("/Movie", "Movie action"),
    ("/Hide", "Hide annotation action"),
])

ENCRYPTION_KEYWORDS = OrderedDict([
    ("/Encrypt", "Document encryption dictionary"),
    ("/P", "Permissions flags"),
    ("/R", "Security handler revision"),
    ("/V", "Security handler version"),
    ("/CF", "Crypt filters"),
    ("/StmF", "Stream crypt filter"),
    ("/StrF", "String crypt filter"),
])

DANGEROUS_PATTERNS = [
    (r"eval\s*\(", "eval() call in JavaScript"),
    (r"unescape\s*\(", "unescape() call (often used in exploits)"),
    (r"String\.fromCharCode", "String.fromCharCode (obfuscation)"),
    (r"getAnnots", "getAnnots call"),
    (r"getIcon", "getIcon call"),
    (r"spell\.customDictionaryOpen", "spell.customDictionaryOpen exploit"),
    (r"util\.printf", "util.printf (format string exploit)"),
    (r"media\.newPlayer", "media.newPlayer exploit"),
    (r"Collab\.collectEmailInfo", "Collab.collectEmailInfo exploit"),
    (r"app\.setTimeOut", "app.setTimeOut (delayed execution)"),
    (r"app\.setInterval", "app.setInterval (repeated execution)"),
    (r"this\.exportDataObject", "exportDataObject (data exfiltration)"),
    (r"this\.submitForm", "submitForm (data exfiltration)"),
    (r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", "Percent-encoded sequences"),
    (r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}", "Hex-encoded character sequences"),
    (r"\\u[0-9a-fA-F]{4}", "Unicode escape sequences"),
    (r"(?:0x[0-9a-fA-F]+,?\s*){8,}", "Large hex array (shellcode indicator)"),
]


class ScanResult:
    """Container for scan results."""

    def __init__(self):
        self.structural_counts = OrderedDict()
        self.suspicious_counts = OrderedDict()
        self.encryption_info = OrderedDict()
        self.dangerous_patterns = []
        self.obfuscated_names = []
        self.name_hex_encoding_count = 0
        self.risk_score = 0
        self.risk_level = "LOW"
        self.risk_factors = []
        self.warnings = []
        self.document_info = {}


def scan_document(doc):
    """
    Perform comprehensive security scan on a parsed PDF document.

    Args:
        doc: A PDFDocument instance from the parser.

    Returns:
        ScanResult with all findings.
    """
    result = ScanResult()

    # Document info
    result.document_info = {
        "file": doc.file_path,
        "size": doc.file_size,
        "version": doc.version,
        "pages": doc.page_count,
        "objects": len(doc.objects),
        "streams": sum(1 for o in doc.objects.values() if o.is_stream),
        "incremental_updates": doc.incremental_updates,
        "eof_markers": doc.eof_count,
        "encrypted": doc.encrypted,
        "linearized": doc.linearized,
    }

    _count_structural_keywords(doc, result)
    _count_suspicious_keywords(doc, result)
    _check_encryption(doc, result)
    _scan_dangerous_patterns(doc, result)
    _detect_obfuscation(doc, result)
    _check_anomalies(doc, result)
    _calculate_risk_score(result)

    return result


def _count_structural_keywords(doc, result):
    """Count structural PDF keywords in raw data."""
    raw = doc.raw_data

    for keyword in STRUCTURAL_KEYWORDS:
        if keyword.startswith("/"):
            pattern = re.escape(keyword.encode())
        else:
            pattern = re.escape(keyword.encode())
        count = len(re.findall(pattern, raw))
        result.structural_counts[keyword] = count


def _count_suspicious_keywords(doc, result):
    """Count security-relevant keywords both in raw data and parsed objects."""
    raw = doc.raw_data

    for keyword in SUSPICIOUS_KEYWORDS:
        # Count in raw data (catches obfuscated references too)
        raw_pattern = re.escape(keyword.encode())
        raw_count = len(re.findall(raw_pattern, raw))

        # Also check parsed objects for decoded names
        decoded_name = keyword.lstrip("/")
        obj_count = 0
        for obj in doc.objects.values():
            obj_count += _count_name_in_object(obj.value, decoded_name)

        result.suspicious_counts[keyword] = max(raw_count, obj_count)


def _count_name_in_object(value, name):
    """Recursively count occurrences of a name in a PDF object tree."""
    count = 0
    if isinstance(value, PDFDictionary):
        for key in value.keys():
            if key == name:
                count += 1
            count += _count_name_in_object(value.get(key), name)
    elif isinstance(value, PDFArray):
        for item in value:
            count += _count_name_in_object(item, name)
    elif isinstance(value, PDFName):
        if value.name == name:
            count += 1
    elif isinstance(value, PDFStream):
        count += _count_name_in_object(value.dictionary, name)
    return count


def _check_encryption(doc, result):
    """Check encryption details."""
    for keyword in ENCRYPTION_KEYWORDS:
        raw_pattern = re.escape(keyword.encode())
        count = len(re.findall(raw_pattern, doc.raw_data))
        result.encryption_info[keyword] = count

    if doc.encrypted and doc.encryption_dict:
        d = doc.encryption_dict
        v_val = d.get("V")
        r_val = d.get("R")
        if v_val:
            v = v_val.value if isinstance(v_val, PDFInteger) else v_val
            result.document_info["encryption_version"] = v
        if r_val:
            r = r_val.value if isinstance(r_val, PDFInteger) else r_val
            result.document_info["encryption_revision"] = r


def _scan_dangerous_patterns(doc, result):
    """Scan stream data and strings for dangerous code patterns."""
    # Collect all text content from streams and strings
    text_sources = []

    for obj in doc.objects.values():
        if obj.is_stream:
            data = obj.value.data
            if data:
                try:
                    text_sources.append(data.decode("latin-1", errors="replace"))
                except (UnicodeDecodeError, AttributeError):
                    pass

        # Also check raw_data for string content
        if obj.raw_data:
            try:
                if isinstance(obj.raw_data, bytes):
                    text_sources.append(obj.raw_data.decode("latin-1", errors="replace"))
                else:
                    text_sources.append(str(obj.raw_data))
            except (UnicodeDecodeError, AttributeError):
                pass

    combined_text = "\n".join(text_sources)

    for pattern, description in DANGEROUS_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            result.dangerous_patterns.append({
                "pattern": description,
                "count": len(matches),
                "samples": matches[:3],
            })


def _detect_obfuscation(doc, result):
    """Detect name obfuscation (hex-encoded name characters)."""
    for obj in doc.objects.values():
        _find_obfuscated_names(obj.value, result)

    # Also scan raw data for hex-encoded names
    hex_name_pattern = rb"/[A-Za-z0-9]*#[0-9a-fA-F]{2}[A-Za-z0-9#]*"
    raw_matches = re.findall(hex_name_pattern, doc.raw_data)
    result.name_hex_encoding_count = len(raw_matches)

    if result.name_hex_encoding_count > 0:
        result.warnings.append(
            f"Found {result.name_hex_encoding_count} hex-encoded name(s) "
            "(potential obfuscation)"
        )


def _find_obfuscated_names(value, result):
    """Recursively find obfuscated names in object tree."""
    if isinstance(value, PDFName):
        if value.is_obfuscated:
            result.obfuscated_names.append({
                "raw": f"/{value.raw_name}",
                "decoded": f"/{value.name}",
            })
    elif isinstance(value, PDFDictionary):
        for v in value.values():
            _find_obfuscated_names(v, result)
    elif isinstance(value, PDFArray):
        for item in value:
            _find_obfuscated_names(item, result)
    elif isinstance(value, PDFStream):
        _find_obfuscated_names(value.dictionary, result)


def _check_anomalies(doc, result):
    """Check for structural anomalies."""
    # Multiple %%EOF markers
    if doc.eof_count > 1:
        result.warnings.append(
            f"Multiple %%EOF markers ({doc.eof_count}) - "
            "indicates incremental updates or manipulation"
        )

    # Object count vs xref mismatch
    xref_count = sum(len(t) for t in doc.xref_tables)
    if xref_count > 0 and abs(len(doc.objects) - xref_count) > xref_count * 0.5:
        result.warnings.append(
            f"Object count ({len(doc.objects)}) differs significantly "
            f"from xref entries ({xref_count})"
        )

    # Header not at beginning
    if doc.raw_data[:5] != b"%PDF-":
        result.warnings.append("PDF header not at file start (possible polyglot)")

    # Check for embedded files
    ef_count = 0
    for obj in doc.objects.values():
        d = obj.dictionary
        if d and "EF" in d:
            ef_count += 1
    if ef_count > 0:
        result.warnings.append(f"Document contains {ef_count} embedded file(s)")

    # Unusually large number of objects
    if len(doc.objects) > 10000:
        result.warnings.append(
            f"Very large number of objects ({len(doc.objects)}) - "
            "possible resource exhaustion attempt"
        )


def _calculate_risk_score(result):
    """Calculate an overall risk score (0-100) based on findings."""
    score = 0
    factors = []

    # JavaScript presence (high risk)
    js_count = result.suspicious_counts.get("/JS", 0) + \
               result.suspicious_counts.get("/JavaScript", 0)
    if js_count > 0:
        score += min(30, js_count * 15)
        factors.append(f"JavaScript detected ({js_count} reference(s))")

    # Auto-execute actions
    aa_count = result.suspicious_counts.get("/AA", 0) + \
               result.suspicious_counts.get("/OpenAction", 0)
    if aa_count > 0:
        score += min(20, aa_count * 10)
        factors.append(f"Auto-execute actions ({aa_count})")

    # Launch actions
    launch_count = result.suspicious_counts.get("/Launch", 0)
    if launch_count > 0:
        score += 20
        factors.append(f"Launch action(s) ({launch_count})")

    # Embedded files
    ef_count = result.suspicious_counts.get("/EmbeddedFile", 0)
    if ef_count > 0:
        score += min(15, ef_count * 5)
        factors.append(f"Embedded file(s) ({ef_count})")

    # XFA forms
    xfa_count = result.suspicious_counts.get("/XFA", 0)
    if xfa_count > 0:
        score += 10
        factors.append("XFA form(s)")

    # JBIG2 (historical exploit vector)
    jbig2_count = result.suspicious_counts.get("/JBIG2Decode", 0)
    if jbig2_count > 0:
        score += 10
        factors.append("JBIG2Decode usage")

    # Rich media
    rm_count = result.suspicious_counts.get("/RichMedia", 0)
    if rm_count > 0:
        score += 10
        factors.append("Rich media content")

    # Obfuscated names
    if result.name_hex_encoding_count > 5:
        score += 15
        factors.append(f"Heavy name obfuscation ({result.name_hex_encoding_count})")
    elif result.name_hex_encoding_count > 0:
        score += 5
        factors.append(f"Name obfuscation ({result.name_hex_encoding_count})")

    # Dangerous code patterns
    if result.dangerous_patterns:
        pattern_score = min(25, len(result.dangerous_patterns) * 5)
        score += pattern_score
        for dp in result.dangerous_patterns:
            factors.append(f"Dangerous pattern: {dp['pattern']}")

    # URI/form submission
    submit_count = result.suspicious_counts.get("/SubmitForm", 0)
    if submit_count > 0:
        score += 10
        factors.append(f"Form submission action(s) ({submit_count})")

    # Multiple incremental updates
    inc_updates = result.document_info.get("incremental_updates", 0)
    if inc_updates > 2:
        score += 5
        factors.append(f"Multiple incremental updates ({inc_updates})")

    result.risk_score = min(100, score)
    result.risk_factors = factors

    if result.risk_score >= 70:
        result.risk_level = "CRITICAL"
    elif result.risk_score >= 50:
        result.risk_level = "HIGH"
    elif result.risk_score >= 25:
        result.risk_level = "MEDIUM"
    else:
        result.risk_level = "LOW"


def format_scan_report(result, verbose=False):
    """
    Format scan results as a human-readable report.

    Args:
        result: ScanResult instance.
        verbose: If True, include all keyword counts; otherwise only non-zero.

    Returns:
        str: Formatted report.
    """
    lines = []
    info = result.document_info

    # Header
    lines.append("=" * 65)
    lines.append("  PDetectiF - PDF Security Analysis Report")
    lines.append("=" * 65)

    # Document info
    lines.append("")
    lines.append("── Document Info ──")
    lines.append(f"  File:          {info.get('file', 'N/A')}")
    lines.append(f"  Size:          {_format_size(info.get('size', 0))}")
    lines.append(f"  PDF Version:   {info.get('version', 'N/A')}")
    lines.append(f"  Pages:         {info.get('pages', 'N/A')}")
    lines.append(f"  Objects:       {info.get('objects', 0)}")
    lines.append(f"  Streams:       {info.get('streams', 0)}")
    lines.append(f"  Encrypted:     {'Yes' if info.get('encrypted') else 'No'}")
    lines.append(f"  Linearized:    {'Yes' if info.get('linearized') else 'No'}")
    if info.get("incremental_updates", 0) > 0:
        lines.append(f"  Inc. Updates:  {info['incremental_updates']}")

    # Structural keywords
    lines.append("")
    lines.append("── Structure ──")
    for kw, count in result.structural_counts.items():
        if verbose or count > 0:
            pad = " " * max(1, 18 - len(kw))
            lines.append(f"  {kw}{pad}{count}")

    # Suspicious keywords
    lines.append("")
    lines.append("── Suspicious Keywords ──")
    has_suspicious = False
    for kw, count in result.suspicious_counts.items():
        if verbose or count > 0:
            has_suspicious = True
            pad = " " * max(1, 18 - len(kw))
            desc = SUSPICIOUS_KEYWORDS.get(kw, "")
            indicator = " ⚠" if count > 0 else ""
            lines.append(f"  {kw}{pad}{count}{indicator}")
    if not has_suspicious:
        lines.append("  (none detected)")

    # Dangerous patterns
    if result.dangerous_patterns:
        lines.append("")
        lines.append("── Dangerous Patterns ──")
        for dp in result.dangerous_patterns:
            lines.append(f"  ⚠ {dp['pattern']} (×{dp['count']})")

    # Obfuscation
    if result.obfuscated_names or result.name_hex_encoding_count > 0:
        lines.append("")
        lines.append("── Obfuscation ──")
        lines.append(f"  Hex-encoded names: {result.name_hex_encoding_count}")
        for ob in result.obfuscated_names[:10]:
            lines.append(f"    {ob['raw']}  →  {ob['decoded']}")
        if len(result.obfuscated_names) > 10:
            lines.append(f"    ... and {len(result.obfuscated_names) - 10} more")

    # Encryption details
    if info.get("encrypted"):
        lines.append("")
        lines.append("── Encryption ──")
        if "encryption_version" in info:
            lines.append(f"  Version (V):   {info['encryption_version']}")
        if "encryption_revision" in info:
            lines.append(f"  Revision (R):  {info['encryption_revision']}")

    # Warnings
    if result.warnings:
        lines.append("")
        lines.append("── Warnings ──")
        for w in result.warnings:
            lines.append(f"  ⚠ {w}")

    # Risk assessment
    lines.append("")
    lines.append("── Risk Assessment ──")
    bar = _risk_bar(result.risk_score)
    lines.append(f"  Score:  {result.risk_score}/100  {bar}  [{result.risk_level}]")
    if result.risk_factors:
        lines.append("  Factors:")
        for f in result.risk_factors:
            lines.append(f"    • {f}")

    lines.append("")
    lines.append("=" * 65)

    return "\n".join(lines)


def _format_size(size_bytes):
    """Format byte count as human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def _risk_bar(score):
    """Generate a visual risk bar."""
    filled = score // 5
    empty = 20 - filled
    return "[" + "█" * filled + "░" * empty + "]"
