"""
URL, URI, and email extraction from PDF documents.

Extracts URLs from /URI actions, annotations, decoded streams,
string objects, and raw PDF data. Also extracts email addresses.
"""

import re

from ..core.objects import (
    PDFDictionary,
    PDFName,
    PDFString,
    PDFHexString,
    PDFStream,
    PDFArray,
    PDFReference,
)


# Patterns
URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"')\]}>]+|ftp://[^\s<>\"')\]}>]+)",
    re.IGNORECASE,
)

URI_PATTERN = re.compile(
    r"(https?://[^\s<>\"')\]}>]+|ftp://[^\s<>\"')\]}>]+|"
    r"file://[^\s<>\"')\]}>]+|mailto:[^\s<>\"')\]}>]+)",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|mil|int|info|biz|name|pro|museum|coop|aero|"
    r"io|dev|app|xyz|online|site|tech|store|blog|cloud|ai|co|us|uk|de|fr|"
    r"ru|cn|jp|br|in|au|ca|it|es|nl|se|no|fi|dk|pl|cz|at|ch|be|ie|pt)\b",
    re.IGNORECASE,
)


def extract_urls(doc):
    """
    Extract all URLs from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Extraction results.
    """
    results = {
        "urls": [],
        "uri_actions": [],
        "total": 0,
    }

    seen = set()

    # Method 1: Extract from /URI actions in parsed objects
    for (obj_num, gen_num), obj in doc.objects.items():
        _extract_uris_from_value(doc, obj.value, obj_num, results, seen)

    # Method 2: Scan decoded stream data
    for (obj_num, gen_num), obj in doc.objects.items():
        if obj.is_stream:
            data = obj.value.data
            if data:
                try:
                    text = data.decode("latin-1", errors="replace")
                    _extract_urls_from_text(text, f"stream {obj_num}", results, seen)
                except (UnicodeDecodeError, AttributeError):
                    pass

    # Method 3: Scan raw data as fallback
    try:
        raw_text = doc.raw_data.decode("latin-1", errors="replace")
        _extract_urls_from_text(raw_text, "raw_data", results, seen)
    except (UnicodeDecodeError, AttributeError):
        pass

    results["total"] = len(results["urls"])
    return results


def _extract_uris_from_value(doc, value, obj_num, results, seen):
    """Recursively extract URIs from PDF object tree."""
    if isinstance(value, PDFDictionary):
        # Check for /URI action
        s_val = value.get("S")
        uri_val = value.get("URI")
        if isinstance(s_val, PDFName) and s_val.name == "URI" and uri_val:
            url = _extract_string_value(uri_val)
            if url and url not in seen:
                seen.add(url)
                results["uri_actions"].append({
                    "url": url,
                    "object": obj_num,
                    "type": "URI_action",
                })
                results["urls"].append(url)

        # Check for /A (action) dictionary with URI
        a_val = value.get("A")
        if isinstance(a_val, PDFDictionary):
            _extract_uris_from_value(doc, a_val, obj_num, results, seen)
        elif isinstance(a_val, PDFReference):
            resolved = doc.get_object(a_val.obj_num, a_val.gen_num)
            if resolved:
                _extract_uris_from_value(doc, resolved.value, obj_num, results, seen)

        # Recurse into all values
        for key in value.keys():
            if key not in ("URI", "A"):
                child = value.get(key)
                if isinstance(child, (PDFDictionary, PDFArray)):
                    _extract_uris_from_value(doc, child, obj_num, results, seen)

    elif isinstance(value, PDFArray):
        for item in value:
            _extract_uris_from_value(doc, item, obj_num, results, seen)

    elif isinstance(value, PDFStream):
        _extract_uris_from_value(doc, value.dictionary, obj_num, results, seen)


def _extract_string_value(val):
    """Extract string content from various PDF string types."""
    if isinstance(val, PDFString):
        return val.value
    elif isinstance(val, PDFHexString):
        return str(val)
    elif isinstance(val, str):
        return val
    return None


def _extract_urls_from_text(text, source, results, seen):
    """Extract URLs from text using regex."""
    for match in URL_PATTERN.finditer(text):
        url = match.group(0)
        # Clean trailing punctuation
        url = url.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            results["urls"].append(url)


def extract_emails(doc):
    """
    Extract all email addresses from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Extraction results.
    """
    results = {
        "emails": [],
        "total": 0,
    }

    seen = set()

    # Scan decoded streams
    for (obj_num, _), obj in doc.objects.items():
        if obj.is_stream:
            data = obj.value.data
            if data:
                try:
                    text = data.decode("latin-1", errors="replace")
                    for match in EMAIL_PATTERN.finditer(text):
                        email = match.group(0)
                        if email not in seen:
                            seen.add(email)
                            results["emails"].append(email)
                except (UnicodeDecodeError, AttributeError):
                    pass

    # Scan raw data
    try:
        raw_text = doc.raw_data.decode("latin-1", errors="replace")
        for match in EMAIL_PATTERN.finditer(raw_text):
            email = match.group(0)
            if email not in seen:
                seen.add(email)
                results["emails"].append(email)
    except (UnicodeDecodeError, AttributeError):
        pass

    results["total"] = len(results["emails"])
    return results


def extract_domains(doc):
    """
    Extract domain names and IP addresses from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Extraction results with domains and IPs.
    """
    results = {
        "domains": [],
        "ip_addresses": [],
        "total_domains": 0,
        "total_ips": 0,
    }

    seen_domains = set()
    seen_ips = set()

    try:
        raw_text = doc.raw_data.decode("latin-1", errors="replace")
    except (UnicodeDecodeError, AttributeError):
        return results

    # Extract domains
    for match in DOMAIN_PATTERN.finditer(raw_text):
        domain = match.group(0).lower()
        if domain not in seen_domains:
            seen_domains.add(domain)
            results["domains"].append(domain)

    # Extract IPs
    for match in IP_PATTERN.finditer(raw_text):
        ip = match.group(0)
        # Basic validation
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            if ip not in seen_ips:
                seen_ips.add(ip)
                results["ip_addresses"].append(ip)

    results["total_domains"] = len(results["domains"])
    results["total_ips"] = len(results["ip_addresses"])
    return results


def format_url_report(results):
    """Format URL extraction results."""
    lines = []
    lines.append("── URL Extraction ──")
    lines.append(f"  Total URLs found: {results['total']}")

    if results["uri_actions"]:
        lines.append("")
        lines.append("  URI Actions:")
        for ua in results["uri_actions"]:
            lines.append(f"    Object {ua['object']}: {ua['url']}")

    if results["urls"]:
        lines.append("")
        lines.append("  All URLs:")
        for url in results["urls"]:
            lines.append(f"    {url}")

    if not results["urls"]:
        lines.append("  No URLs found.")

    return "\n".join(lines)


def format_email_report(results):
    """Format email extraction results."""
    lines = []
    lines.append("── Email Extraction ──")
    lines.append(f"  Total emails found: {results['total']}")

    for email in results["emails"]:
        lines.append(f"    {email}")

    if not results["emails"]:
        lines.append("  No email addresses found.")

    return "\n".join(lines)
