"""
PDF metadata extraction.

Extracts document metadata from the Info dictionary, XMP metadata
streams, and other document properties.
"""

import re

from ..core.objects import (
    PDFDictionary,
    PDFName,
    PDFString,
    PDFHexString,
    PDFStream,
    PDFReference,
    PDFArray,
    PDFInteger,
    PDFReal,
    PDFBoolean,
)


# Standard Info dictionary keys
INFO_KEYS = [
    "Title", "Author", "Subject", "Keywords", "Creator",
    "Producer", "CreationDate", "ModDate", "Trapped",
]


def extract_metadata(doc):
    """
    Extract all metadata from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Metadata extraction results.
    """
    results = {
        "info": {},
        "xmp": None,
        "custom_metadata": {},
        "document_id": None,
        "creation_tool": None,
    }

    # Extract from trailer /Info reference
    for trailer in doc.trailers:
        info_ref = trailer.get("Info")
        if isinstance(info_ref, PDFReference):
            info_obj = doc.get_object(info_ref.obj_num, info_ref.gen_num)
            if info_obj and info_obj.dictionary:
                _extract_info_dict(info_obj.dictionary, results)
        elif isinstance(info_ref, PDFDictionary):
            _extract_info_dict(info_ref, results)

        # Document ID
        id_val = trailer.get("ID")
        if isinstance(id_val, PDFArray) and len(id_val) >= 1:
            ids = []
            for item in id_val:
                if isinstance(item, PDFHexString):
                    ids.append(item.hex_value)
                elif isinstance(item, PDFString):
                    ids.append(item.value.encode("latin-1").hex())
                else:
                    ids.append(str(item))
            results["document_id"] = ids

    # Extract XMP metadata from metadata streams
    for (obj_num, _), obj in doc.objects.items():
        if obj.is_stream:
            d = obj.value.dictionary
            if d:
                subtype = d.get("Subtype") or d.get("Type")
                if isinstance(subtype, PDFName) and subtype.name == "Metadata":
                    data = obj.value.data
                    if data:
                        try:
                            xmp_text = data.decode("utf-8", errors="replace")
                            results["xmp"] = _parse_xmp(xmp_text)
                        except (UnicodeDecodeError, AttributeError):
                            pass

    # Determine creation tool
    producer = results["info"].get("Producer", "")
    creator = results["info"].get("Creator", "")
    if producer:
        results["creation_tool"] = producer
    elif creator:
        results["creation_tool"] = creator

    return results


def _extract_info_dict(dictionary, results):
    """Extract standard and custom metadata from an Info dictionary."""
    for key in dictionary.keys():
        val = dictionary.get(key)
        str_val = _value_to_string(val)

        if key in INFO_KEYS:
            results["info"][key] = str_val
        else:
            results["custom_metadata"][key] = str_val


def _value_to_string(val):
    """Convert a PDF value to a string representation."""
    if isinstance(val, PDFString):
        text = val.value
        # Handle Unicode BOM
        if text.startswith("\xfe\xff"):
            try:
                raw = val.raw if isinstance(val.raw, bytes) else val.value.encode("latin-1")
                return raw[2:].decode("utf-16-be", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                pass
        return text
    elif isinstance(val, PDFHexString):
        # Try to decode as text
        try:
            if val.value[:2] == b"\xfe\xff":
                return val.value[2:].decode("utf-16-be", errors="replace")
            return val.value.decode("latin-1", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return val.hex_value
    elif isinstance(val, PDFName):
        return val.name
    elif isinstance(val, (PDFInteger, PDFReal)):
        return str(val.value)
    elif isinstance(val, PDFBoolean):
        return str(val.value)
    elif val is None:
        return ""
    return str(val)


def _parse_xmp(xmp_text):
    """Parse XMP (XML) metadata into a dictionary of key-value pairs."""
    results = {}

    # Extract common XMP properties using simple regex
    # (avoids needing xml.etree for potentially malformed XMP)
    xmp_tags = [
        ("dc:title", r"<dc:title[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
        ("dc:creator", r"<dc:creator[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
        ("dc:description", r"<dc:description[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
        ("dc:subject", r"<dc:subject[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
        ("xmp:CreateDate", r"<xmp:CreateDate>(.*?)</xmp:CreateDate>"),
        ("xmp:ModifyDate", r"<xmp:ModifyDate>(.*?)</xmp:ModifyDate>"),
        ("xmp:CreatorTool", r"<xmp:CreatorTool>(.*?)</xmp:CreatorTool>"),
        ("xmp:MetadataDate", r"<xmp:MetadataDate>(.*?)</xmp:MetadataDate>"),
        ("pdf:Producer", r"<pdf:Producer>(.*?)</pdf:Producer>"),
        ("pdf:Keywords", r"<pdf:Keywords>(.*?)</pdf:Keywords>"),
        ("pdf:PDFVersion", r"<pdf:PDFVersion>(.*?)</pdf:PDFVersion>"),
        ("pdfaid:part", r"<pdfaid:part>(.*?)</pdfaid:part>"),
        ("pdfaid:conformance", r"<pdfaid:conformance>(.*?)</pdfaid:conformance>"),
    ]

    for name, pattern in xmp_tags:
        match = re.search(pattern, xmp_text, re.DOTALL | re.IGNORECASE)
        if match:
            results[name] = match.group(1).strip()

    # Store raw XMP if we found anything
    if not results:
        # Just store a truncated version of raw XMP
        results["raw"] = xmp_text[:2000] if len(xmp_text) > 2000 else xmp_text

    return results


def format_metadata_report(results):
    """Format metadata extraction results."""
    lines = []
    lines.append("── Document Metadata ──")

    if results["info"]:
        for key in INFO_KEYS:
            if key in results["info"]:
                val = results["info"][key]
                pad = " " * max(1, 18 - len(key))
                lines.append(f"  {key}{pad}{val}")

    if results["custom_metadata"]:
        lines.append("")
        lines.append("  Custom metadata:")
        for key, val in results["custom_metadata"].items():
            pad = " " * max(1, 18 - len(key))
            lines.append(f"    {key}{pad}{val}")

    if results["document_id"]:
        lines.append("")
        lines.append("  Document ID:")
        for i, id_val in enumerate(results["document_id"]):
            lines.append(f"    [{i}] {id_val}")

    if results["creation_tool"]:
        lines.append(f"\n  Creation Tool:   {results['creation_tool']}")

    if results["xmp"]:
        lines.append("")
        lines.append("  XMP Metadata:")
        for key, val in results["xmp"].items():
            if key == "raw":
                lines.append(f"    (raw XMP: {len(val)} chars)")
            else:
                pad = " " * max(1, 22 - len(key))
                lines.append(f"    {key}{pad}{val}")

    if not results["info"] and not results["xmp"]:
        lines.append("  No metadata found.")

    return "\n".join(lines)
