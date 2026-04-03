"""
JavaScript extraction from PDF documents.

Extracts JavaScript code from /JS entries, /JavaScript actions,
OpenAction scripts, and decoded stream content. Also detects
JavaScript in string objects and hex-encoded strings.
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
    PDFIndirectObject,
)


def extract_javascript(doc):
    """
    Extract all JavaScript from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Extraction results with JS code snippets and locations.
    """
    results = {
        "scripts": [],
        "total_scripts": 0,
        "total_size": 0,
        "locations": [],
    }

    # Method 1: Find /JS entries in object dictionaries
    for (obj_num, gen_num), obj in doc.objects.items():
        _extract_js_from_value(doc, obj.value, obj_num, gen_num, results)

    # Method 2: Scan decoded streams for JavaScript patterns
    for (obj_num, gen_num), obj in doc.objects.items():
        if not obj.is_stream:
            continue

        # Check if stream is associated with JavaScript
        d = obj.value.dictionary
        is_js_stream = False
        if d:
            subtype = d.get("Subtype") or d.get("S")
            if isinstance(subtype, PDFName) and subtype.name in ("JavaScript", "JS"):
                is_js_stream = True

        data = obj.value.data
        if data:
            try:
                text = data.decode("latin-1", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                continue

            if is_js_stream or _looks_like_javascript(text):
                _add_script(results, text, f"stream {obj_num} {gen_num}",
                            "stream_content")

    results["total_scripts"] = len(results["scripts"])
    results["total_size"] = sum(len(s["code"]) for s in results["scripts"])

    return results


def _extract_js_from_value(doc, value, obj_num, gen_num, results, path=""):
    """Recursively extract JavaScript from PDF object trees."""
    if isinstance(value, PDFDictionary):
        # Check /S /JavaScript or /JS entries
        s_val = value.get("S")
        if isinstance(s_val, PDFName) and s_val.name in ("JavaScript", "JS"):
            js_val = value.get("JS")
            if js_val:
                _handle_js_value(doc, js_val, obj_num, gen_num, results,
                                 f"{path}/Action")

        # Direct /JS key
        js_val = value.get("JS")
        if js_val and not (isinstance(s_val, PDFName) and s_val.name in ("JavaScript", "JS")):
            _handle_js_value(doc, js_val, obj_num, gen_num, results,
                             f"{path}/JS")

        # Check /JavaScript name tree
        js_tree = value.get("JavaScript")
        if isinstance(js_tree, PDFDictionary):
            _extract_js_from_value(doc, js_tree, obj_num, gen_num, results,
                                   f"{path}/JavaScript")

        # Recurse into all dictionary values
        for key in value.keys():
            if key not in ("JS", "JavaScript"):
                child = value.get(key)
                _extract_js_from_value(doc, child, obj_num, gen_num, results,
                                       f"{path}/{key}")

    elif isinstance(value, PDFArray):
        for i, item in enumerate(value):
            _extract_js_from_value(doc, item, obj_num, gen_num, results,
                                   f"{path}[{i}]")

    elif isinstance(value, PDFStream):
        _extract_js_from_value(doc, value.dictionary, obj_num, gen_num, results,
                               path)

    elif isinstance(value, PDFReference):
        # Resolve reference (avoid infinite loops by not going too deep)
        if path.count("/") < 20:
            resolved = doc.get_object(value.obj_num, value.gen_num)
            if resolved:
                _extract_js_from_value(doc, resolved.value,
                                       value.obj_num, value.gen_num, results,
                                       f"ref({value.obj_num})")


def _handle_js_value(doc, js_val, obj_num, gen_num, results, location):
    """Handle a /JS value which may be a string, hex string, stream, or reference."""
    if isinstance(js_val, PDFString):
        _add_script(results, js_val.value,
                    f"object {obj_num} {gen_num} {location}", "string")

    elif isinstance(js_val, PDFHexString):
        _add_script(results, str(js_val),
                    f"object {obj_num} {gen_num} {location}", "hex_string")

    elif isinstance(js_val, PDFStream):
        data = js_val.data
        if data:
            try:
                text = data.decode("latin-1", errors="replace")
                _add_script(results, text,
                            f"object {obj_num} {gen_num} {location}", "stream")
            except (UnicodeDecodeError, AttributeError):
                pass

    elif isinstance(js_val, PDFReference):
        resolved = doc.get_object(js_val.obj_num, js_val.gen_num)
        if resolved:
            if resolved.is_stream:
                data = resolved.value.data
                if data:
                    try:
                        text = data.decode("latin-1", errors="replace")
                        _add_script(results, text,
                                    f"ref {js_val.obj_num} {js_val.gen_num}",
                                    "referenced_stream")
                    except (UnicodeDecodeError, AttributeError):
                        pass
            else:
                _handle_js_value(doc, resolved.value, js_val.obj_num,
                                 js_val.gen_num, results, location)


def _add_script(results, code, location, source_type):
    """Add a JavaScript snippet to results, avoiding duplicates."""
    code = code.strip()
    if not code:
        return

    # Check for duplicates
    for existing in results["scripts"]:
        if existing["code"] == code:
            return

    results["scripts"].append({
        "code": code,
        "location": location,
        "source_type": source_type,
        "size": len(code),
    })
    results["locations"].append(location)


def _looks_like_javascript(text):
    """Heuristic check if text content appears to be JavaScript."""
    js_patterns = [
        r"\bfunction\s*\(",
        r"\bvar\s+\w+\s*=",
        r"\bapp\.\w+",
        r"\bthis\.\w+",
        r"\bdocument\.\w+",
        r"\beval\s*\(",
        r"\bString\.fromCharCode",
        r"\bunescape\s*\(",
        r"\bgetField\s*\(",
    ]
    matches = sum(1 for p in js_patterns if re.search(p, text))
    return matches >= 2


def format_javascript_report(results):
    """Format JavaScript extraction results."""
    lines = []
    lines.append("── JavaScript Extraction ──")
    lines.append(f"  Scripts found:   {results['total_scripts']}")
    lines.append(f"  Total JS size:   {results['total_size']} bytes")

    for i, script in enumerate(results["scripts"], 1):
        lines.append("")
        lines.append(f"  Script #{i} ({script['source_type']}, "
                     f"{script['size']} bytes)")
        lines.append(f"  Location: {script['location']}")
        lines.append("  " + "-" * 50)

        # Show the code (limit to reasonable size for display)
        code = script["code"]
        if len(code) > 2000:
            code = code[:2000] + f"\n... ({len(code) - 2000} more bytes)"
        for line in code.split("\n"):
            lines.append(f"  | {line}")

    if not results["scripts"]:
        lines.append("  No JavaScript found.")

    return "\n".join(lines)
