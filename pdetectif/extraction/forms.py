"""
AcroForm field extraction from PDF documents.

Extracts interactive form fields, their types, values, default
values, and associated actions (calculation scripts, format
actions, keystroke handlers).
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


# Field type mapping
FIELD_TYPES = {
    "Tx": "Text",
    "Btn": "Button",
    "Ch": "Choice",
    "Sig": "Signature",
}


def extract_form_fields(doc):
    """
    Extract all AcroForm fields from a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Form extraction results.
    """
    results = {
        "has_acroform": False,
        "fields": [],
        "field_actions": [],
        "xfa": False,
        "total_fields": 0,
        "signatures": 0,
    }

    catalog = doc.catalog
    if not catalog:
        return results

    d = catalog.dictionary
    if not d:
        return results

    acroform = d.get("AcroForm")
    if isinstance(acroform, PDFReference):
        obj = doc.get_object(acroform.obj_num, acroform.gen_num)
        if obj:
            acroform = obj.value
    if not isinstance(acroform, PDFDictionary):
        return results

    results["has_acroform"] = True

    # Check for XFA
    xfa = acroform.get("XFA")
    if xfa is not None:
        results["xfa"] = True

    # Get fields array
    fields = acroform.get("Fields")
    if isinstance(fields, PDFReference):
        obj = doc.get_object(fields.obj_num, fields.gen_num)
        if obj:
            fields = obj.value
    if isinstance(fields, PDFArray):
        for item in fields:
            _extract_field(doc, item, results, depth=0)

    results["total_fields"] = len(results["fields"])
    results["signatures"] = sum(
        1 for f in results["fields"] if f["type"] == "Signature"
    )

    return results


def _extract_field(doc, field_ref, results, depth):
    """Extract a single form field and recurse into kids."""
    if depth > 20:
        return

    field = field_ref
    if isinstance(field, PDFReference):
        obj = doc.get_object(field.obj_num, field.gen_num)
        if not obj:
            return
        field = obj.value

    if not isinstance(field, PDFDictionary):
        return

    # Field info
    ft = field.get("FT")
    field_type = ""
    if isinstance(ft, PDFName):
        field_type = FIELD_TYPES.get(ft.name, ft.name)

    name = _get_str(field.get("T"))
    full_name = _get_str(field.get("TU")) or name
    value = _get_str(field.get("V"))
    default = _get_str(field.get("DV"))

    # Flags
    ff = field.get("Ff")
    flags = ff.value if isinstance(ff, PDFInteger) else 0

    entry = {
        "name": name or "(unnamed)",
        "full_name": full_name or "",
        "type": field_type or "Unknown",
        "value": value,
        "default_value": default,
        "flags": flags,
        "actions": [],
    }

    # Check for actions (AA = additional actions)
    aa = field.get("AA")
    if isinstance(aa, PDFReference):
        obj = doc.get_object(aa.obj_num, aa.gen_num)
        if obj:
            aa = obj.value
    if isinstance(aa, PDFDictionary):
        action_types = {
            "K": "Keystroke",
            "F": "Format",
            "V": "Validate",
            "C": "Calculate",
            "E": "Enter",
            "X": "Exit",
            "Fo": "Focus",
            "Bl": "Blur",
        }
        for key, desc in action_types.items():
            action = aa.get(key)
            if action is not None:
                action_info = {"trigger": desc}
                if isinstance(action, PDFReference):
                    obj = doc.get_object(action.obj_num, action.gen_num)
                    if obj:
                        action = obj.value
                if isinstance(action, PDFDictionary):
                    s = action.get("S")
                    if isinstance(s, PDFName):
                        action_info["type"] = s.name
                    js = action.get("JS")
                    if js is not None:
                        js_text = _get_str(js)
                        if js_text:
                            action_info["javascript"] = js_text[:200]
                entry["actions"].append(action_info)
                results["field_actions"].append({
                    "field": name or "(unnamed)",
                    **action_info,
                })

    # Direct action (A key)
    a_val = field.get("A")
    if isinstance(a_val, PDFReference):
        obj = doc.get_object(a_val.obj_num, a_val.gen_num)
        if obj:
            a_val = obj.value
    if isinstance(a_val, PDFDictionary):
        action_info = {"trigger": "Activate"}
        s = a_val.get("S")
        if isinstance(s, PDFName):
            action_info["type"] = s.name
        js = a_val.get("JS")
        if js is not None:
            js_text = _get_str(js)
            if js_text:
                action_info["javascript"] = js_text[:200]
        entry["actions"].append(action_info)
        results["field_actions"].append({
            "field": name or "(unnamed)",
            **action_info,
        })

    if field_type:
        results["fields"].append(entry)

    # Recurse into kids
    kids = field.get("Kids")
    if isinstance(kids, PDFReference):
        obj = doc.get_object(kids.obj_num, kids.gen_num)
        if obj:
            kids = obj.value
    if isinstance(kids, PDFArray):
        for kid in kids:
            _extract_field(doc, kid, results, depth + 1)


def _get_str(val):
    """Extract string from various PDF types."""
    if isinstance(val, PDFString):
        return val.value
    elif isinstance(val, PDFHexString):
        return str(val)
    elif isinstance(val, PDFName):
        return val.name
    elif isinstance(val, str):
        return val
    return None


def format_forms_report(results):
    """Format form extraction results."""
    lines = []
    lines.append("── Form Fields ──")

    if not results["has_acroform"]:
        lines.append("  No AcroForm found.")
        return "\n".join(lines)

    lines.append(f"  Total fields:  {results['total_fields']}")
    lines.append(f"  Signatures:    {results['signatures']}")
    lines.append(f"  XFA:           {'Yes' if results['xfa'] else 'No'}")

    if results["fields"]:
        lines.append("")
        for f in results["fields"]:
            lines.append(f"  Field: {f['name']}")
            lines.append(f"    Type:  {f['type']}")
            if f["value"]:
                lines.append(f"    Value: {f['value']}")
            if f["actions"]:
                for a in f["actions"]:
                    js = a.get("javascript", "")
                    js_preview = f" -> {js[:80]}..." if js else ""
                    lines.append(
                        f"    Action: {a['trigger']}"
                        f" ({a.get('type', '?')}){js_preview}"
                    )

    if results["field_actions"]:
        lines.append("")
        lines.append(f"  Total field actions: {len(results['field_actions'])}")

    return "\n".join(lines)
