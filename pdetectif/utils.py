"""
Utility functions for PDetectiF.

Provides hex dump, formatting, and other helper functions.
"""


def hex_dump(data, offset=0, length=None, width=16):
    """
    Generate a hex dump of binary data.

    Args:
        data: bytes to dump.
        offset: Starting offset for display.
        length: Maximum number of bytes to dump.
        width: Bytes per line (default 16).

    Returns:
        str: Formatted hex dump.
    """
    if length is not None:
        data = data[:length]

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        hex_padded = hex_part.ljust(width * 3 - 1)
        lines.append(f"  {offset + i:08x}  {hex_padded}  |{ascii_part}|")

    return "\n".join(lines)


def format_object_tree(obj, indent=0, max_depth=10):
    """
    Format a PDF object as an indented tree for display.

    Args:
        obj: A PDF object.
        indent: Current indentation level.
        max_depth: Maximum recursion depth.

    Returns:
        str: Formatted tree representation.
    """
    from .core.objects import (
        PDFDictionary, PDFArray, PDFStream, PDFIndirectObject,
        PDFName, PDFString, PDFHexString, PDFReference,
        PDFInteger, PDFReal, PDFBoolean, PDFNull,
    )

    prefix = "  " * indent

    if indent > max_depth:
        return f"{prefix}..."

    if isinstance(obj, PDFIndirectObject):
        header = f"{prefix}{obj.obj_num} {obj.gen_num} obj"
        body = format_object_tree(obj.value, indent + 1, max_depth)
        return f"{header}\n{body}\n{prefix}endobj"

    if isinstance(obj, PDFStream):
        dict_str = format_object_tree(obj.dictionary, indent, max_depth)
        data_len = len(obj.data) if obj.data else 0
        raw_len = len(obj.raw_data) if obj.raw_data else 0
        return (f"{dict_str}\n"
                f"{prefix}stream ({raw_len} raw bytes, {data_len} decoded bytes)")

    if isinstance(obj, PDFDictionary):
        if not obj.entries:
            return f"{prefix}<< >>"
        lines = [f"{prefix}<<"]
        for key, val in obj.items():
            val_str = format_object_tree(val, indent + 1, max_depth)
            # For simple values, put on same line
            if "\n" not in val_str:
                lines.append(f"{prefix}  /{key} {val_str.strip()}")
            else:
                lines.append(f"{prefix}  /{key}")
                lines.append(val_str)
        lines.append(f"{prefix}>>")
        return "\n".join(lines)

    if isinstance(obj, PDFArray):
        if not obj.items:
            return f"{prefix}[]"
        if len(obj.items) <= 5 and all(
            isinstance(i, (PDFInteger, PDFReal, PDFReference, PDFName, PDFNull))
            for i in obj.items
        ):
            items_str = " ".join(repr(i) for i in obj.items)
            return f"{prefix}[{items_str}]"
        lines = [f"{prefix}["]
        for item in obj.items:
            lines.append(format_object_tree(item, indent + 1, max_depth))
        lines.append(f"{prefix}]")
        return "\n".join(lines)

    return f"{prefix}{repr(obj)}"


def format_raw_object(obj_data, max_length=5000):
    """
    Format raw object data for display.

    Args:
        obj_data: Raw bytes of the object.
        max_length: Maximum characters to display.

    Returns:
        str: Formatted raw object data.
    """
    if isinstance(obj_data, bytes):
        try:
            text = obj_data.decode("latin-1", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return hex_dump(obj_data, length=max_length)
    else:
        text = str(obj_data)

    if len(text) > max_length:
        text = text[:max_length] + f"\n... ({len(text) - max_length} more characters)"

    return text
