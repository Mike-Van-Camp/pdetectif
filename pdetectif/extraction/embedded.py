"""
Embedded file and stream content extraction from PDF documents.

Extracts embedded files (EmbeddedFile streams), attachments,
and provides raw stream data access. Also handles extraction
of images, fonts, and other embedded resources metadata.
"""

import os

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


def extract_embedded_files(doc):
    """
    Extract information about embedded files in a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Information about embedded files.
    """
    results = {
        "files": [],
        "total": 0,
    }

    # Method 1: Find via catalog /Names /EmbeddedFiles
    catalog = doc.catalog
    if catalog:
        d = catalog.dictionary
        if d:
            names = d.get("Names")
            if isinstance(names, PDFReference):
                names_obj = doc.get_object(names.obj_num, names.gen_num)
                if names_obj:
                    names = names_obj.value

            if isinstance(names, PDFDictionary):
                ef_tree = names.get("EmbeddedFiles")
                if isinstance(ef_tree, PDFReference):
                    ef_obj = doc.get_object(ef_tree.obj_num, ef_tree.gen_num)
                    if ef_obj:
                        ef_tree = ef_obj.value
                if isinstance(ef_tree, PDFDictionary):
                    _extract_from_name_tree(doc, ef_tree, results)

    # Method 2: Find /EF (embedded file) entries in any object
    for (obj_num, _), obj in doc.objects.items():
        d = obj.dictionary
        if d is None:
            continue

        ef_val = d.get("EF")
        if isinstance(ef_val, PDFDictionary):
            filename = _get_filename(d)
            _extract_ef_dict(doc, ef_val, filename, obj_num, results)

    # Method 3: Find /Type /EmbeddedFile streams
    for (obj_num, _), obj in doc.objects.items():
        if not obj.is_stream:
            continue
        d = obj.value.dictionary
        if d:
            type_val = d.get("Type")
            if isinstance(type_val, PDFName) and type_val.name == "EmbeddedFile":
                # Check if already captured
                if not any(f["object"] == obj_num for f in results["files"]):
                    subtype = d.get("Subtype")
                    mime = subtype.name if isinstance(subtype, PDFName) else "unknown"
                    size = len(obj.value.data) if obj.value.data else 0
                    results["files"].append({
                        "filename": f"embedded_{obj_num}",
                        "object": obj_num,
                        "size": size,
                        "mime_type": mime.replace("#2F", "/"),
                        "has_data": size > 0,
                    })

    results["total"] = len(results["files"])
    return results


def _extract_from_name_tree(doc, tree_dict, results):
    """Extract embedded files from a name tree."""
    names_array = tree_dict.get("Names")
    if isinstance(names_array, PDFArray):
        i = 0
        items = list(names_array)
        while i + 1 < len(items):
            name = items[i]
            spec = items[i + 1]
            filename = str(name) if name else "unknown"

            if isinstance(spec, PDFReference):
                spec_obj = doc.get_object(spec.obj_num, spec.gen_num)
                if spec_obj:
                    spec = spec_obj.value

            if isinstance(spec, PDFDictionary):
                ef_val = spec.get("EF")
                if isinstance(ef_val, PDFDictionary):
                    _extract_ef_dict(doc, ef_val, filename, None, results)

            i += 2

    # Handle Kids arrays (name tree branches)
    kids = tree_dict.get("Kids")
    if isinstance(kids, PDFArray):
        for kid_ref in kids:
            if isinstance(kid_ref, PDFReference):
                kid_obj = doc.get_object(kid_ref.obj_num, kid_ref.gen_num)
                if kid_obj and isinstance(kid_obj.value, PDFDictionary):
                    _extract_from_name_tree(doc, kid_obj.value, results)


def _extract_ef_dict(doc, ef_dict, filename, obj_num, results):
    """Extract file info from an /EF dictionary."""
    for key in ef_dict.keys():
        ref = ef_dict.get(key)
        if isinstance(ref, PDFReference):
            file_obj = doc.get_object(ref.obj_num, ref.gen_num)
            if file_obj and file_obj.is_stream:
                d = file_obj.value.dictionary
                subtype = d.get("Subtype") if d else None
                mime = subtype.name if isinstance(subtype, PDFName) else "unknown"
                size = len(file_obj.value.data) if file_obj.value.data else 0
                results["files"].append({
                    "filename": filename,
                    "object": ref.obj_num,
                    "size": size,
                    "mime_type": mime.replace("#2F", "/"),
                    "has_data": size > 0,
                    "ef_key": key,
                })


def _get_filename(dictionary):
    """Extract filename from a file specification dictionary."""
    for key in ("UF", "F", "DOS", "Mac", "Unix"):
        val = dictionary.get(key)
        if isinstance(val, (PDFString, PDFHexString)):
            return str(val)
    return "unknown"


def save_embedded_files(doc, output_dir):
    """
    Save all embedded files to a directory.

    Args:
        doc: A PDFDocument instance.
        output_dir: Directory to save files to.

    Returns:
        list: Paths of saved files.
    """
    results = extract_embedded_files(doc)
    saved = []

    os.makedirs(output_dir, exist_ok=True)

    for file_info in results["files"]:
        if not file_info["has_data"]:
            continue

        obj = doc.get_object(file_info["object"])
        if obj and obj.is_stream and obj.value.data:
            filename = file_info["filename"]
            # Sanitize filename
            filename = "".join(
                c for c in filename if c.isalnum() or c in ".-_ "
            ).strip()
            if not filename:
                filename = f"file_{file_info['object']}"

            filepath = os.path.join(output_dir, filename)
            # Avoid overwriting
            counter = 1
            base, ext = os.path.splitext(filepath)
            while os.path.exists(filepath):
                filepath = f"{base}_{counter}{ext}"
                counter += 1

            with open(filepath, "wb") as f:
                f.write(obj.value.data)
            saved.append(filepath)

    return saved


def extract_streams_info(doc):
    """
    Get information about all streams in the document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        list: Stream information dictionaries.
    """
    streams = []

    for (obj_num, gen_num), obj in sorted(doc.objects.items()):
        if not obj.is_stream:
            continue

        d = obj.value.dictionary
        info = {
            "object": f"{obj_num} {gen_num}",
            "raw_size": len(obj.value.raw_data) if obj.value.raw_data else 0,
            "decoded_size": len(obj.value.data) if obj.value.data else 0,
            "filter": "",
            "type": "",
            "subtype": "",
            "decoded": obj.value.decoded_data is not None,
        }

        if d:
            filt = d.get("Filter")
            if isinstance(filt, PDFName):
                info["filter"] = filt.name
            elif isinstance(filt, PDFArray):
                info["filter"] = ", ".join(
                    i.name if isinstance(i, PDFName) else str(i)
                    for i in filt
                )

            type_val = d.get("Type")
            if isinstance(type_val, PDFName):
                info["type"] = type_val.name

            sub_val = d.get("Subtype")
            if isinstance(sub_val, PDFName):
                info["subtype"] = sub_val.name

        streams.append(info)

    return streams


def extract_images_info(doc):
    """
    Extract information about images in the document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        list: Image information dictionaries.
    """
    images = []

    for (obj_num, gen_num), obj in sorted(doc.objects.items()):
        if not obj.is_stream:
            continue

        d = obj.value.dictionary
        if d is None:
            continue

        subtype = d.get("Subtype")
        if not (isinstance(subtype, PDFName) and subtype.name == "Image"):
            continue

        width = d.get("Width")
        height = d.get("Height")
        bpc = d.get("BitsPerComponent")
        cs = d.get("ColorSpace")
        filt = d.get("Filter")

        info = {
            "object": f"{obj_num} {gen_num}",
            "width": width.value if isinstance(width, PDFInteger) else str(width) if width else "?",
            "height": height.value if isinstance(height, PDFInteger) else str(height) if height else "?",
            "bits_per_component": bpc.value if isinstance(bpc, PDFInteger) else str(bpc) if bpc else "?",
            "color_space": cs.name if isinstance(cs, PDFName) else str(cs) if cs else "?",
            "filter": filt.name if isinstance(filt, PDFName) else str(filt) if filt else "none",
            "raw_size": len(obj.value.raw_data) if obj.value.raw_data else 0,
        }

        images.append(info)

    return images


def format_embedded_files_report(results):
    """Format embedded files report."""
    lines = []
    lines.append("── Embedded Files ──")
    lines.append(f"  Total: {results['total']}")

    for f in results["files"]:
        lines.append(f"\n  File: {f['filename']}")
        lines.append(f"    Object:    {f['object']}")
        lines.append(f"    Size:      {f['size']} bytes")
        lines.append(f"    MIME type: {f['mime_type']}")

    if not results["files"]:
        lines.append("  No embedded files found.")

    return "\n".join(lines)


def format_streams_report(streams):
    """Format streams information report."""
    lines = []
    lines.append("── Streams ──")
    lines.append(f"  Total: {len(streams)}")
    lines.append("")
    lines.append(f"  {'Object':<12} {'Raw':<10} {'Decoded':<10} "
                 f"{'Filter':<20} {'Type':<15} {'Subtype'}")
    lines.append("  " + "-" * 80)

    for s in streams:
        lines.append(
            f"  {s['object']:<12} "
            f"{s['raw_size']:<10} "
            f"{s['decoded_size']:<10} "
            f"{s['filter']:<20} "
            f"{s['type']:<15} "
            f"{s['subtype']}"
        )

    return "\n".join(lines)


def format_images_report(images):
    """Format images information report."""
    lines = []
    lines.append("── Images ──")
    lines.append(f"  Total: {len(images)}")

    for img in images:
        lines.append(f"\n  Image in object {img['object']}:")
        lines.append(f"    Dimensions:  {img['width']} x {img['height']}")
        lines.append(f"    BPC:         {img['bits_per_component']}")
        lines.append(f"    ColorSpace:  {img['color_space']}")
        lines.append(f"    Filter:      {img['filter']}")
        lines.append(f"    Raw size:    {img['raw_size']} bytes")

    if not images:
        lines.append("  No images found.")

    return "\n".join(lines)
