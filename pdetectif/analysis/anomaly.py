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
        "encryption_analysis": {},
        "incremental_update_analysis": {},
        "circular_references": [],
        "action_chains": [],
        "total_severity_score": 0,
    }

    _check_header_anomalies(doc, results)
    _check_polyglot(doc, results)
    _check_xref_anomalies(doc, results)
    _check_object_anomalies(doc, results)
    _check_trailer_anomalies(doc, results)
    _check_stream_anomalies(doc, results)
    _check_circular_references(doc, results)
    _check_encryption_strength(doc, results)
    _check_incremental_updates(doc, results)
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

        # Check for deeply nested actions and analyze action types
        action_info = {"depth": 0, "types": []}
        _measure_action_chain(d, doc, action_info)
        if action_info["depth"] > 5:
            _add_anomaly(results, "Deep action nesting",
                         f"Object {obj_num} has action nesting depth "
                         f"{action_info['depth']}",
                         "high")
        if action_info["types"]:
            chain_entry = {
                "object": obj_num,
                "depth": action_info["depth"],
                "action_types": action_info["types"],
            }
            results["action_chains"].append(chain_entry)
            # Flag dangerous action type combinations
            dangerous_types = {"Launch", "JavaScript", "SubmitForm", "ImportData"}
            found_dangerous = set(action_info["types"]) & dangerous_types
            if found_dangerous:
                _add_anomaly(
                    results,
                    "Dangerous action chain",
                    f"Object {obj_num} action chain contains: "
                    f"{', '.join(sorted(found_dangerous))}",
                    "high",
                )

    results["structure_info"]["object_types"] = type_counts


def _measure_action_chain(dictionary, doc, info, depth=0, visited=None):
    """Measure action chain depth and collect action types."""
    if depth > 50 or not isinstance(dictionary, PDFDictionary):
        return
    if visited is None:
        visited = set()

    info["depth"] = max(info["depth"], depth)

    # Collect action type
    s_val = dictionary.get("S")
    if isinstance(s_val, PDFName):
        info["types"].append(s_val.name)

    # Follow /Next chain
    next_action = dictionary.get("Next")
    if isinstance(next_action, PDFReference):
        ref_key = (next_action.obj_num, next_action.gen_num)
        if ref_key not in visited:
            visited.add(ref_key)
            resolved = doc.get_object(next_action.obj_num, next_action.gen_num)
            if resolved and resolved.dictionary:
                _measure_action_chain(resolved.dictionary, doc, info, depth + 1, visited)
    elif isinstance(next_action, PDFDictionary):
        _measure_action_chain(next_action, doc, info, depth + 1, visited)
    elif isinstance(next_action, PDFArray):
        for item in next_action:
            if isinstance(item, PDFDictionary):
                _measure_action_chain(item, doc, info, depth + 1, visited)


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

        # Check for decompression bomb (decoded >> raw)
        if stream.raw_data and stream.decoded_data is not None:
            raw_len = len(stream.raw_data)
            dec_len = len(stream.decoded_data)
            if raw_len > 0 and dec_len > 100 * raw_len:
                _add_anomaly(
                    results, "Potential decompression bomb",
                    f"Object {obj_num}: decoded size ({dec_len}) is "
                    f"{dec_len // raw_len}x the raw size ({raw_len})",
                    "critical",
                )


def _check_circular_references(doc, results):
    """Detect circular references in the object graph."""
    for (obj_num, gen_num), obj in doc.objects.items():
        if obj.dictionary is None:
            continue
        path = []
        if _has_cycle(doc, obj.value, set(), path, depth=0):
            cycle_str = " -> ".join(str(p) for p in path[-5:])
            results["circular_references"].append({
                "start_object": obj_num,
                "cycle": cycle_str,
            })
            _add_anomaly(
                results, "Circular reference detected",
                f"Object {obj_num} is part of a reference cycle: {cycle_str}",
                "medium",
            )
            # Only report first few to avoid flooding
            if len(results["circular_references"]) >= 10:
                return


def _has_cycle(doc, value, visiting, path, depth):
    """Check if following references from value leads to a cycle."""
    if depth > 30:
        return False
    if isinstance(value, PDFDictionary):
        for key in value.keys():
            child = value.get(key)
            if isinstance(child, PDFReference):
                ref_key = (child.obj_num, child.gen_num)
                if ref_key in visiting:
                    path.append(ref_key)
                    return True
                visiting.add(ref_key)
                path.append(ref_key)
                resolved = doc.get_object(child.obj_num, child.gen_num)
                if resolved and resolved.dictionary:
                    if _has_cycle(doc, resolved.value, visiting, path, depth + 1):
                        return True
                path.pop()
                visiting.discard(ref_key)
    elif isinstance(value, PDFArray):
        for item in value:
            if isinstance(item, PDFReference):
                ref_key = (item.obj_num, item.gen_num)
                if ref_key in visiting:
                    path.append(ref_key)
                    return True
    elif isinstance(value, PDFStream):
        return _has_cycle(doc, value.dictionary, visiting, path, depth)
    return False


def _check_encryption_strength(doc, results):
    """Analyze encryption strength when encryption is present."""
    if not doc.encrypted or not doc.encryption_dict:
        return

    d = doc.encryption_dict
    analysis = {}

    v_val = d.get("V")
    r_val = d.get("R")
    length_val = d.get("Length")
    cf_val = d.get("CF")

    v = v_val.value if isinstance(v_val, PDFInteger) else v_val
    r = r_val.value if isinstance(r_val, PDFInteger) else r_val
    key_length = length_val.value if isinstance(length_val, PDFInteger) else None

    analysis["version"] = v
    analysis["revision"] = r
    analysis["key_length"] = key_length

    # Determine encryption algorithm and strength
    if v == 1 or (v == 2 and (key_length is None or key_length == 40)):
        analysis["algorithm"] = "RC4"
        analysis["strength"] = "40-bit (weak)"
        analysis["secure"] = False
        _add_anomaly(results, "Weak encryption",
                     "Document uses 40-bit RC4 encryption (easily broken)",
                     "medium")
    elif v == 2:
        analysis["algorithm"] = "RC4"
        analysis["strength"] = f"{key_length or 128}-bit"
        analysis["secure"] = (key_length or 128) >= 128
    elif v == 3:
        analysis["algorithm"] = "RC4 (unpublished)"
        analysis["strength"] = f"{key_length or 128}-bit"
        analysis["secure"] = False
        _add_anomaly(results, "Non-standard encryption",
                     "Document uses unpublished encryption algorithm (V=3)",
                     "medium")
    elif v == 4:
        analysis["algorithm"] = "AES-128 or RC4-128"
        analysis["strength"] = "128-bit"
        analysis["secure"] = True
        # Check crypt filters for specifics
        if isinstance(cf_val, PDFDictionary):
            for name in cf_val.keys():
                cf_entry = cf_val.get(name)
                if isinstance(cf_entry, PDFDictionary):
                    cfm = cf_entry.get("CFM")
                    if isinstance(cfm, PDFName):
                        if cfm.name == "AESV2":
                            analysis["algorithm"] = "AES-128"
                        elif cfm.name == "V2":
                            analysis["algorithm"] = "RC4-128"
    elif v == 5:
        analysis["algorithm"] = "AES-256"
        analysis["strength"] = "256-bit"
        analysis["secure"] = True
    else:
        analysis["algorithm"] = "Unknown"
        analysis["strength"] = "Unknown"
        analysis["secure"] = False

    # Check permissions
    p_val = d.get("P")
    if isinstance(p_val, PDFInteger):
        perms = p_val.value
        analysis["permissions"] = {
            "print": bool(perms & 4),
            "modify": bool(perms & 8),
            "copy": bool(perms & 16),
            "annotate": bool(perms & 32),
            "fill_forms": bool(perms & 256),
            "extract_accessibility": bool(perms & 512),
            "assemble": bool(perms & 1024),
            "print_high_quality": bool(perms & 2048),
        }

    results["encryption_analysis"] = analysis


def _check_incremental_updates(doc, results):
    """Analyze incremental updates for signs of manipulation."""
    data = doc.raw_data

    eof_positions = [m.start() for m in re.finditer(rb"%%EOF", data)]
    if len(eof_positions) <= 1:
        return

    analysis = {
        "eof_count": len(eof_positions),
        "updates": [],
    }

    # Analyze sections between %%EOF markers
    for i in range(len(eof_positions) - 1):
        section_start = eof_positions[i] + 5  # after "%%EOF"
        section_end = eof_positions[i + 1]
        section = data[section_start:section_end]

        # Count objects in this section
        obj_pattern = rb"\b(\d+)\s+(\d+)\s+obj\b"
        objects_in_section = re.findall(obj_pattern, section)

        update_info = {
            "section": i + 1,
            "offset_range": f"{section_start}-{section_end}",
            "size": section_end - section_start,
            "objects_modified": len(objects_in_section),
            "object_numbers": [int(m[0]) for m in objects_in_section[:20]],
        }

        # Check for xref in this section
        has_xref = b"xref" in section or b"/Type /XRef" in section
        update_info["has_xref"] = has_xref

        analysis["updates"].append(update_info)

        if len(objects_in_section) > 0:
            _add_anomaly(
                results,
                "Incremental update modifies objects",
                f"Update section {i + 1}: modifies {len(objects_in_section)} "
                f"object(s) (objects: {update_info['object_numbers'][:5]})",
                "info",
            )

    results["incremental_update_analysis"] = analysis


def _compute_hashes(doc, results):
    """Compute cryptographic hashes of the file for forensic purposes.
    
    Uses single-pass processing to feed all three hashers simultaneously.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    data = doc.raw_data
    chunk_size = 65536
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    results["hashes"] = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
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
            lines.append(f"  ! {p}")

    # Action chains
    if results.get("action_chains"):
        lines.append("")
        lines.append("── Action Chains ──")
        for chain in results["action_chains"]:
            types_str = " -> ".join(chain["action_types"])
            lines.append(
                f"  Object {chain['object']}: "
                f"depth {chain['depth']}, types: {types_str}"
            )

    # Circular references
    if results.get("circular_references"):
        lines.append("")
        lines.append("── Circular References ──")
        for cr in results["circular_references"]:
            lines.append(f"  Object {cr['start_object']}: {cr['cycle']}")

    # Encryption analysis
    enc = results.get("encryption_analysis", {})
    if enc:
        lines.append("")
        lines.append("── Encryption Analysis ──")
        lines.append(f"  Algorithm:   {enc.get('algorithm', 'N/A')}")
        lines.append(f"  Strength:    {enc.get('strength', 'N/A')}")
        lines.append(f"  Key length:  {enc.get('key_length', 'N/A')}")
        lines.append(f"  Secure:      {'Yes' if enc.get('secure') else 'No'}")
        perms = enc.get("permissions", {})
        if perms:
            allowed = [k for k, v in perms.items() if v]
            denied = [k for k, v in perms.items() if not v]
            if allowed:
                lines.append(f"  Allowed:     {', '.join(allowed)}")
            if denied:
                lines.append(f"  Denied:      {', '.join(denied)}")

    # Incremental update analysis
    inc = results.get("incremental_update_analysis", {})
    if inc:
        lines.append("")
        lines.append("── Incremental Updates ──")
        lines.append(f"  EOF markers: {inc.get('eof_count', 0)}")
        for upd in inc.get("updates", []):
            lines.append(
                f"  Update {upd['section']}: "
                f"{upd['size']} bytes, "
                f"{upd['objects_modified']} object(s) modified"
            )
            if upd["object_numbers"]:
                lines.append(
                    f"    Objects: {upd['object_numbers'][:10]}"
                )

    lines.append("")
    lines.append(f"  Total severity score: {results['total_severity_score']}")

    return "\n".join(lines)
