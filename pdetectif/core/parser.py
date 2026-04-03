"""
Core PDF binary parser.

Parses PDF files at the binary level without external dependencies.
Handles tokenization, object parsing, cross-reference tables, trailers,
incremental updates, and cross-reference streams.
"""

import re

from .objects import (
    PDFBoolean,
    PDFInteger,
    PDFReal,
    PDFString,
    PDFHexString,
    PDFName,
    PDFArray,
    PDFDictionary,
    PDFStream,
    PDFReference,
    PDFNull,
    PDFIndirectObject,
    PDFXRefEntry,
    PDFDocument,
)
from .stream import decode_stream, StreamDecodeError


class PDFParseError(Exception):
    """Raised when PDF parsing encounters an error."""


# Whitespace and delimiter characters per PDF spec
_WHITESPACE = b"\x00\x09\x0a\x0c\x0d\x20"
_DELIMITERS = b"()<>[]{}/%"


def parse_file(file_path):
    """
    Parse a PDF file and return a PDFDocument.

    Args:
        file_path: Path to the PDF file.

    Returns:
        PDFDocument with all parsed structure.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    doc = PDFDocument()
    doc.raw_data = data
    doc.file_size = len(data)
    doc.file_path = file_path

    _parse_header(doc)
    _parse_all_xref_and_trailers(doc)
    _detect_encryption_early(doc)
    _parse_all_objects(doc)
    if not doc.encrypted:
        _decode_object_streams(doc)
    _detect_features(doc)

    return doc


def _parse_header(doc):
    """Parse the PDF header to extract version."""
    data = doc.raw_data
    match = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
    if match:
        doc.version = match.group(1).decode("ascii")
        doc.header = match.group(0).decode("ascii")

    # Count %%EOF markers (multiple = incremental updates)
    eof_positions = [m.start() for m in re.finditer(rb"%%EOF", data)]
    doc.eof_count = len(eof_positions)
    doc.incremental_updates = max(0, doc.eof_count - 1)


def _parse_all_xref_and_trailers(doc):
    """Find and parse all xref tables and trailers (including incremental updates)."""
    data = doc.raw_data

    # Find startxref values
    for m in re.finditer(rb"startxref\s+(\d+)", data):
        offset = int(m.group(1))
        doc.startxref_offsets.append(offset)

    # Parse traditional xref tables
    for m in re.finditer(rb"xref\s*\n", data):
        offset = m.start()
        xref_entries = _parse_xref_table(data, offset)
        if xref_entries:
            doc.xref_tables.append(xref_entries)

    # Parse trailers
    for m in re.finditer(rb"trailer\s*", data):
        pos = m.end()
        try:
            trailer_dict, _ = _parse_object_at(data, pos)
            if isinstance(trailer_dict, PDFDictionary):
                doc.trailers.append(trailer_dict)
        except (PDFParseError, IndexError, ValueError):
            pass

    # Handle cross-reference streams (PDF 1.5+)
    for offset in doc.startxref_offsets:
        if offset < len(data):
            # Check if startxref points to an xref stream instead of table
            if not data[offset:offset + 4].startswith(b"xref"):
                try:
                    obj, _ = _parse_indirect_object_at(data, offset)
                    if obj and obj.is_stream:
                        d = obj.value.dictionary
                        if d and d.get("Type") == PDFName("XRef"):
                            doc.xref_streams.append(obj)
                            # The stream dict also serves as trailer
                            doc.trailers.append(d)
                            # Parse xref stream to get object offsets
                            xref_entries = _parse_xref_stream(obj.value, d)
                            if xref_entries:
                                doc.xref_tables.append(xref_entries)
                except (PDFParseError, IndexError, ValueError):
                    pass


def _parse_xref_stream(stream, dictionary):
    """Parse a cross-reference stream to extract object offsets."""
    data = stream.data
    if data is None:
        return {}

    w_val = dictionary.get("W")
    if not isinstance(w_val, PDFArray) or len(w_val) < 3:
        return {}

    w = []
    for item in w_val:
        if isinstance(item, PDFInteger):
            w.append(item.value)
        else:
            w.append(int(item) if item else 0)

    w1, w2, w3 = w[0], w[1], w[2]
    entry_size = w1 + w2 + w3
    if entry_size == 0:
        return {}

    # Get index array (subsection ranges)
    size_val = dictionary.get("Size")
    size = size_val.value if isinstance(size_val, PDFInteger) else 0

    index_val = dictionary.get("Index")
    if isinstance(index_val, PDFArray):
        indices = []
        for item in index_val:
            if isinstance(item, PDFInteger):
                indices.append(item.value)
            else:
                indices.append(int(item) if item else 0)
    else:
        indices = [0, size]

    entries = {}
    pos = 0

    for i in range(0, len(indices), 2):
        if i + 1 >= len(indices):
            break
        first_obj = indices[i]
        count = indices[i + 1]

        for j in range(count):
            if pos + entry_size > len(data):
                break

            # Read type field
            if w1 > 0:
                type_val = int.from_bytes(data[pos:pos + w1], "big")
            else:
                type_val = 1  # default per spec

            # Read field 2
            if w2 > 0:
                field2 = int.from_bytes(data[pos + w1:pos + w1 + w2], "big")
            else:
                field2 = 0

            # Read field 3
            if w3 > 0:
                field3 = int.from_bytes(
                    data[pos + w1 + w2:pos + w1 + w2 + w3], "big")
            else:
                field3 = 0

            obj_num = first_obj + j

            if type_val == 1:
                # In-use object: field2=offset, field3=gen
                entries[obj_num] = PDFXRefEntry(field2, field3, True)
            # type 0 = free, type 2 = compressed (in object stream)

            pos += entry_size

    return entries


def _parse_xref_table(data, offset):
    """Parse a traditional cross-reference table."""
    entries = {}
    pos = offset

    # Skip "xref" keyword
    match = re.match(rb"xref\s*\n", data[pos:pos + 20])
    if not match:
        return entries
    pos += match.end()

    while pos < len(data):
        # Try to read subsection header: first_obj_num count
        line_match = re.match(rb"(\d+)\s+(\d+)\s*\n", data[pos:pos + 40])
        if not line_match:
            break

        first_obj = int(line_match.group(1))
        count = int(line_match.group(2))
        pos += line_match.end()

        for i in range(count):
            entry_data = data[pos:pos + 20]
            entry_match = re.match(rb"(\d{10})\s+(\d{5})\s+([nf])\s*\r?\n?", entry_data)
            if entry_match:
                entry_offset = int(entry_match.group(1))
                gen_num = int(entry_match.group(2))
                in_use = entry_match.group(3) == b"n"
                entries[first_obj + i] = PDFXRefEntry(entry_offset, gen_num, in_use)
                pos += 20
            else:
                pos += 20

    return entries


def _parse_all_objects(doc):
    """Find and parse all indirect objects in the document."""
    data = doc.raw_data
    skip_decode = doc.encrypted

    # Build obj_num -> offset lookup from xref for fast Length resolution
    obj_offsets = {}
    for xref_table in doc.xref_tables:
        for obj_num, entry in xref_table.items():
            if entry.in_use:
                obj_offsets[obj_num] = entry.offset

    # If we have xref data, parse objects at those offsets first
    if obj_offsets:
        for obj_num, offset in obj_offsets.items():
            if offset >= len(data):
                continue
            # Look up gen from xref
            gen_num = 0
            for xref_table in doc.xref_tables:
                if obj_num in xref_table:
                    gen_num = xref_table[obj_num].gen_num
                    break
            key = (obj_num, gen_num)
            try:
                obj, _ = _parse_indirect_object_at(data, offset,
                                                   skip_decode=skip_decode,
                                                   obj_offsets=obj_offsets)
                if obj:
                    doc.objects[key] = obj
            except (PDFParseError, IndexError, ValueError, RecursionError):
                endobj_pos = data.find(b"endobj", offset, offset + 65536)
                raw = data[offset:endobj_pos + 6] if endobj_pos and endobj_pos > offset else data[offset:offset + 100]
                doc.objects[key] = PDFIndirectObject(
                    obj_num, gen_num, PDFNull(), offset=offset, raw_data=raw
                )

    # Also scan for objects not in xref (handles damaged/incremental PDFs)
    # For encrypted PDFs, skip this scan since false positives in encrypted
    # stream data would cause slowdowns
    if not doc.encrypted:
        for m in re.finditer(rb"(\d+)\s+(\d+)\s+obj\b", data):
            obj_num = int(m.group(1))
            gen_num = int(m.group(2))
            offset = m.start()
            key = (obj_num, gen_num)

            if key in doc.objects:
                continue

            try:
                obj, _ = _parse_indirect_object_at(data, offset,
                                                   skip_decode=skip_decode,
                                                   obj_offsets=obj_offsets)
                if obj:
                    doc.objects[key] = obj
            except (PDFParseError, IndexError, ValueError, RecursionError):
                endobj_pos = data.find(b"endobj", offset)
                raw = data[offset:endobj_pos + 6] if endobj_pos and endobj_pos > offset else data[offset:offset + 100]
                doc.objects[key] = PDFIndirectObject(
                    obj_num, gen_num, PDFNull(), offset=offset, raw_data=raw
                )


def _parse_indirect_object_at(data, offset, skip_decode=False, obj_offsets=None):
    """Parse an indirect object at a specific offset."""
    match = re.match(rb"(\d+)\s+(\d+)\s+obj\b", data[offset:offset + 30])
    if not match:
        raise PDFParseError(f"No indirect object at offset {offset}")

    obj_num = int(match.group(1))
    gen_num = int(match.group(2))
    pos = offset + match.end()

    pos = _skip_whitespace(data, pos)

    value, pos = _parse_object_at(data, pos)

    pos = _skip_whitespace(data, pos)

    # Check for stream
    if isinstance(value, PDFDictionary) and data[pos:pos + 6] == b"stream":
        pos += 6
        # Stream data starts after \r\n or \n
        if pos < len(data) and data[pos:pos + 1] == b"\r":
            pos += 1
        if pos < len(data) and data[pos:pos + 1] == b"\n":
            pos += 1

        # Get stream length
        stream_length = _get_stream_length(value, data, obj_offsets)

        if stream_length is not None and stream_length >= 0:
            stream_data = data[pos:pos + stream_length]
            pos += stream_length
        else:
            # Search for endstream
            end_marker = data.find(b"endstream", pos)
            if end_marker == -1:
                stream_data = b""
            else:
                stream_data = data[pos:end_marker]
                # Strip trailing whitespace from stream data
                stream_data = stream_data.rstrip(b"\r\n")
                pos = end_marker

        stream_obj = PDFStream(value, stream_data)
        if not skip_decode:
            _try_decode_stream(stream_obj)
        value = stream_obj

    # Find endobj
    endobj_pos = data.find(b"endobj", pos)
    raw_end = endobj_pos + 6 if endobj_pos != -1 else pos
    raw_data = data[offset:raw_end]

    obj = PDFIndirectObject(obj_num, gen_num, value, offset=offset, raw_data=raw_data)
    return obj, raw_end


def _get_stream_length(dictionary, full_data, obj_offsets=None):
    """Extract stream length from dictionary, resolving indirect references if needed."""
    length_val = dictionary.get("Length")
    if length_val is None:
        return None
    if isinstance(length_val, PDFInteger):
        return length_val.value
    if isinstance(length_val, (int, float)):
        return int(length_val)
    if isinstance(length_val, PDFReference):
        # Fast path: use xref offset lookup if available
        if obj_offsets and length_val.obj_num in obj_offsets:
            ref_offset = obj_offsets[length_val.obj_num]
            try:
                m = re.match(rb"(\d+)\s+(\d+)\s+obj\b",
                             full_data[ref_offset:ref_offset + 30])
                if m:
                    pos = _skip_whitespace(full_data, ref_offset + m.end())
                    val, _ = _parse_object_at(full_data, pos)
                    if isinstance(val, PDFInteger):
                        return val.value
            except (PDFParseError, IndexError, ValueError):
                pass

        # Slow fallback: regex search over entire data
        match = re.search(
            rb"(?<!\d)" + str(length_val.obj_num).encode()
            + rb"\s+" + str(length_val.gen_num).encode()
            + rb"\s+obj\b",
            full_data,
        )
        if match:
            try:
                pos = _skip_whitespace(full_data, match.end())
                val, _ = _parse_object_at(full_data, pos)
                if isinstance(val, PDFInteger):
                    return val.value
            except (PDFParseError, IndexError, ValueError):
                pass
    return None


def _try_decode_stream(stream_obj):
    """Attempt to decode a stream's data using its filter(s)."""
    d = stream_obj.dictionary
    filter_val = d.get("Filter")
    if filter_val is None:
        stream_obj.decoded_data = stream_obj.raw_data
        return

    # Normalize filter to list of strings
    if isinstance(filter_val, PDFName):
        filters = [filter_val.name]
    elif isinstance(filter_val, PDFArray):
        filters = [item.name if isinstance(item, PDFName) else str(item) for item in filter_val]
    else:
        return

    # Get decode parameters
    params_val = d.get("DecodeParms") or d.get("DP")
    decode_params = None
    if isinstance(params_val, PDFDictionary):
        decode_params = _dict_to_native(params_val)
    elif isinstance(params_val, PDFArray):
        decode_params = [_dict_to_native(p) if isinstance(p, PDFDictionary) else None for p in params_val]

    try:
        stream_obj.decoded_data = decode_stream(stream_obj.raw_data, filters, decode_params)
    except StreamDecodeError:
        pass


def _dict_to_native(pdf_dict):
    """Convert PDFDictionary to native Python dict for decode params."""
    if not isinstance(pdf_dict, PDFDictionary):
        return None
    result = {}
    for key, val in pdf_dict.items():
        if isinstance(val, PDFInteger):
            result[key] = val.value
        elif isinstance(val, PDFReal):
            result[key] = val.value
        elif isinstance(val, PDFBoolean):
            result[key] = val.value
        elif isinstance(val, PDFName):
            result[key] = val.name
        else:
            result[key] = val
    return result


def _decode_object_streams(doc):
    """Parse objects contained within Object Streams (PDF 1.5+)."""
    for key, obj in list(doc.objects.items()):
        if not obj.is_stream:
            continue
        d = obj.dictionary
        if d is None:
            continue
        type_val = d.get("Type")
        if not (isinstance(type_val, PDFName) and type_val.name == "ObjStm"):
            continue

        stream = obj.value
        data = stream.data
        if data is None:
            continue

        n_val = d.get("N")
        first_val = d.get("First")
        if n_val is None or first_val is None:
            continue

        n = n_val.value if isinstance(n_val, PDFInteger) else int(n_val)
        first = first_val.value if isinstance(first_val, PDFInteger) else int(first_val)

        try:
            header_text = data[:first].decode("latin-1", errors="replace")
            tokens = header_text.split()
            for i in range(0, min(len(tokens), n * 2), 2):
                child_obj_num = int(tokens[i])
                child_offset = int(tokens[i + 1])

                abs_offset = first + child_offset
                child_key = (child_obj_num, 0)
                if child_key not in doc.objects:
                    try:
                        child_val, _ = _parse_object_at(data, abs_offset)
                        doc.objects[child_key] = PDFIndirectObject(
                            child_obj_num, 0, child_val, offset=None
                        )
                    except (PDFParseError, IndexError, ValueError):
                        pass
        except (ValueError, IndexError):
            pass


def _detect_encryption_early(doc):
    """Detect encryption from trailers before full object parsing."""
    for trailer in doc.trailers:
        if "Encrypt" in trailer:
            doc.encrypted = True
            break


def _detect_features(doc):
    """Detect document-level features like encryption and linearization."""
    for trailer in doc.trailers:
        if "Encrypt" in trailer:
            doc.encrypted = True
            enc_ref = trailer.get("Encrypt")
            if isinstance(enc_ref, PDFReference):
                enc_obj = doc.get_object(enc_ref.obj_num, enc_ref.gen_num)
                if enc_obj:
                    doc.encryption_dict = enc_obj.dictionary
            elif isinstance(enc_ref, PDFDictionary):
                doc.encryption_dict = enc_ref

    # Check for linearization
    for key in sorted(doc.objects.keys()):
        obj = doc.objects[key]
        d = obj.dictionary
        if d and "Linearized" in d:
            doc.linearized = True
            break


# ---- Tokenizer / Object Parser ----

def _skip_whitespace(data, pos):
    """Skip whitespace and comments."""
    while pos < len(data):
        if data[pos:pos + 1] in (b"\x00", b"\x09", b"\x0a", b"\x0c", b"\x0d", b"\x20"):
            pos += 1
        elif data[pos:pos + 1] == b"%":
            # Skip comment to end of line
            while pos < len(data) and data[pos:pos + 1] not in (b"\n", b"\r"):
                pos += 1
        else:
            break
    return pos


def _parse_object_at(data, pos, depth=0):
    """
    Parse a PDF object at the given position.

    Returns:
        Tuple of (parsed_object, new_position).
    """
    if depth > 100:
        raise PDFParseError("Maximum parsing depth exceeded")

    pos = _skip_whitespace(data, pos)

    if pos >= len(data):
        raise PDFParseError("Unexpected end of data")

    byte = data[pos:pos + 1]

    # Boolean
    if data[pos:pos + 4] == b"true":
        nxt = pos + 4
        if nxt >= len(data) or data[nxt:nxt + 1] in _WHITESPACE + _DELIMITERS:
            return PDFBoolean(True), nxt
    if data[pos:pos + 5] == b"false":
        nxt = pos + 5
        if nxt >= len(data) or data[nxt:nxt + 1] in _WHITESPACE + _DELIMITERS:
            return PDFBoolean(False), nxt

    # Null
    if data[pos:pos + 4] == b"null":
        nxt = pos + 4
        if nxt >= len(data) or data[nxt:nxt + 1] in _WHITESPACE + _DELIMITERS:
            return PDFNull(), nxt

    # Dictionary or hex string
    if byte == b"<":
        if data[pos + 1:pos + 2] == b"<":
            return _parse_dictionary(data, pos, depth)
        else:
            return _parse_hex_string(data, pos)

    # String
    if byte == b"(":
        return _parse_literal_string(data, pos)

    # Name
    if byte == b"/":
        return _parse_name(data, pos)

    # Array
    if byte == b"[":
        return _parse_array(data, pos, depth)

    # Number or indirect reference
    if byte in (b"+", b"-", b".") or (b"0" <= byte <= b"9"):
        return _parse_number_or_ref(data, pos, depth)

    # If we reach here, try to skip unknown token
    end = pos
    while end < len(data) and data[end:end + 1] not in _WHITESPACE + _DELIMITERS:
        end += 1
    token = data[pos:end].decode("latin-1", errors="replace")

    # Check for endobj/endstream markers (we've gone too far)
    if token in ("endobj", "endstream", "stream"):
        raise PDFParseError(f"Unexpected token: {token}")

    return PDFNull(), end


def _parse_literal_string(data, pos):
    """Parse a PDF literal string (parenthesized)."""
    assert data[pos:pos + 1] == b"("
    pos += 1
    result = bytearray()
    nesting = 1

    while pos < len(data) and nesting > 0:
        ch = data[pos]
        if ch == ord(b"\\"):
            pos += 1
            if pos >= len(data):
                break
            esc = data[pos]
            if esc == ord(b"n"):
                result.append(10)
            elif esc == ord(b"r"):
                result.append(13)
            elif esc == ord(b"t"):
                result.append(9)
            elif esc == ord(b"b"):
                result.append(8)
            elif esc == ord(b"f"):
                result.append(12)
            elif esc == ord(b"("):
                result.append(ord(b"("))
            elif esc == ord(b")"):
                result.append(ord(b")"))
            elif esc == ord(b"\\"):
                result.append(ord(b"\\"))
            elif ord(b"0") <= esc <= ord(b"7"):
                # Octal escape
                octal = chr(esc)
                for _ in range(2):
                    if pos + 1 < len(data) and ord(b"0") <= data[pos + 1] <= ord(b"7"):
                        pos += 1
                        octal += chr(data[pos])
                    else:
                        break
                result.append(int(octal, 8) & 0xFF)
            elif esc in (10, 13):
                # Line continuation
                if esc == 13 and pos + 1 < len(data) and data[pos + 1] == 10:
                    pos += 1
            else:
                result.append(esc)
        elif ch == ord(b"("):
            nesting += 1
            result.append(ch)
        elif ch == ord(b")"):
            nesting -= 1
            if nesting > 0:
                result.append(ch)
        else:
            result.append(ch)
        pos += 1

    text = result.decode("latin-1", errors="replace")
    return PDFString(text, raw=bytes(result)), pos


def _parse_hex_string(data, pos):
    """Parse a PDF hexadecimal string."""
    assert data[pos:pos + 1] == b"<"
    pos += 1
    hex_chars = []

    while pos < len(data):
        ch = data[pos]
        if ch == ord(b">"):
            pos += 1
            break
        if chr(ch) in "0123456789abcdefABCDEF":
            hex_chars.append(chr(ch))
        pos += 1

    return PDFHexString("".join(hex_chars)), pos


def _parse_name(data, pos):
    """Parse a PDF name object, handling #XX hex escapes."""
    assert data[pos:pos + 1] == b"/"
    pos += 1
    raw_chars = []
    decoded_chars = []

    while pos < len(data):
        ch = data[pos]
        # Stop at whitespace or delimiter characters (PDF spec Table 2 & 3)
        if ch in _WHITESPACE or ch in _DELIMITERS:
            break

        if ch == ord(b"#") and pos + 2 < len(data):
            hex_val = data[pos + 1:pos + 3]
            try:
                decoded_byte = int(hex_val, 16)
                raw_chars.append(chr(ch))
                raw_chars.append(chr(hex_val[0]))
                raw_chars.append(chr(hex_val[1]))
                decoded_chars.append(chr(decoded_byte))
                pos += 3
                continue
            except (ValueError, IndexError):
                pass

        raw_chars.append(chr(ch))
        decoded_chars.append(chr(ch))
        pos += 1

    raw_name = "".join(raw_chars)
    decoded_name = "".join(decoded_chars)
    return PDFName(decoded_name, raw_name=raw_name), pos


def _is_delimiter_or_whitespace(ch_byte):
    """Check if a byte is a PDF delimiter or whitespace."""
    return ch_byte in _WHITESPACE or ch_byte in _DELIMITERS


def _parse_array(data, pos, depth):
    """Parse a PDF array."""
    assert data[pos:pos + 1] == b"["
    pos += 1
    items = []

    while pos < len(data):
        pos = _skip_whitespace(data, pos)
        if pos >= len(data):
            break
        if data[pos:pos + 1] == b"]":
            pos += 1
            break
        item, pos = _parse_object_at(data, pos, depth + 1)
        items.append(item)

    return PDFArray(items), pos


def _parse_dictionary(data, pos, depth):
    """Parse a PDF dictionary."""
    assert data[pos:pos + 2] == b"<<"
    pos += 2
    start_pos = pos
    entries = {}
    skipped = 0

    while pos < len(data):
        pos = _skip_whitespace(data, pos)
        if pos >= len(data):
            break
        if data[pos:pos + 2] == b">>":
            pos += 2
            break

        # Parse key (must be a name)
        if data[pos:pos + 1] != b"/":
            # Skip invalid data, but bail out if too much junk
            skipped += 1
            if skipped > 1024:
                raise PDFParseError(
                    f"Too many invalid bytes in dictionary at offset {start_pos}")
            pos += 1
            continue

        key, pos = _parse_name(data, pos)
        pos = _skip_whitespace(data, pos)

        if pos >= len(data) or data[pos:pos + 2] == b">>":
            entries[key.name] = PDFNull()
            continue

        value, pos = _parse_object_at(data, pos, depth + 1)
        entries[key.name] = value

    return PDFDictionary(entries), pos


def _parse_number_or_ref(data, pos, depth):
    """Parse a number, which might be part of an indirect reference (N G R)."""
    num_match = re.match(rb"([+-]?\d+\.?\d*|[+-]?\.\d+)", data[pos:pos + 30])
    if not num_match:
        raise PDFParseError(f"Expected number at offset {pos}")

    num_str = num_match.group(1)
    end_pos = pos + len(num_str)

    # Check if it's a real number
    if b"." in num_str:
        return PDFReal(num_str.decode("ascii")), end_pos

    int_val = int(num_str)

    # Check for indirect reference: int int R
    saved_pos = end_pos
    ws_pos = _skip_whitespace(data, end_pos)

    gen_match = re.match(rb"(\d+)", data[ws_pos:ws_pos + 10])
    if gen_match:
        gen_end = ws_pos + len(gen_match.group(1))
        r_pos = _skip_whitespace(data, gen_end)
        if r_pos < len(data) and data[r_pos:r_pos + 1] == b"R":
            nxt = r_pos + 1
            if nxt >= len(data) or data[nxt:nxt + 1] in _WHITESPACE + _DELIMITERS:
                gen_val = int(gen_match.group(1))
                return PDFReference(int_val, gen_val), nxt

    return PDFInteger(int_val), end_pos
