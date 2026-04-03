"""
PDF stream filter decompression.

Supports decoding PDF streams using only Python standard library.
Handles: FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode,
RunLengthDecode, and filter chaining.
"""

import zlib
import struct


class StreamDecodeError(Exception):
    """Raised when stream decoding fails."""


# Maximum allowed decoded size (100 MB)
_MAX_DECODED_SIZE = 100 * 1024 * 1024

# Maximum ratio of decoded/raw size before flagging as bomb
_MAX_DECODE_RATIO = 100


def decode_stream(raw_data, filters, decode_params=None):
    """
    Decode a PDF stream by applying one or more filters.

    Args:
        raw_data: The raw stream bytes.
        filters: A single filter name (str) or list of filter names.
        decode_params: Optional decode parameters dict or list of dicts.

    Returns:
        bytes: The decoded data.

    Raises:
        StreamDecodeError: If decoding fails or decompression bomb detected.
    """
    if raw_data is None:
        return b""

    if isinstance(filters, str):
        filters = [filters]

    if decode_params is None:
        decode_params = [None] * len(filters)
    elif isinstance(decode_params, dict):
        decode_params = [decode_params]

    # Pad decode_params if shorter than filters
    while len(decode_params) < len(filters):
        decode_params.append(None)

    raw_size = len(raw_data)
    data = raw_data
    for filt, params in zip(filters, decode_params):
        decoder = FILTER_DECODERS.get(filt)
        if decoder is None:
            raise StreamDecodeError(f"Unsupported filter: {filt}")
        try:
            data = decoder(data, params)
        except StreamDecodeError:
            raise
        except Exception as e:
            raise StreamDecodeError(f"Error decoding {filt}: {e}") from e

        # Check for decompression bomb
        if len(data) > _MAX_DECODED_SIZE:
            raise StreamDecodeError(
                f"Decoded size ({len(data)}) exceeds maximum "
                f"allowed size ({_MAX_DECODED_SIZE}). "
                f"Possible decompression bomb."
            )
        if raw_size > 0 and len(data) > raw_size * _MAX_DECODE_RATIO:
            raise StreamDecodeError(
                f"Decoded size ({len(data)}) is {len(data) // raw_size}x "
                f"the raw size ({raw_size}). "
                f"Possible decompression bomb."
            )

    return data


def _decode_flate(data, params=None):
    """Decompress FlateDecode (zlib/deflate) data."""
    try:
        decoded = zlib.decompress(data)
    except zlib.error:
        # Try with raw deflate (no header)
        try:
            decoded = zlib.decompress(data, -15)
        except zlib.error as e:
            raise StreamDecodeError(f"FlateDecode failed: {e}") from e

    if params:
        decoded = _apply_predictor(decoded, params)

    return decoded


def _apply_predictor(data, params):
    """Apply PNG predictor to decoded data (used with FlateDecode/LZWDecode)."""
    if not isinstance(params, dict):
        return data

    predictor = params.get("Predictor", 1)
    if isinstance(predictor, int):
        pred_val = predictor
    else:
        pred_val = int(predictor) if predictor else 1

    if pred_val == 1:
        return data

    columns = params.get("Columns", 1)
    if not isinstance(columns, int):
        columns = int(columns) if columns else 1

    colors = params.get("Colors", 1)
    if not isinstance(colors, int):
        colors = int(colors) if colors else 1

    bits_per_component = params.get("BitsPerComponent", 8)
    if not isinstance(bits_per_component, int):
        bits_per_component = int(bits_per_component) if bits_per_component else 8

    if pred_val == 2:
        # TIFF predictor
        return _tiff_predictor(data, columns, colors, bits_per_component)

    if 10 <= pred_val <= 15:
        # PNG predictors
        return _png_predictor(data, columns, colors, bits_per_component)

    return data


def _tiff_predictor(data, columns, colors, bpc):
    """Apply TIFF predictor 2."""
    bytes_per_pixel = (colors * bpc + 7) // 8
    row_bytes = (columns * colors * bpc + 7) // 8
    output = bytearray()

    offset = 0
    while offset < len(data):
        row = bytearray(data[offset:offset + row_bytes])
        for i in range(bytes_per_pixel, len(row)):
            row[i] = (row[i] + row[i - bytes_per_pixel]) & 0xFF
        output.extend(row)
        offset += row_bytes

    return bytes(output)


def _png_predictor(data, columns, colors, bpc):
    """Apply PNG predictor (types 0-4)."""
    bytes_per_pixel = max(1, (colors * bpc + 7) // 8)
    row_bytes = (columns * colors * bpc + 7) // 8
    stride = row_bytes + 1  # +1 for filter type byte

    output = bytearray()
    prev_row = bytearray(row_bytes)

    offset = 0
    while offset < len(data):
        if offset >= len(data):
            break

        filter_type = data[offset]
        offset += 1

        row_data = data[offset:offset + row_bytes]
        if len(row_data) < row_bytes:
            row_data = row_data + b"\x00" * (row_bytes - len(row_data))
        offset += row_bytes

        current_row = bytearray(row_data)

        if filter_type == 0:
            # None
            pass
        elif filter_type == 1:
            # Sub
            for i in range(bytes_per_pixel, row_bytes):
                current_row[i] = (current_row[i] + current_row[i - bytes_per_pixel]) & 0xFF
        elif filter_type == 2:
            # Up
            for i in range(row_bytes):
                current_row[i] = (current_row[i] + prev_row[i]) & 0xFF
        elif filter_type == 3:
            # Average
            for i in range(row_bytes):
                left = current_row[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                up = prev_row[i]
                current_row[i] = (current_row[i] + (left + up) // 2) & 0xFF
        elif filter_type == 4:
            # Paeth
            for i in range(row_bytes):
                left = current_row[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                up = prev_row[i]
                up_left = prev_row[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                current_row[i] = (current_row[i] + _paeth(left, up, up_left)) & 0xFF

        output.extend(current_row)
        prev_row = current_row

    return bytes(output)


def _paeth(a, b, c):
    """Paeth predictor function."""
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    return c


def _decode_ascii_hex(data, params=None):
    """Decode ASCIIHexDecode filter."""
    text = data.decode("ascii", errors="ignore")
    # Remove whitespace
    text = "".join(text.split())
    # Remove EOD marker
    if text.endswith(">"):
        text = text[:-1]
    # Pad if odd length
    if len(text) % 2 != 0:
        text += "0"
    try:
        return bytes.fromhex(text)
    except ValueError as e:
        raise StreamDecodeError(f"ASCIIHexDecode failed: {e}") from e


def _decode_ascii85(data, params=None):
    """Decode ASCII85Decode (Ascii85/btoa) filter."""
    text = data.decode("ascii", errors="ignore")
    # Remove whitespace
    text = "".join(text.split())
    # Remove <~ and ~> markers if present
    if text.startswith("<~"):
        text = text[2:]
    if text.endswith("~>"):
        text = text[:-2]

    result = bytearray()
    i = 0
    while i < len(text):
        if text[i] == "z":
            result.extend(b"\x00\x00\x00\x00")
            i += 1
            continue

        group = text[i:i + 5]
        n = len(group)
        if n < 5:
            group += "u" * (5 - n)

        value = 0
        for ch in group:
            value = value * 85 + (ord(ch) - 33)

        try:
            decoded = struct.pack(">I", value)
        except struct.error:
            break

        if n < 5:
            result.extend(decoded[:n - 1])
        else:
            result.extend(decoded)

        i += n

    return bytes(result)


def _decode_lzw(data, params=None):
    """Decode LZWDecode filter."""
    if not data:
        return b""

    early_change = 1
    if params and isinstance(params, dict):
        early_change = params.get("EarlyChange", 1)
        if not isinstance(early_change, int):
            early_change = int(early_change) if early_change else 1

    result = bytearray()
    reader = _BitReader(data)

    # Initialize table
    table = {i: bytes([i]) for i in range(256)}
    table[256] = None  # Clear table
    table[257] = None  # EOD

    next_code = 258
    code_size = 9
    prev_entry = None

    while True:
        code = reader.read_bits(code_size)
        if code is None or code == 257:
            break

        if code == 256:
            # Reset table
            table = {i: bytes([i]) for i in range(256)}
            table[256] = None
            table[257] = None
            next_code = 258
            code_size = 9
            prev_entry = None
            continue

        if code in table:
            entry = table[code]
        elif code == next_code and prev_entry is not None:
            entry = prev_entry + prev_entry[0:1]
        else:
            break

        result.extend(entry)

        if prev_entry is not None:
            table[next_code] = prev_entry + entry[0:1]
            next_code += 1

            limit = (1 << code_size) - early_change
            if next_code >= limit and code_size < 12:
                code_size += 1

        prev_entry = entry

    decoded = bytes(result)
    if params:
        decoded = _apply_predictor(decoded, params)
    return decoded


class _BitReader:
    """Read bits MSB-first from a byte sequence."""

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bit_pos = 0

    def read_bits(self, n):
        result = 0
        for _ in range(n):
            if self.pos >= len(self.data):
                return None
            byte = self.data[self.pos]
            bit = (byte >> (7 - self.bit_pos)) & 1
            result = (result << 1) | bit
            self.bit_pos += 1
            if self.bit_pos >= 8:
                self.bit_pos = 0
                self.pos += 1
        return result


def _decode_run_length(data, params=None):
    """Decode RunLengthDecode filter."""
    result = bytearray()
    i = 0
    while i < len(data):
        length_byte = data[i]
        i += 1

        if length_byte == 128:
            break  # EOD
        elif length_byte < 128:
            # Copy next length_byte + 1 bytes
            count = length_byte + 1
            result.extend(data[i:i + count])
            i += count
        else:
            # Repeat next byte 257 - length_byte times
            count = 257 - length_byte
            if i < len(data):
                result.extend(bytes([data[i]]) * count)
                i += 1

    return bytes(result)


# Map filter names to decoder functions
FILTER_DECODERS = {
    "FlateDecode": _decode_flate,
    "Fl": _decode_flate,
    "ASCIIHexDecode": _decode_ascii_hex,
    "AHx": _decode_ascii_hex,
    "ASCII85Decode": _decode_ascii85,
    "A85": _decode_ascii85,
    "LZWDecode": _decode_lzw,
    "LZW": _decode_lzw,
    "RunLengthDecode": _decode_run_length,
    "RL": _decode_run_length,
}
