"""
QR code detection and analysis for PDF documents.

Detects images that may contain QR codes based on their
properties (dimensions, color space, bit depth). Optionally
decodes QR content if pyzbar and Pillow are available.

QR code phishing ("quishing") in PDFs is a growing attack
vector where attackers embed QR codes pointing to malicious
URLs, bypassing traditional text-based URL scanners.
"""

import io
import re

from ..core.objects import (
    PDFDictionary,
    PDFName,
    PDFArray,
    PDFReference,
    PDFInteger,
)

# Try importing optional QR decode libraries
_HAS_DECODER = False
try:
    from PIL import Image as PILImage
    from pyzbar.pyzbar import decode as pyzbar_decode
    _HAS_DECODER = True
except ImportError:
    pass


# QR code characteristics for detection heuristics
_QR_MIN_DIM = 20
_QR_MAX_DIM = 2000
_QR_MAX_ASPECT_RATIO = 1.3  # QR codes are square


def detect_qr_codes(doc):
    """
    Detect potential QR code images in a PDF document.

    Detection works in two modes:
    1. Heuristic detection (always available): identifies images
       with QR-like properties (square, small, low-color)
    2. Full decode (requires pyzbar + Pillow): decodes actual
       QR content and extracts URLs

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: QR code detection results.
    """
    results = {
        "potential_qr_images": [],
        "decoded_qr": [],
        "urls_from_qr": [],
        "total_candidates": 0,
        "total_decoded": 0,
        "decoder_available": _HAS_DECODER,
    }

    for (obj_num, gen_num), obj in doc.objects.items():
        if not obj.is_stream:
            continue

        d = obj.value.dictionary
        if d is None:
            continue

        subtype = d.get("Subtype")
        if not (isinstance(subtype, PDFName) and subtype.name == "Image"):
            continue

        # Get image properties
        width = _get_int(d.get("Width"))
        height = _get_int(d.get("Height"))
        bpc = _get_int(d.get("BitsPerComponent"))
        cs = d.get("ColorSpace")

        if width is None or height is None:
            continue
        if width < _QR_MIN_DIM or height < _QR_MIN_DIM:
            continue
        if width > _QR_MAX_DIM or height > _QR_MAX_DIM:
            continue

        # Check aspect ratio (QR codes are square)
        aspect = max(width, height) / max(min(width, height), 1)
        if aspect > _QR_MAX_ASPECT_RATIO:
            continue

        # Score how likely this is a QR code
        score = 0
        reasons = []

        # Square images are more likely QR codes
        if aspect <= 1.05:
            score += 3
            reasons.append("Square aspect ratio")
        elif aspect <= 1.15:
            score += 1
            reasons.append("Near-square aspect ratio")

        # Low color depth is typical for QR
        cs_name = _get_colorspace_name(cs)
        if bpc == 1:
            score += 3
            reasons.append("1-bit depth (binary image)")
        elif bpc == 8 and cs_name in ("DeviceGray", "CalGray", "ICCBased"):
            score += 1
            reasons.append("Grayscale image")

        if cs_name in ("DeviceGray", "CalGray"):
            score += 1
            reasons.append(f"Grayscale colorspace ({cs_name})")

        # Small to medium dimensions typical for QR
        if 50 <= width <= 500 and 50 <= height <= 500:
            score += 1
            reasons.append(f"Typical QR dimensions ({width}x{height})")

        # Need minimum score to be a candidate
        if score < 2:
            continue

        candidate = {
            "object": obj_num,
            "width": width,
            "height": height,
            "bpc": bpc,
            "colorspace": cs_name,
            "score": score,
            "reasons": reasons,
            "decoded": False,
            "content": None,
        }

        # Try to decode if libraries available
        if _HAS_DECODER:
            decoded = _try_decode_qr(obj.value.data, width, height, bpc, cs_name)
            if decoded:
                candidate["decoded"] = True
                candidate["content"] = decoded
                results["decoded_qr"].append({
                    "object": obj_num,
                    "content": decoded,
                })
                results["total_decoded"] += 1

                # Extract URLs from decoded content
                urls = _extract_urls_from_text(decoded)
                for url in urls:
                    results["urls_from_qr"].append({
                        "url": url,
                        "source_object": obj_num,
                    })

        results["potential_qr_images"].append(candidate)

    results["total_candidates"] = len(results["potential_qr_images"])
    return results


def _get_int(val):
    """Extract integer from PDFInteger or int."""
    if isinstance(val, PDFInteger):
        return val.value
    if isinstance(val, int):
        return val
    return None


def _get_colorspace_name(cs):
    """Get a simple colorspace name string."""
    if isinstance(cs, PDFName):
        return cs.name
    if isinstance(cs, PDFArray) and len(cs) > 0:
        first = cs[0]
        if isinstance(first, PDFName):
            return first.name
    return "Unknown"


def _try_decode_qr(data, width, height, bpc, cs_name):
    """Attempt to decode QR code from raw image data using pyzbar."""
    if not _HAS_DECODER or not data:
        return None

    try:
        # Try interpreting as raw bitmap first
        if bpc == 1 and cs_name in ("DeviceGray", "CalGray"):
            # 1-bit grayscale: convert to 8-bit
            pixels = bytearray()
            for byte in data:
                for bit in range(7, -1, -1):
                    pixels.append(255 if (byte >> bit) & 1 else 0)
            pixels = pixels[:width * height]
            if len(pixels) == width * height:
                img = PILImage.frombytes("L", (width, height), bytes(pixels))
                decoded = pyzbar_decode(img)
                if decoded:
                    return decoded[0].data.decode("utf-8", errors="replace")

        # Try as standard image format (JPEG, PNG inside stream)
        try:
            img = PILImage.open(io.BytesIO(data))
            decoded = pyzbar_decode(img)
            if decoded:
                return decoded[0].data.decode("utf-8", errors="replace")
        except Exception:
            pass

        # Try raw 8-bit grayscale
        if bpc == 8 and len(data) >= width * height:
            raw = data[:width * height]
            img = PILImage.frombytes("L", (width, height), raw)
            decoded = pyzbar_decode(img)
            if decoded:
                return decoded[0].data.decode("utf-8", errors="replace")

    except Exception:
        pass

    return None


def _extract_urls_from_text(text):
    """Extract URLs from decoded QR text."""
    pattern = re.compile(
        r"(https?://[^\s<>\"')\]}>]+|ftp://[^\s<>\"')\]}>]+)",
        re.IGNORECASE,
    )
    return [m.group(0).rstrip(".,;:!?") for m in pattern.finditer(text)]


def format_qr_report(results):
    """Format QR code detection results."""
    lines = []
    lines.append("── QR Code Analysis ──")
    lines.append(f"  Decoder available: {'Yes' if results['decoder_available'] else 'No (install Pillow + pyzbar for full decode)'}")
    lines.append(f"  Candidates found:  {results['total_candidates']}")
    lines.append(f"  Decoded:           {results['total_decoded']}")

    if results["potential_qr_images"]:
        lines.append("")
        for img in results["potential_qr_images"]:
            status = "DECODED" if img["decoded"] else f"score {img['score']}"
            lines.append(
                f"  Object {img['object']}: "
                f"{img['width']}x{img['height']} "
                f"{img['colorspace']} {img['bpc']}bpc "
                f"[{status}]"
            )
            for reason in img["reasons"]:
                lines.append(f"    - {reason}")
            if img["content"]:
                content = img["content"][:200]
                lines.append(f"    Content: {content}")

    if results["urls_from_qr"]:
        lines.append("")
        lines.append("  URLs extracted from QR codes:")
        for u in results["urls_from_qr"]:
            lines.append(f"    Object {u['source_object']}: {u['url']}")

    if not results["potential_qr_images"]:
        lines.append("  No potential QR code images detected.")

    return "\n".join(lines)
