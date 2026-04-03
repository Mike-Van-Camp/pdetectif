"""
Entropy analysis for PDF streams and data.

Calculates Shannon entropy to detect encrypted, compressed, or
obfuscated content. High entropy in unexpected places can indicate
shellcode, encrypted payloads, or steganographic content.
"""

import math
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte sequence.

    Args:
        data: bytes or bytearray.

    Returns:
        float: Entropy value between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)
    entropy = 0.0

    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def classify_entropy(entropy_value):
    """
    Classify an entropy value.

    Returns:
        str: Classification label.
    """
    if entropy_value < 1.0:
        return "very_low"
    elif entropy_value < 3.0:
        return "low"
    elif entropy_value < 5.0:
        return "moderate"
    elif entropy_value < 7.0:
        return "high"
    elif entropy_value < 7.5:
        return "very_high"
    else:
        return "suspicious"


def analyze_document_entropy(doc):
    """
    Analyze entropy of all streams in a PDF document.

    Args:
        doc: A PDFDocument instance.

    Returns:
        dict: Entropy analysis results.
    """
    results = {
        "file_entropy": 0.0,
        "file_classification": "",
        "stream_analysis": [],
        "summary": {
            "total_streams": 0,
            "compressed_streams": 0,
            "high_entropy_streams": 0,
            "suspicious_streams": 0,
            "average_raw_entropy": 0.0,
            "average_decoded_entropy": 0.0,
        },
    }

    # Overall file entropy
    results["file_entropy"] = calculate_entropy(doc.raw_data)
    results["file_classification"] = classify_entropy(results["file_entropy"])

    raw_entropies = []
    decoded_entropies = []

    for (obj_num, gen_num), obj in sorted(doc.objects.items()):
        if not obj.is_stream:
            continue

        stream = obj.value
        results["summary"]["total_streams"] += 1

        entry = {
            "object": f"{obj_num} {gen_num}",
            "raw_size": len(stream.raw_data) if stream.raw_data else 0,
            "decoded_size": len(stream.data) if stream.data else 0,
            "raw_entropy": 0.0,
            "decoded_entropy": 0.0,
            "raw_classification": "",
            "decoded_classification": "",
            "filter": "",
            "suspicious": False,
        }

        # Get filter info
        d = stream.dictionary
        if d:
            filt = d.get("Filter")
            if filt:
                entry["filter"] = str(filt)

        # Raw entropy
        if stream.raw_data:
            entry["raw_entropy"] = calculate_entropy(stream.raw_data)
            entry["raw_classification"] = classify_entropy(entry["raw_entropy"])
            raw_entropies.append(entry["raw_entropy"])

            if entry["raw_entropy"] > 7.0:
                results["summary"]["compressed_streams"] += 1

        # Decoded entropy
        if stream.decoded_data is not None and stream.decoded_data != stream.raw_data:
            entry["decoded_entropy"] = calculate_entropy(stream.decoded_data)
            entry["decoded_classification"] = classify_entropy(entry["decoded_entropy"])
            decoded_entropies.append(entry["decoded_entropy"])

            # Suspicious: decoded data still has very high entropy
            # (may contain shellcode or encrypted payload)
            if entry["decoded_entropy"] > 7.5:
                entry["suspicious"] = True
                results["summary"]["suspicious_streams"] += 1

        if entry["raw_entropy"] > 7.0:
            results["summary"]["high_entropy_streams"] += 1

        results["stream_analysis"].append(entry)

    if raw_entropies:
        results["summary"]["average_raw_entropy"] = sum(raw_entropies) / len(raw_entropies)
    if decoded_entropies:
        results["summary"]["average_decoded_entropy"] = sum(decoded_entropies) / len(decoded_entropies)

    return results


def format_entropy_report(results):
    """Format entropy analysis results as a human-readable report."""
    lines = []
    summary = results["summary"]

    lines.append("── Entropy Analysis ──")
    lines.append(f"  File entropy:        {results['file_entropy']:.4f} "
                 f"({results['file_classification']})")
    lines.append(f"  Total streams:       {summary['total_streams']}")
    lines.append(f"  High entropy:        {summary['high_entropy_streams']}")
    lines.append(f"  Suspicious streams:  {summary['suspicious_streams']}")
    lines.append(f"  Avg raw entropy:     {summary['average_raw_entropy']:.4f}")
    lines.append(f"  Avg decoded entropy: {summary['average_decoded_entropy']:.4f}")

    if results["stream_analysis"]:
        lines.append("")
        lines.append("  Streams:")
        lines.append(f"  {'Object':<12} {'Raw H':<10} {'Dec H':<10} "
                     f"{'Raw Size':<12} {'Dec Size':<12} {'Filter':<20} {'Flag'}")
        lines.append("  " + "-" * 85)

        for entry in results["stream_analysis"]:
            flag = "⚠ SUSPICIOUS" if entry["suspicious"] else ""
            lines.append(
                f"  {entry['object']:<12} "
                f"{entry['raw_entropy']:<10.4f} "
                f"{entry['decoded_entropy']:<10.4f} "
                f"{entry['raw_size']:<12} "
                f"{entry['decoded_size']:<12} "
                f"{entry['filter']:<20} "
                f"{flag}"
            )

    return "\n".join(lines)
