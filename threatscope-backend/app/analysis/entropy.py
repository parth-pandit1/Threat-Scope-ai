"""
Shannon entropy calculator for file analysis.

High-entropy files (> 7.0) are strongly indicative of packing,
compression, or encryption — common malware obfuscation techniques.

Scoring contribution: 0-20 points toward the overall threat score.
"""

import logging
import math
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)


def calculate_file_entropy(file_path: str) -> float:
    """
    Calculate the Shannon entropy of the entire file.

    Returns:
        Float in the range 0.0 – 8.0.
        Higher values indicate more randomness (likely packed / encrypted).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return round(entropy, 4)

    except Exception as exc:
        logger.error("Failed to calculate file entropy for %s: %s", file_path, str(exc))
        return 0.0


def calculate_section_entropy(file_path: str) -> list[dict[str, Any]]:
    """
    Calculate per-section entropy for PE files.

    Uses ``pefile`` to iterate over PE sections. Returns an empty
    list for non-PE files or if pefile is unavailable.

    Returns:
        List of dicts: ``[{"name": ".text", "entropy": 6.2, "size": 4096}, ...]``
    """
    try:
        import pefile
    except ImportError:
        logger.debug("pefile not installed — skipping section entropy")
        return []

    try:
        pe = pefile.PE(file_path)
        sections: list[dict[str, Any]] = []

        for section in pe.sections:
            section_data = section.get_data()
            if section_data and len(section_data) > 0:
                counter = Counter(section_data)
                length = len(section_data)
                entropy = -sum(
                    (c / length) * math.log2(c / length)
                    for c in counter.values()
                )
                entropy = round(entropy, 4)
            else:
                entropy = 0.0

            sections.append({
                "name": section.Name.decode("utf-8", errors="replace").rstrip("\x00"),
                "entropy": entropy,
                "size": section.SizeOfRawData,
            })

        pe.close()
        return sections

    except Exception as exc:
        logger.debug("Section entropy calculation failed: %s", str(exc))
        return []


def entropy_verdict(entropy: float) -> dict[str, Any]:
    """
    Convert a raw entropy value into a threat-score contribution
    and human-readable assessment.

    Thresholds:
        < 6.5  → normal     (0 pts)
        6.5-7.0 → elevated  (5 pts)
        7.0-7.5 → high      (12 pts)
        > 7.5  → very_high  (20 pts)

    Returns:
        Dict with ``entropy_score`` (0-20), ``entropy_label``,
        and ``entropy_note``.
    """
    if entropy > 7.5:
        return {
            "entropy_score": 20,
            "entropy_label": "very_high",
            "entropy_note": (
                f"Entropy {entropy:.2f} — very high; file is almost certainly "
                f"packed, encrypted, or compressed"
            ),
        }
    if entropy > 7.0:
        return {
            "entropy_score": 12,
            "entropy_label": "high",
            "entropy_note": (
                f"Entropy {entropy:.2f} — high; likely compressed "
                f"or obfuscated content"
            ),
        }
    if entropy > 6.5:
        return {
            "entropy_score": 5,
            "entropy_label": "elevated",
            "entropy_note": (
                f"Entropy {entropy:.2f} — slightly elevated; may contain "
                f"compressed resources or packed sections"
            ),
        }
    return {
        "entropy_score": 0,
        "entropy_label": "normal",
        "entropy_note": (
            f"Entropy {entropy:.2f} — within the normal range for "
            f"typical executables and documents"
        ),
    }
