"""
Binary string extractor and classifier.

Extracts printable ASCII and UTF-16LE strings from binary files,
then classifies them against pattern groups: network indicators,
execution commands, persistence mechanisms, evasion techniques,
crypto artefacts, and credential references.

Scoring contribution: 0-15 points toward the overall threat score.
"""

import base64
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Suspicious pattern groups
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_PATTERNS: dict[str, list[str]] = {
    "network": [
        r"https?://[^\s]{10,}",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"[a-z0-9\-]+\.(ru|cn|tk|ml|ga|cf|pw|top|xyz|buzz|icu|club)\b",
    ],
    "execution": [
        r"cmd\.exe",
        r"powershell",
        r"wscript",
        r"cscript",
        r"regsvr32",
        r"mshta",
        r"rundll32",
        r"certutil",
        r"/c\s+",
        r"-enc\s+",
        r"-encoded",
    ],
    "persistence": [
        r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"HKEY_LOCAL_MACHINE",
        r"HKEY_CURRENT_USER",
        r"schtasks",
        r"at\.exe",
        r"sc\.exe",
        r"startup",
        r"autorun",
    ],
    "evasion": [
        r"IsDebuggerPresent",
        r"CheckRemoteDebuggerPresent",
        r"NtQueryInformationProcess",
        r"GetTickCount",
        r"SANDBOXIE",
        r"VBOX",
        r"VMWARE",
        r"sleep\(\d{4,}\)",
    ],
    "crypto": [
        r"[A-Za-z0-9+/]{40,}={0,2}",
        r"[0-9a-fA-F]{32,}",
        r"AES",
        r"RSA",
        r"XOR",
        r"RC4",
    ],
    "credentials": [
        r"password",
        r"passwd",
        r"credential",
        r"username",
        r"api[_\-]?key",
        r"secret",
        r"token",
        r"auth",
    ],
}

# Compile patterns once
_COMPILED_PATTERNS: dict[str, list[re.Pattern]] = {
    group: [re.compile(p, re.IGNORECASE) for p in patterns]
    for group, patterns in SUSPICIOUS_PATTERNS.items()
}


# ─────────────────────────────────────────────────────────────
# String extraction helpers
# ─────────────────────────────────────────────────────────────

def _extract_ascii_strings(data: bytes, min_length: int) -> list[str]:
    """Extract printable ASCII strings from raw bytes."""
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [s.decode("ascii") for s in re.findall(pattern, data)]


def _extract_unicode_strings(data: bytes, min_length: int) -> list[str]:
    """Extract UTF-16LE (Windows Unicode) strings from raw bytes."""
    pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
    matches = re.findall(pattern, data)
    return [m.decode("utf-16-le", errors="replace") for m in matches]


def _classify_strings(
    strings: list[str],
) -> dict[str, list[str]]:
    """Classify strings against each suspicious pattern group."""
    results: dict[str, list[str]] = {group: [] for group in _COMPILED_PATTERNS}

    for s in strings:
        for group, patterns in _COMPILED_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(s):
                    if s not in results[group]:
                        results[group].append(s)
                    break  # One match per group per string is enough

    return results


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def decode_base64_strings(strings: list[str]) -> list[str]:
    """
    Attempt to Base64-decode candidate strings.

    Returns only those that decode to valid UTF-8 text (≥ 6 chars).
    """
    decoded: list[str] = []
    b64_pattern = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

    for s in strings:
        if not b64_pattern.match(s):
            continue
        try:
            raw = base64.b64decode(s, validate=True)
            text = raw.decode("utf-8", errors="strict")
            # Only keep if it looks like readable text
            if len(text) >= 6 and text.isprintable():
                decoded.append(text)
        except Exception:
            continue

    return decoded


def extract_strings(file_path: str, min_length: int = 6) -> dict[str, Any]:
    """
    Extract and classify strings from a binary file.

    Args:
        file_path: Path to the file on disk.
        min_length: Minimum string length to extract (default 6).

    Returns:
        Dictionary with:
        - ``all_strings``:         Full list of extracted strings.
        - ``total_count``:         Total strings found.
        - ``suspicious_strings``:  Dict of category → matched strings.
        - ``suspicious_count``:    Total suspicious strings across all categories.
        - ``string_score``:        Threat score contribution (0-15).
        - ``has_base64_payload``:  Whether long Base64 strings were found.
        - ``decoded_base64``:      Successfully decoded Base64 payloads.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as exc:
        logger.error("Failed to read file for string extraction: %s", str(exc))
        return {
            "all_strings": [],
            "total_count": 0,
            "suspicious_strings": {},
            "suspicious_count": 0,
            "string_score": 0,
            "has_base64_payload": False,
            "decoded_base64": [],
            "error": str(exc),
        }

    # Extract ASCII + Unicode strings
    ascii_strings = _extract_ascii_strings(data, min_length)
    unicode_strings = _extract_unicode_strings(data, min_length)

    # Deduplicate while preserving order
    seen: set[str] = set()
    all_strings: list[str] = []
    for s in ascii_strings + unicode_strings:
        if s not in seen:
            seen.add(s)
            all_strings.append(s)

    # Classify suspicious strings
    suspicious = _classify_strings(all_strings)
    suspicious_count = sum(len(v) for v in suspicious.values())

    # Threat score: 2 pts per suspicious string, capped at 15
    string_score = min(15, suspicious_count * 2)

    # Base64 analysis
    crypto_strings = suspicious.get("crypto", [])
    b64_candidates = [
        s for s in crypto_strings
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", s)
    ]
    has_base64 = len(b64_candidates) > 0
    decoded_b64 = decode_base64_strings(b64_candidates) if has_base64 else []

    return {
        "all_strings": all_strings,
        "total_count": len(all_strings),
        "suspicious_strings": suspicious,
        "suspicious_count": suspicious_count,
        "string_score": string_score,
        "has_base64_payload": has_base64,
        "decoded_base64": decoded_b64,
    }
