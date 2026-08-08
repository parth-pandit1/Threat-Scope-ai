"""
Indicator of Compromise (IOC) extractor.

Parses text (or binary files via string extraction) to identify
network indicators, file hashes, registry keys, crypto-wallet
addresses, CVE identifiers, and MITRE ATT&CK technique IDs.

All IOCs are deduplicated and private IP ranges are filtered out.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# IOC regex patterns
# ─────────────────────────────────────────────────────────────

PATTERNS: dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "url": re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha512": re.compile(r"\b[a-fA-F0-9]{128}\b"),
    "registry": re.compile(
        r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
        r"\\[^\s\"'<>]+"
    ),
    "file_path": re.compile(
        r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+'
    ),
    "mutex": re.compile(r"(?:Global|Local)\\[A-Za-z0-9_\-]{4,}"),
    "bitcoin": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

# ─────────────────────────────────────────────────────────────
# Private IP detection
# ─────────────────────────────────────────────────────────────

_PRIVATE_IP_PATTERNS: list[re.Pattern] = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
]


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP belongs to a private / reserved range."""
    return any(p.match(ip) for p in _PRIVATE_IP_PATTERNS)


# ─────────────────────────────────────────────────────────────
# False-positive domain blocklist
# ─────────────────────────────────────────────────────────────

_DOMAIN_FALSE_POSITIVES: set[str] = {
    # Common code artefacts
    "system.io", "system.net", "system.text", "system.threading",
    "microsoft.com", "windows.com", "w3.org", "schema.org",
    "example.com", "example.org", "example.net",
    "localhost.localdomain",
    # Compiler / framework noise
    "go.microsoft.com", "aka.ms",
}


def _is_fp_domain(domain: str) -> bool:
    """Return True if the domain is a known false positive."""
    lower = domain.lower()
    return lower in _DOMAIN_FALSE_POSITIVES or lower.startswith("www.w3.org")


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def extract_iocs(text: str) -> dict[str, Any]:
    """
    Extract all IOCs from a text blob.

    Private IPs and known false-positive domains are filtered out.
    All results are deduplicated.

    Args:
        text: Raw text to scan for indicators.

    Returns:
        Dictionary keyed by IOC category, plus ``total_ioc_count``.
    """
    if not text:
        return _empty_result()

    try:
        # ── Network indicators ───────────────
        raw_ipv4 = list(set(PATTERNS["ipv4"].findall(text)))
        ipv4 = [ip for ip in raw_ipv4 if not _is_private_ip(ip)]

        ipv6 = list(set(PATTERNS["ipv6"].findall(text)))

        raw_domains = list(set(PATTERNS["domain"].findall(text)))
        domains = [d for d in raw_domains if not _is_fp_domain(d)]

        urls = list(set(PATTERNS["url"].findall(text)))
        emails = list(set(PATTERNS["email"].findall(text)))

        # ── Hashes ───────────────────────────
        # Extract in descending length order to avoid partial matches
        sha512 = list(set(PATTERNS["sha512"].findall(text)))
        sha256 = list(set(PATTERNS["sha256"].findall(text)))
        sha1 = list(set(PATTERNS["sha1"].findall(text)))
        md5 = list(set(PATTERNS["md5"].findall(text)))

        # Remove hash substrings (a SHA-256 contains valid MD5 substrings)
        all_long_hashes = set(sha512 + sha256 + sha1)
        md5 = [h for h in md5 if not any(h in lh for lh in all_long_hashes)]
        sha1_set = set(sha512 + sha256)
        sha1 = [h for h in sha1 if not any(h in lh for lh in sha1_set)]

        # ── System artefacts ─────────────────
        registry_keys = list(set(PATTERNS["registry"].findall(text)))
        file_paths = list(set(PATTERNS["file_path"].findall(text)))
        mutexes = list(set(PATTERNS["mutex"].findall(text)))

        # ── Crypto wallets ───────────────────
        bitcoin = list(set(PATTERNS["bitcoin"].findall(text)))
        ethereum = list(set(PATTERNS["ethereum"].findall(text)))

        # ── Threat intelligence ──────────────
        cves = list(set(PATTERNS["cve"].findall(text)))
        mitre_techniques = list(set(PATTERNS["mitre_technique"].findall(text)))

        total = (
            len(ipv4) + len(ipv6) + len(domains) + len(urls) + len(emails)
            + len(md5) + len(sha1) + len(sha256) + len(sha512)
            + len(registry_keys) + len(file_paths) + len(mutexes)
            + len(bitcoin) + len(ethereum)
            + len(cves) + len(mitre_techniques)
        )

        return {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "domains": domains,
            "urls": urls,
            "emails": emails,
            "hashes": {
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "sha512": sha512,
            },
            "registry_keys": registry_keys,
            "file_paths": file_paths,
            "mutexes": mutexes,
            "crypto_wallets": {
                "bitcoin": bitcoin,
                "ethereum": ethereum,
            },
            "cves": cves,
            "mitre_techniques": mitre_techniques,
            "total_ioc_count": total,
        }

    except Exception as exc:
        logger.error("IOC extraction failed: %s", str(exc))
        result = _empty_result()
        result["error"] = str(exc)
        return result


def defang_ioc(ioc: str) -> str:
    """
    Convert an IOC to defanged format for safe sharing.

    Examples:
        ``http://evil.com`` → ``hxxp://evil[.]com``
        ``192.168.1.1``     → ``192[.]168[.]1[.]1``
    """
    result = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://")
    if "://" in result:
        proto, rest = result.split("://", 1)
        parts = rest.split("/", 1)
        parts[0] = parts[0].replace(".", "[.]")
        return proto + "://" + "/".join(parts)
    else:
        parts = result.split("/", 1)
        parts[0] = parts[0].replace(".", "[.]")
        return "/".join(parts)


def extract_iocs_from_file(file_path: str) -> dict[str, Any]:
    """
    Extract IOCs from a binary file by first pulling ASCII strings.

    Args:
        file_path: Path to the binary file.

    Returns:
        IOC extraction results (same structure as ``extract_iocs``).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract ASCII strings ≥ 6 chars
        ascii_strings = re.findall(rb"[\x20-\x7e]{6,}", data)
        text = "\n".join(s.decode("ascii", errors="replace") for s in ascii_strings)

        return extract_iocs(text)

    except Exception as exc:
        logger.error("IOC extraction from file failed: %s", str(exc))
        result = _empty_result()
        result["error"] = str(exc)
        return result


def _empty_result() -> dict[str, Any]:
    """Return an empty IOC result skeleton."""
    return {
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "hashes": {"md5": [], "sha1": [], "sha256": [], "sha512": []},
        "registry_keys": [],
        "file_paths": [],
        "mutexes": [],
        "crypto_wallets": {"bitcoin": [], "ethereum": []},
        "cves": [],
        "mitre_techniques": [],
        "total_ioc_count": 0,
    }
