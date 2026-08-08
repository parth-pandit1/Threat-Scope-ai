"""
WHOIS and DNS analysis module for URL / domain scanning.

Runs synchronous WHOIS lookups (python-whois) and DNS resolution
(dnspython) for A, MX, and TXT records. Designed for execution
inside RQ worker tasks.

All external calls are wrapped in try/except so that a single
failing lookup never crashes the entire scan.
"""

import logging
import socket
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import whois

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# WHOIS Lookup
# ─────────────────────────────────────────────────────────────
def run_whois_lookup(domain: str) -> dict[str, Any]:
    """
    Perform a WHOIS lookup for the given domain.

    Args:
        domain: Bare domain name (e.g. ``example.com``).

    Returns:
        Dictionary with registrar info, dates, name servers, and
        computed ``domain_age_days``. On failure the dictionary
        contains ``whois_available: false`` plus the error message.
    """
    try:
        w = whois.whois(domain)

        # python-whois sometimes returns lists for date fields
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Calculate domain age in days
        domain_age_days: int | None = None
        if creation_date and isinstance(creation_date, datetime):
            aware_creation = creation_date.replace(tzinfo=timezone.utc)
            domain_age_days = (datetime.now(timezone.utc) - aware_creation).days

        return {
            "whois_available": True,
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "domain_age_days": domain_age_days,
            "name_servers": (
                [str(ns) for ns in w.name_servers] if w.name_servers else []
            ),
            "registrant_country": str(w.country) if w.country else None,
            "dnssec": (
                str(w.dnssec)
                if hasattr(w, "dnssec") and w.dnssec
                else None
            ),
            "org": str(w.org) if w.org else None,
        }

    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, str(exc))
        return {
            "whois_available": False,
            "whois_error": f"WHOIS lookup failed: {str(exc)}",
        }


# ─────────────────────────────────────────────────────────────
# DNS Resolution
# ─────────────────────────────────────────────────────────────
def run_dns_resolution(domain: str) -> dict[str, Any]:
    """
    Resolve A, MX, and TXT DNS records for a domain.

    Also attempts reverse DNS on the first A record.

    Args:
        domain: Bare domain name.

    Returns:
        Dictionary with ``a_records``, ``mx_records``,
        ``txt_records``, and optional ``reverse_dns``.
    """
    results: dict[str, Any] = {"dns_available": True}

    # ── A records ────────────────────────────
    try:
        a_answers = dns.resolver.resolve(domain, "A")
        results["a_records"] = [str(rdata) for rdata in a_answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
    ):
        results["a_records"] = []
    except Exception as exc:
        results["a_records"] = []
        results["a_records_error"] = str(exc)

    # ── MX records ───────────────────────────
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        results["mx_records"] = [
            {"priority": rdata.preference, "exchange": str(rdata.exchange)}
            for rdata in mx_answers
        ]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
    ):
        results["mx_records"] = []
    except Exception as exc:
        results["mx_records"] = []
        results["mx_records_error"] = str(exc)

    # ── TXT records ──────────────────────────
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT")
        results["txt_records"] = [
            str(rdata).strip('"') for rdata in txt_answers
        ]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
    ):
        results["txt_records"] = []
    except Exception as exc:
        results["txt_records"] = []
        results["txt_records_error"] = str(exc)

    # ── Reverse DNS on first A record ────────
    if results.get("a_records"):
        try:
            ip = results["a_records"][0]
            hostname_info = socket.gethostbyaddr(ip)
            results["reverse_dns"] = hostname_info[0]
        except (socket.herror, socket.gaierror, OSError):
            results["reverse_dns"] = None
    else:
        results["reverse_dns"] = None

    return results


# ─────────────────────────────────────────────────────────────
# Threat Scoring
# ─────────────────────────────────────────────────────────────
def calculate_url_threat_score(
    whois_result: dict[str, Any],
    dns_result: dict[str, Any],
) -> tuple[int, str]:
    """
    Calculate a 0-100 threat score for a URL based on domain age
    and DNS characteristics.

    Phase 1 scoring heuristics:
    - Very new domain (< 30 days): +50
    - New domain (< 90 days): +30
    - Less than a year: +10
    - Unknown WHOIS: +20
    - No A records: +15
    - Unknown domain age: +15

    Returns:
        ``(threat_score, verdict)`` tuple.
    """
    score = 0

    # ── Domain age scoring ───────────────────
    domain_age_days = whois_result.get("domain_age_days")
    if domain_age_days is not None:
        if domain_age_days < 30:
            score += 50  # Very new — high risk
        elif domain_age_days < 90:
            score += 30  # Recently registered
        elif domain_age_days < 365:
            score += 10  # Less than a year
        # Older domains: no additional score
    else:
        score += 15  # Unknown age — slight risk

    # ── WHOIS availability ───────────────────
    if not whois_result.get("whois_available"):
        score += 20

    # ── DNS availability ─────────────────────
    if not dns_result.get("a_records"):
        score += 15

    score = min(100, score)

    # ── Verdict ──────────────────────────────
    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif score >= 15:
        verdict = "low_risk"
    else:
        verdict = "clean"

    return score, verdict
