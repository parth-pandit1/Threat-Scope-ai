"""
IP Reputation and Threat Intelligence analysis module.

Queries local DNS, python-whois, and external threat intelligence APIs:
- VirusTotal (IP report)
- AbuseIPDB (Abuse confidence score)
- Shodan (Open ports & OS detection)
"""

import socket
import logging
import whois
import httpx
from typing import Any
from app.core.config import settings

logger = logging.getLogger(__name__)

def run_ip_whois(ip: str) -> dict[str, Any]:
    """Perform WHOIS lookup on an IP address."""
    try:
        w = whois.whois(ip)
        # Handle lists or dictionaries returned by python-whois
        def _get_first(val):
            if isinstance(val, list):
                return val[0]
            return val

        return {
            "whois_available": True,
            "asn": _get_first(w.get("asn") or w.get("origin")),
            "netname": _get_first(w.get("netname") or w.get("network_name")),
            "country": _get_first(w.get("country")),
            "org": _get_first(w.get("org") or w.get("descr") or w.get("organization")),
            "registrar": _get_first(w.get("registrar")),
        }
    except Exception as exc:
        logger.warning("WHOIS lookup failed for IP %s: %s", ip, str(exc))
        return {
            "whois_available": False,
            "whois_error": str(exc),
        }

def run_ip_reverse_dns(ip: str) -> str | None:
    """Perform reverse DNS PTR lookup on an IP address."""
    try:
        hostname_info = socket.gethostbyaddr(ip)
        return hostname_info[0]
    except (socket.herror, socket.gaierror, OSError):
        return None

def lookup_ip_virustotal(ip: str) -> dict[str, Any]:
    """Lookup IP details on VirusTotal v3."""
    if settings.VIRUSTOTAL_API_KEY in ("your-vt-key-here", ""):
        return {"vt_available": False}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attribs = data.get("attributes", {})
            stats = attribs.get("last_analysis_stats", {})
            return {
                "vt_available": True,
                "vt_reputation": attribs.get("reputation", 0),
                "vt_malicious_count": stats.get("malicious", 0),
                "vt_suspicious_count": stats.get("suspicious", 0),
                "vt_total_engines": sum(stats.values()) if stats else 0,
            }
        return {"vt_available": False, "vt_error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("VirusTotal IP lookup failed: %s", str(exc))
        return {"vt_available": False, "vt_error": str(exc)}

def lookup_ip_abuseipdb(ip: str) -> dict[str, Any]:
    """Lookup IP details on AbuseIPDB v2."""
    if not settings.ABUSEIPDB_API_KEY:
        return {"abuseipdb_available": False}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseipdb_available": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
            }
        return {"abuseipdb_available": False, "abuseipdb_error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("AbuseIPDB IP lookup failed: %s", str(exc))
        return {"abuseipdb_available": False, "abuseipdb_error": str(exc)}

def lookup_ip_shodan(ip: str) -> dict[str, Any]:
    """Lookup IP details on Shodan."""
    if not settings.SHODAN_API_KEY:
        return {"shodan_available": False}

    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": settings.SHODAN_API_KEY}

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, params=params)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "shodan_available": True,
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "os": data.get("os"),
                "isp": data.get("isp"),
            }
        return {"shodan_available": False, "shodan_error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("Shodan IP lookup failed: %s", str(exc))
        return {"shodan_available": False, "shodan_error": str(exc)}
