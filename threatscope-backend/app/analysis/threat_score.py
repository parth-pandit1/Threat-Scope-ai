"""
ThreatScope AI — Proprietary Threat Scoring Engine.

Aggregates outputs from every analysis module into a single
0-100 threat score with a human-readable verdict, colour label,
per-signal breakdown, and a ranked list of reasons.

Scoring budget (max 100, capped):
┌────────────────────────────┬──────┬──────────────────────┐
│ Signal                     │ Max  │ Source Module         │
├────────────────────────────┼──────┼──────────────────────┤
│ YARA rule matches          │  25  │ yara_engine           │
│ File entropy               │  20  │ entropy               │
│ Suspicious strings         │  15  │ string_extractor      │
│ Domain age / WHOIS         │  15  │ whois_dns             │
│ PE suspicious imports      │  10  │ pe_parser             │
│ VirusTotal detections      │  10  │ virustotal            │
│ SSL certificate issues     │  10  │ ssl_inspector         │
└────────────────────────────┴──────┴──────────────────────┘
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Verdict thresholds and colours
# ─────────────────────────────────────────────────────────────

_VERDICTS = [
    # (max_score, verdict, label, hex_colour)
    (19, "clean", "CLEAN", "#10b981"),
    (39, "low_risk", "LOW RISK", "#3b82f6"),
    (69, "suspicious", "SUSPICIOUS", "#f59e0b"),
    (100, "malicious", "MALICIOUS", "#ef4444"),
]


def _resolve_verdict(score: int) -> tuple[str, str, str]:
    """Map a 0-100 score to ``(verdict, label, colour)``."""
    for threshold, verdict, label, colour in _VERDICTS:
        if score <= threshold:
            return verdict, label, colour
    return "malicious", "MALICIOUS", "#ef4444"


# ─────────────────────────────────────────────────────────────
# Signal extractors — one per analysis module
# ─────────────────────────────────────────────────────────────

def _score_yara(results: dict) -> dict[str, Any]:
    yara = results.get("yara", {})
    raw = yara.get("yara_score", 0)
    score = min(25, raw)
    count = yara.get("match_count", 0)
    families = yara.get("malware_families", [])
    if count:
        detail = f"{count} YARA rule(s) matched"
        if families:
            detail += f": {', '.join(families[:3])}"
    else:
        detail = "No YARA rules matched"
    return {"score": score, "max": 25, "detail": detail}


def _score_entropy(results: dict) -> dict[str, Any]:
    ent = results.get("entropy", {})
    raw = ent.get("entropy_score", 0)
    score = min(20, raw)
    value = ent.get("value", 0)
    label = ent.get("entropy_label", "normal")
    return {
        "score": score,
        "max": 20,
        "detail": f"Entropy {value:.2f} — {label}",
    }


def _score_strings(results: dict) -> dict[str, Any]:
    strings = results.get("strings", {})
    raw = strings.get("string_score", 0)
    score = min(15, raw)
    count = strings.get("suspicious_count", 0)
    return {
        "score": score,
        "max": 15,
        "detail": f"{count} suspicious string(s) found" if count else "No suspicious strings",
    }


def _score_domain(results: dict) -> dict[str, Any]:
    """Score based on WHOIS domain age (for URL scans)."""
    whois = results.get("whois", {})
    age = whois.get("domain_age_days")
    if age is None:
        if not whois.get("whois_available", True):
            return {"score": 10, "max": 15, "detail": "WHOIS data unavailable"}
        return {"score": 5, "max": 15, "detail": "Domain age unknown"}
    if age < 30:
        return {"score": 15, "max": 15, "detail": f"Domain is {age} day(s) old — very new"}
    if age < 90:
        return {"score": 10, "max": 15, "detail": f"Domain is {age} day(s) old — recently registered"}
    if age < 365:
        return {"score": 5, "max": 15, "detail": f"Domain is {age} day(s) old — less than 1 year"}
    return {"score": 0, "max": 15, "detail": f"Domain is {age} day(s) old — established"}


def _score_pe(results: dict) -> dict[str, Any]:
    pe = results.get("pe_analysis", {})
    if not pe.get("is_pe", False):
        return {"score": 0, "max": 10, "detail": "Not a PE file"}
    suspicious = pe.get("suspicious_imports", [])
    raw = min(10, len(suspicious) * 2)
    if suspicious:
        detail = f"{len(suspicious)} suspicious import(s): {', '.join(suspicious[:5])}"
    else:
        detail = "No suspicious imports detected"
    return {"score": raw, "max": 10, "detail": detail}


def _score_virustotal(results: dict) -> dict[str, Any]:
    vt = results.get("virustotal", {})
    scan_type = results.get("scan_type", "file")
    is_ip = (scan_type == "ip")

    if not vt.get("vt_available", False):
        return {"score": 0, "max": 30 if is_ip else 10, "detail": "VirusTotal not available"}
    if not is_ip and not vt.get("vt_found", False):
        return {"score": 0, "max": 10, "detail": "Not found in VirusTotal"}

    malicious = vt.get("vt_malicious_count", 0)
    suspicious_vt = vt.get("vt_suspicious_count", 0)
    total = vt.get("vt_total_engines", 1)
    detections = malicious + suspicious_vt
    ratio = detections / max(total, 1)

    if is_ip:
        score = min(30, int(ratio * 30 * 1.5))
    else:
        score = min(10, int(ratio * 15))

    return {
        "score": score,
        "max": 30 if is_ip else 10,
        "detail": f"{detections}/{total} engines detected",
    }


def _score_ssl(results: dict) -> dict[str, Any]:
    ssl_data = results.get("ssl", {})
    raw = ssl_data.get("ssl_score", 0)
    score = min(10, raw)
    notes = ssl_data.get("ssl_notes", [])
    detail = "; ".join(notes) if notes else "SSL not inspected"
    return {"score": score, "max": 10, "detail": detail}


def _score_ip_whois(results: dict) -> dict[str, Any]:
    whois = results.get("whois", {})
    score = 0
    detail = "WHOIS data available"
    if not whois.get("whois_available", True):
        score = 20
        detail = "WHOIS data unavailable"
    return {"score": score, "max": 20, "detail": detail}


def _score_ip_abuse(results: dict) -> dict[str, Any]:
    abuse = results.get("abuseipdb", {})
    score = 0
    detail = "No AbuseIPDB reports"
    if abuse.get("abuseipdb_available", False):
        score_val = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        score = min(50, int(score_val * 0.5))
        if reports > 0:
            detail = f"Abuse confidence {score_val}% ({reports} report(s))"
        else:
            detail = f"Abuse confidence {score_val}%"
    return {"score": score, "max": 50, "detail": detail}


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def calculate_threat_score(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregate all analysis module outputs into a final threat
    assessment.

    Args:
        analysis_results: Dictionary containing outputs from each
            analysis module, keyed by module name.

    Returns:
        Dictionary with ``score``, ``verdict``, ``verdict_label``,
        ``verdict_color``, ``breakdown``, ``reasons``, ``top_threat``,
        and ``scan_type``.
    """
    scan_type = analysis_results.get("scan_type", "file")

    # ── Compute per-signal scores ────────────
    breakdown: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []

    if scan_type == "file":
        breakdown["yara"] = _score_yara(analysis_results)
        breakdown["entropy"] = _score_entropy(analysis_results)
        breakdown["strings"] = _score_strings(analysis_results)
        breakdown["pe_imports"] = _score_pe(analysis_results)
        breakdown["virustotal"] = _score_virustotal(analysis_results)
    elif scan_type == "url":
        breakdown["domain"] = _score_domain(analysis_results)
        breakdown["ssl"] = _score_ssl(analysis_results)
        breakdown["virustotal"] = _score_virustotal(analysis_results)
    elif scan_type == "ip":
        breakdown["whois"] = _score_ip_whois(analysis_results)
        breakdown["abuseipdb"] = _score_ip_abuse(analysis_results)
        breakdown["virustotal"] = _score_virustotal(analysis_results)
    else:
        # Generic — score everything available
        breakdown["yara"] = _score_yara(analysis_results)
        breakdown["entropy"] = _score_entropy(analysis_results)
        breakdown["strings"] = _score_strings(analysis_results)
        breakdown["pe_imports"] = _score_pe(analysis_results)
        breakdown["domain"] = _score_domain(analysis_results)
        breakdown["virustotal"] = _score_virustotal(analysis_results)
        breakdown["ssl"] = _score_ssl(analysis_results)

    # ── Aggregate ────────────────────────────
    total_score = sum(b["score"] for b in breakdown.values())
    total_score = min(100, total_score)

    verdict, verdict_label, verdict_color = _resolve_verdict(total_score)

    # ── Build reasons list (only for signals that scored > 0) ──
    for signal_name, signal_data in breakdown.items():
        if signal_data["score"] > 0:
            reasons.append(f"[{signal_name}] {signal_data['detail']}")

    # ── Identify top threat ──────────────────
    top_threat: str | None = None
    yara_data = analysis_results.get("yara", {})
    families = yara_data.get("malware_families", [])
    if families:
        top_threat = families[0]
    elif yara_data.get("matches"):
        top_threat = yara_data["matches"][0].get("rule")

    # If no YARA hit, use VT threat name
    if not top_threat:
        vt_data = analysis_results.get("virustotal", {})
        top_threat = vt_data.get("vt_popular_threat_name")

    if not reasons:
        reasons.append("No significant threat indicators detected")

    logger.info(
        "Threat score calculated: %d/100 → %s (scan_type=%s)",
        total_score, verdict_label, scan_type,
    )

    return {
        "score": total_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "verdict_color": verdict_color,
        "breakdown": breakdown,
        "reasons": reasons,
        "top_threat": top_threat,
        "scan_type": scan_type,
    }
