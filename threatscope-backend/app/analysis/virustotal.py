"""
VirusTotal API integration for file hash lookups.

Uses the VirusTotal v3 REST API via ``httpx`` (synchronous client)
to look up SHA-256 hashes. Designed to run inside RQ worker tasks.

Handles:
- Missing / placeholder API keys gracefully
- HTTP 404 (hash not in VT database)
- HTTP 429 (rate limit exceeded) — stores flag instead of crashing
- Network timeouts and connection errors
"""

import logging
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


def lookup_file_hash(file_hash: str) -> dict[str, Any]:
    """
    Query VirusTotal for a file hash (MD5 / SHA-1 / SHA-256).

    Args:
        file_hash: Hash string to look up.

    Returns:
        Dictionary with VT results, or error/unavailability info.
    """
    if settings.VIRUSTOTAL_API_KEY in ("your-vt-key-here", ""):
        logger.warning("VirusTotal API key not configured — skipping lookup")
        return {
            "vt_available": False,
            "vt_error": "API key not configured",
        }

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    url = f"{VT_API_BASE}/files/{file_hash}"

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "vt_available": True,
                "vt_found": True,
                "vt_detection_stats": stats,
                "vt_total_engines": sum(stats.values()) if stats else 0,
                "vt_malicious_count": stats.get("malicious", 0),
                "vt_suspicious_count": stats.get("suspicious", 0),
                "vt_undetected_count": stats.get("undetected", 0),
                "vt_harmless_count": stats.get("harmless", 0),
                "vt_reputation": attributes.get("reputation", 0),
                "vt_popular_threat_name": (
                    attributes.get("popular_threat_classification", {})
                    .get("suggested_threat_label")
                ),
                "vt_file_type": attributes.get("type_description", "unknown"),
                "vt_first_submission": attributes.get("first_submission_date"),
                "vt_last_analysis_date": attributes.get("last_analysis_date"),
            }

        if response.status_code == 404:
            return {
                "vt_available": True,
                "vt_found": False,
                "vt_message": "File hash not found in VirusTotal database",
            }

        if response.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded")
            return {
                "vt_available": False,
                "vt_rate_limited": True,
                "vt_error": "API rate limit exceeded — try again later",
            }

        logger.error(
            "VirusTotal API error: HTTP %d — %s",
            response.status_code,
            response.text[:200],
        )
        return {
            "vt_available": False,
            "vt_error": f"API returned HTTP {response.status_code}",
        }

    except httpx.TimeoutException:
        logger.error("VirusTotal API request timed out for hash %s", file_hash)
        return {"vt_available": False, "vt_error": "Request timed out"}

    except httpx.HTTPError as exc:
        logger.error("VirusTotal HTTP error: %s", str(exc))
        return {"vt_available": False, "vt_error": f"HTTP error: {str(exc)}"}


def calculate_threat_score_from_vt(vt_result: dict[str, Any]) -> tuple[int, str]:
    """
    Derive a 0-100 threat score and a verdict label from VT results.

    Scoring heuristic:
    - ``detection_ratio = (malicious + suspicious) / total_engines``
    - Amplified by 1.5× so even moderate detections surface clearly.

    Returns:
        ``(threat_score, verdict)`` where verdict is one of
        ``clean | low_risk | suspicious | malicious``.
    """
    if not vt_result.get("vt_available") or not vt_result.get("vt_found"):
        return 0, "clean"

    total = vt_result.get("vt_total_engines", 0)
    malicious = vt_result.get("vt_malicious_count", 0)
    suspicious = vt_result.get("vt_suspicious_count", 0)

    if total == 0:
        return 0, "clean"

    detection_ratio = (malicious + suspicious) / total
    threat_score = min(100, int(detection_ratio * 100 * 1.5))

    if threat_score >= 70:
        verdict = "malicious"
    elif threat_score >= 40:
        verdict = "suspicious"
    elif threat_score >= 15:
        verdict = "low_risk"
    else:
        verdict = "clean"

    return threat_score, verdict
