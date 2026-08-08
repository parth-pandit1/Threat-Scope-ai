"""
RQ tasks for asynchronous file and URL scanning — Phase 2.

Each task orchestrates the full analysis pipeline:

**File scan pipeline:**
  1. Download from MinIO → temp file
  2. Compute MD5 + SHA-256 hashes
  3. Entropy analysis (Shannon entropy, per-section)
  4. PE header parsing (imports, sections, timestamps)
  5. String extraction + classification
  6. YARA rule scanning
  7. IOC extraction from binary strings
  8. VirusTotal hash lookup
  9. Threat score aggregation
  10. AI explanation (Ollama LLM)
  11. Persist results → completed

**URL scan pipeline:**
  1. WHOIS + DNS resolution
  2. SSL certificate inspection
  3. Screenshot capture (Playwright)
  4. Page intelligence extraction (DOM inspection)
  5. IOC extraction from page content
  6. Threat score aggregation
  7. AI explanation (Ollama LLM)
  8. Persist results → completed

Every analysis module call is individually wrapped in try/except
so a single module failure never crashes the entire scan.
"""

import asyncio
import hashlib
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from app.core.database import async_session_factory
from app.core.storage import download_file
from app.models.scan import Scan, ScanStatus, Verdict
import ssdeep

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Async helper for running coroutines from sync RQ context
# ─────────────────────────────────────────────────────────────

_worker_loop = None

def _run_async(coro):  # type: ignore[type-arg]
    """Execute an async coroutine from a synchronous RQ task."""
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_worker_loop)
    return _worker_loop.run_until_complete(coro)


# ─────────────────────────────────────────────────────────────
# Database update helper
# ─────────────────────────────────────────────────────────────

async def _update_scan(
    scan_id: str,
    *,
    status: ScanStatus,
    result_json: dict[str, Any] | None = None,
    threat_score: int | None = None,
    verdict: Verdict | None = None,
    file_hash_md5: str | None = None,
    file_hash_sha256: str | None = None,
) -> None:
    """Atomically update a Scan row in PostgreSQL."""
    async with async_session_factory() as session:
        result = await session.execute(
            select(Scan).where(Scan.id == uuid.UUID(scan_id))
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            logger.error("Scan %s not found — cannot update", scan_id)
            return

        scan.status = status
        if result_json is not None:
            scan.result_json = result_json
        if threat_score is not None:
            scan.threat_score = threat_score
        if verdict is not None:
            scan.verdict = verdict
        if file_hash_md5 is not None:
            scan.file_hash_md5 = file_hash_md5
        if file_hash_sha256 is not None:
            scan.file_hash_sha256 = file_hash_sha256
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            scan.completed_at = datetime.now(timezone.utc)

        await session.commit()
        logger.info("Scan %s → %s", scan_id, status.value)


# ─────────────────────────────────────────────────────────────
# Safe module runner — isolates each analysis module
# ─────────────────────────────────────────────────────────────

def _safe_run(module_name: str, func, *args, **kwargs) -> Any:
    """
    Call *func* and return its result.  On any exception, log a
    warning and return a fallback dict so the scan continues.
    """
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        logger.warning("Module [%s] failed: %s", module_name, str(exc))
        return {"module_available": False, "error": str(exc)}


def _safe_run_async(module_name: str, coro) -> Any:
    """Async variant of ``_safe_run``."""
    try:
        return _run_async(coro)
    except Exception as exc:
        logger.warning("Async module [%s] failed: %s", module_name, str(exc))
        return {"module_available": False, "error": str(exc)}


# ═════════════════════════════════════════════════════════════
# FILE SCAN TASK
# ═════════════════════════════════════════════════════════════

def scan_file_task(scan_id: str, object_name: str) -> dict[str, Any]:
    """
    Full file analysis pipeline.

    Args:
        scan_id:     UUID of the Scan row (= job_id).
        object_name: MinIO object key for the uploaded file.

    Returns:
        Summary dict with ``status``, ``threat_score``, ``verdict``.
    """
    logger.info("▶ File scan started — scan_id=%s", scan_id)
    tmp_path: str | None = None

    try:
        # ── 1. Mark as running ───────────────
        _run_async(_update_scan(scan_id, status=ScanStatus.RUNNING))

        # ── 2. Download from MinIO → temp file ──
        try:
            file_data = download_file(object_name)
        except Exception as exc:
            logger.error("MinIO download failed: %s", str(exc))
            _run_async(_update_scan(
                scan_id, status=ScanStatus.FAILED,
                result_json={"error": f"Failed to retrieve file: {str(exc)}"},
            ))
            return {"status": "failed", "error": str(exc)}

        ext = object_name.rsplit(".", 1)[-1] if "." in object_name else "bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name

        # ── 3. Compute hashes ────────────────
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        ssdeep_hash = ssdeep.hash(file_data) if ssdeep else None
        file_size = len(file_data)
        logger.info("Hashes — MD5=%s  SHA256=%s  ssdeep=%s  size=%d", md5_hash, sha256_hash, ssdeep_hash, file_size)

        # ── 4. Entropy analysis ──────────────
        from app.analysis.entropy import (
            calculate_file_entropy,
            calculate_section_entropy,
            entropy_verdict,
        )

        file_entropy = _safe_run("entropy", calculate_file_entropy, tmp_path)
        section_entropy = _safe_run("entropy.sections", calculate_section_entropy, tmp_path)
        entropy_result = _safe_run("entropy.verdict", entropy_verdict, file_entropy)
        if isinstance(entropy_result, dict):
            entropy_result["value"] = file_entropy
            entropy_result["section_entropy"] = section_entropy if isinstance(section_entropy, list) else []

        # ── 5. PE header parsing ─────────────
        from app.analysis.pe_parser import is_pe_file, parse_pe_header

        pe_is_pe = _safe_run("pe.detect", is_pe_file, tmp_path)
        pe_result: dict[str, Any]
        if pe_is_pe:
            pe_result = _safe_run("pe.parse", parse_pe_header, tmp_path)
        else:
            pe_result = {"is_pe": False, "pe_score": 0}

        # ── 6. String extraction ─────────────
        from app.analysis.string_extractor import extract_strings

        strings_result = _safe_run("strings", extract_strings, tmp_path)

        # ── 7. YARA scanning ────────────────
        from app.analysis.yara_manager import scan_with_yara

        yara_result = _safe_run("yara", scan_with_yara, tmp_path)

        # ── 8. IOC extraction ───────────────
        from app.analysis.ioc_extractor import extract_iocs_from_file

        ioc_result = _safe_run("ioc", extract_iocs_from_file, tmp_path)

        # ── 9. VirusTotal hash lookup ────────
        from app.analysis.virustotal import lookup_file_hash

        vt_result = _safe_run("virustotal", lookup_file_hash, sha256_hash)

        # ── 10. Threat score aggregation ─────
        from app.analysis.threat_score import calculate_threat_score

        scoring_input: dict[str, Any] = {
            "scan_type": "file",
            "entropy": entropy_result if isinstance(entropy_result, dict) else {},
            "pe_analysis": pe_result if isinstance(pe_result, dict) else {},
            "strings": strings_result if isinstance(strings_result, dict) else {},
            "yara": yara_result if isinstance(yara_result, dict) else {},
            "iocs": ioc_result if isinstance(ioc_result, dict) else {},
            "virustotal": vt_result if isinstance(vt_result, dict) else {},
        }
        score_result = _safe_run("threat_score", calculate_threat_score, scoring_input)

        # ── 11. AI explanation (async) ───────
        from app.analysis.ai_explainer import generate_explanation

        # Enrich the score result with IOC data for the AI prompt
        if isinstance(score_result, dict) and isinstance(ioc_result, dict):
            score_result["iocs"] = ioc_result
        ai_result = _safe_run_async("ai_explainer", generate_explanation(score_result))

        # ── 12. Build complete result_json ───
        # Strip the raw 'all_strings' list to keep DB payload manageable
        strings_stored = {}
        if isinstance(strings_result, dict):
            strings_stored = {
                k: v for k, v in strings_result.items() if k != "all_strings"
            }

        result_json: dict[str, Any] = {
            "file_info": {
                "md5": md5_hash,
                "sha256": sha256_hash,
                "ssdeep": ssdeep_hash,
                "size_bytes": file_size,
                "minio_object": object_name,
            },
            "entropy": entropy_result if isinstance(entropy_result, dict) else {},
            "pe_analysis": pe_result if isinstance(pe_result, dict) else {},
            "strings": strings_stored,
            "yara": yara_result if isinstance(yara_result, dict) else {},
            "iocs": ioc_result if isinstance(ioc_result, dict) else {},
            "virustotal": vt_result if isinstance(vt_result, dict) else {},
            "threat_score_breakdown": score_result if isinstance(score_result, dict) else {},
            "ai_explanation": ai_result if isinstance(ai_result, dict) else {},
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        threat_score = score_result.get("score", 0) if isinstance(score_result, dict) else 0
        verdict_str = score_result.get("verdict", "clean") if isinstance(score_result, dict) else "clean"

        # ── 13. Persist results ──────────────
        _run_async(_update_scan(
            scan_id,
            status=ScanStatus.COMPLETED,
            result_json=result_json,
            threat_score=threat_score,
            verdict=Verdict(verdict_str),
            file_hash_md5=md5_hash,
            file_hash_sha256=sha256_hash,
        ))

        logger.info(
            "✔ File scan completed — scan_id=%s  score=%d  verdict=%s",
            scan_id, threat_score, verdict_str,
        )
        return {"status": "completed", "threat_score": threat_score, "verdict": verdict_str}

    except Exception as exc:
        logger.exception("File scan failed — scan_id=%s: %s", scan_id, str(exc))
        try:
            from rq import get_current_job
            job = get_current_job()
            retries_left = job.retries_left if job else 0
            if retries_left is None or retries_left <= 0:
                _run_async(_update_scan(
                    scan_id, status=ScanStatus.FAILED,
                    result_json={"error": f"Scan failed: {str(exc)}"},
                ))
            else:
                _run_async(_update_scan(scan_id, status=ScanStatus.QUEUED))
        except Exception:
            logger.error("Could not mark scan %s as failed/queued in DB", scan_id)
        raise exc

    finally:
        # ── 14. Clean up temp file ───────────
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
                logger.debug("Temp file removed: %s", tmp_path)
            except OSError:
                pass


# ═════════════════════════════════════════════════════════════
# URL SCAN TASK
# ═════════════════════════════════════════════════════════════

def scan_url_task(scan_id: str, url: str) -> dict[str, Any]:
    """
    Full URL analysis pipeline.

    Args:
        scan_id: UUID of the Scan row (= job_id).
        url:     The original URL submitted by the user.

    Returns:
        Summary dict with ``status``, ``threat_score``, ``verdict``.
    """
    logger.info("▶ URL scan started — scan_id=%s  url=%s", scan_id, url)

    try:
        # ── 1. Mark as running ───────────────
        _run_async(_update_scan(scan_id, status=ScanStatus.RUNNING))

        # ── 2. Extract domain ────────────────
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.hostname or parsed.path.split("/")[0]

        if not domain:
            _run_async(_update_scan(
                scan_id, status=ScanStatus.FAILED,
                result_json={"error": "Could not extract domain from URL"},
            ))
            return {"status": "failed", "error": "Invalid URL"}

        logger.info("Domain extracted: %s", domain)

        # ── 3. WHOIS + DNS ───────────────────
        from app.analysis.whois_dns import run_dns_resolution, run_whois_lookup

        whois_result = _safe_run("whois", run_whois_lookup, domain)
        dns_result = _safe_run("dns", run_dns_resolution, domain)

        # ── 4. SSL certificate inspection ────
        from app.analysis.ssl_inspector import inspect_ssl

        ssl_result = _safe_run("ssl", inspect_ssl, domain)

        # ── 5. Screenshot capture (async) ────
        from app.analysis.screenshot import capture_screenshot, extract_page_intel

        screenshot_result = _safe_run_async(
            "screenshot", capture_screenshot(url, scan_id)
        )

        # ── 6. Page intelligence (async) ─────
        page_intel = _safe_run_async(
            "page_intel", extract_page_intel(url)
        )

        # ── 7. IOC extraction from page text ─
        from app.analysis.ioc_extractor import extract_iocs

        page_text_parts: list[str] = []
        if isinstance(screenshot_result, dict):
            page_text_parts.append(screenshot_result.get("page_title", ""))
        if isinstance(page_intel, dict):
            page_text_parts.append(page_intel.get("page_text_sample", ""))
            for script in page_intel.get("external_scripts", []):
                page_text_parts.append(script)
            for iframe in page_intel.get("hidden_iframes", []):
                page_text_parts.append(iframe)
            for action in page_intel.get("form_actions", []):
                page_text_parts.append(action)
        combined_text = "\n".join(page_text_parts)
        ioc_result = _safe_run("ioc", extract_iocs, combined_text)

        # ── 8. Threat score aggregation ──────
        from app.analysis.threat_score import calculate_threat_score

        scoring_input: dict[str, Any] = {
            "scan_type": "url",
            "whois": whois_result if isinstance(whois_result, dict) else {},
            "dns": dns_result if isinstance(dns_result, dict) else {},
            "ssl": ssl_result if isinstance(ssl_result, dict) else {},
            "screenshot": screenshot_result if isinstance(screenshot_result, dict) else {},
            "page_intel": page_intel if isinstance(page_intel, dict) else {},
            "iocs": ioc_result if isinstance(ioc_result, dict) else {},
        }
        score_result = _safe_run("threat_score", calculate_threat_score, scoring_input)

        # ── 9. AI explanation (async) ────────
        from app.analysis.ai_explainer import generate_explanation

        if isinstance(score_result, dict) and isinstance(ioc_result, dict):
            score_result["iocs"] = ioc_result
        ai_result = _safe_run_async("ai_explainer", generate_explanation(score_result))

        # ── 10. Build complete result_json ───
        result_json: dict[str, Any] = {
            "url_info": {
                "original_url": url,
                "domain": domain,
                "scheme": parsed.scheme or "unknown",
                "path": parsed.path,
            },
            "whois": whois_result if isinstance(whois_result, dict) else {},
            "dns": dns_result if isinstance(dns_result, dict) else {},
            "ssl": ssl_result if isinstance(ssl_result, dict) else {},
            "screenshot": screenshot_result if isinstance(screenshot_result, dict) else {},
            "page_intel": page_intel if isinstance(page_intel, dict) else {},
            "iocs": ioc_result if isinstance(ioc_result, dict) else {},
            "threat_score_breakdown": score_result if isinstance(score_result, dict) else {},
            "ai_explanation": ai_result if isinstance(ai_result, dict) else {},
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        threat_score = score_result.get("score", 0) if isinstance(score_result, dict) else 0
        verdict_str = score_result.get("verdict", "clean") if isinstance(score_result, dict) else "clean"

        # ── 11. Persist results ──────────────
        _run_async(_update_scan(
            scan_id,
            status=ScanStatus.COMPLETED,
            result_json=result_json,
            threat_score=threat_score,
            verdict=Verdict(verdict_str),
        ))

        logger.info(
            "✔ URL scan completed — scan_id=%s  score=%d  verdict=%s",
            scan_id, threat_score, verdict_str,
        )
        return {"status": "completed", "threat_score": threat_score, "verdict": verdict_str}

    except Exception as exc:
        logger.exception("URL scan failed — scan_id=%s: %s", scan_id, str(exc))
        try:
            from rq import get_current_job
            job = get_current_job()
            retries_left = job.retries_left if job else 0
            if retries_left is None or retries_left <= 0:
                _run_async(_update_scan(
                    scan_id, status=ScanStatus.FAILED,
                    result_json={"error": f"Scan failed: {str(exc)}"},
                ))
            else:
                _run_async(_update_scan(scan_id, status=ScanStatus.QUEUED))
        except Exception:
            logger.error("Could not mark scan %s as failed/queued in DB", scan_id)
        raise exc

# ═════════════════════════════════════════════════════════════
# IP SCAN TASK
# ═════════════════════════════════════════════════════════════

def scan_ip_task(scan_id: str, ip: str) -> dict[str, Any]:
    """
    Full IP analysis pipeline.

    Args:
        scan_id: UUID of the Scan row (= job_id).
        ip:      The original IP submitted by the user.

    Returns:
        Summary dict with ``status``, ``threat_score``, ``verdict``.
    """
    logger.info("▶ IP scan started — scan_id=%s  ip=%s", scan_id, ip)

    try:
        # ── 1. Mark as running ───────────────
        _run_async(_update_scan(scan_id, status=ScanStatus.RUNNING))

        # ── 2. WHOIS lookup ──────────────────
        from app.analysis.ip_reputation import run_ip_whois, run_ip_reverse_dns, lookup_ip_virustotal, lookup_ip_abuseipdb, lookup_ip_shodan

        whois_result = _safe_run("whois", run_ip_whois, ip)

        # ── 3. Reverse DNS ───────────────────
        reverse_dns = _safe_run("reverse_dns", run_ip_reverse_dns, ip)

        # ── 4. VirusTotal reputation ─────────
        vt_result = _safe_run("virustotal", lookup_ip_virustotal, ip)

        # ── 5. AbuseIPDB reputation ──────────
        abuse_result = _safe_run("abuseipdb", lookup_ip_abuseipdb, ip)

        # ── 6. Shodan reputation ─────────────
        shodan_result = _safe_run("shodan", lookup_ip_shodan, ip)

        # ── 7. Threat score aggregation ──────
        from app.analysis.threat_score import calculate_threat_score

        scoring_input: dict[str, Any] = {
            "scan_type": "ip",
            "whois": whois_result if isinstance(whois_result, dict) else {},
            "abuseipdb": abuse_result if isinstance(abuse_result, dict) else {},
            "virustotal": vt_result if isinstance(vt_result, dict) else {},
        }
        score_result = _safe_run("threat_score", calculate_threat_score, scoring_input)

        # ── 8. AI explanation (async) ────────
        from app.analysis.ai_explainer import generate_explanation

        # Pass simple IOC input so the prompt builder can reference the IP
        if isinstance(score_result, dict):
            score_result["iocs"] = {"ipv4": [ip], "ipv6": [], "domains": [], "urls": [], "hashes": {"md5": [], "sha1": [], "sha256": []}}
        ai_result = _safe_run_async("ai_explainer", generate_explanation(score_result))

        # ── 9. Build complete result_json ────
        result_json: dict[str, Any] = {
            "ip_info": {
                "ip": ip,
                "reverse_dns": reverse_dns,
            },
            "whois": whois_result if isinstance(whois_result, dict) else {},
            "abuseipdb": abuse_result if isinstance(abuse_result, dict) else {},
            "shodan": shodan_result if isinstance(shodan_result, dict) else {},
            "virustotal": vt_result if isinstance(vt_result, dict) else {},
            "threat_score_breakdown": score_result if isinstance(score_result, dict) else {},
            "ai_explanation": ai_result if isinstance(ai_result, dict) else {},
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        threat_score = score_result.get("score", 0) if isinstance(score_result, dict) else 0
        verdict_str = score_result.get("verdict", "clean") if isinstance(score_result, dict) else "clean"

        # ── 10. Persist results ──────────────
        _run_async(_update_scan(
            scan_id,
            status=ScanStatus.COMPLETED,
            result_json=result_json,
            threat_score=threat_score,
            verdict=Verdict(verdict_str),
        ))

        logger.info(
            "✔ IP scan completed — scan_id=%s  score=%d  verdict=%s",
            scan_id, threat_score, verdict_str,
        )
        return {"status": "completed", "threat_score": threat_score, "verdict": verdict_str}

    except Exception as exc:
        logger.exception("IP scan failed — scan_id=%s: %s", scan_id, str(exc))
        try:
            from rq import get_current_job
            job = get_current_job()
            retries_left = job.retries_left if job else 0
            if retries_left is None or retries_left <= 0:
                _run_async(_update_scan(
                    scan_id, status=ScanStatus.FAILED,
                    result_json={"error": f"Scan failed: {str(exc)}"},
                ))
            else:
                _run_async(_update_scan(scan_id, status=ScanStatus.QUEUED))
        except Exception:
            logger.error("Could not mark scan %s as failed/queued in DB", scan_id)
        raise exc
