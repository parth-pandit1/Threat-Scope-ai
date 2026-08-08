"""
Pydantic v2 schemas for scan submission and result payloads — Phase 2.

The ``ScanResultResponse`` schema now uses ``result`` (renamed from
``result_json``) and the inner structure carries the full Phase 2
analysis output: entropy, PE, strings, YARA, IOCs, VT, SSL,
screenshot, threat-score breakdown, and AI explanation.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanSubmitResponse(BaseModel):
    """Returned immediately after a scan is queued."""

    job_id: str = Field(..., description="UUID of the scan job for polling.")
    status: str = Field(default="queued", description="Initial job status.")


class UrlScanRequest(BaseModel):
    """Request body for ``POST /api/scan/url``."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        examples=["https://example.com"],
        description="Full URL to analyse (include scheme).",
    )


class IpScanRequest(BaseModel):
    """Request body for ``POST /api/scan/ip``."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=45,
        examples=["8.8.8.8"],
        description="IP address to analyse (IPv4 or IPv6).",
    )


class ScanResultResponse(BaseModel):
    """
    Full scan result returned by ``GET /api/scan/{job_id}``.

    The ``result`` field contains the complete Phase 2 analysis
    output.  Its inner structure depends on scan_type:

    **File scans** include:
    ``file_info``, ``entropy``, ``pe_analysis``, ``strings``,
    ``yara``, ``iocs``, ``virustotal``, ``threat_score_breakdown``,
    ``ai_explanation``.

    **URL scans** include:
    ``url_info``, ``whois``, ``dns``, ``ssl``, ``screenshot``,
    ``page_intel``, ``iocs``, ``threat_score_breakdown``,
    ``ai_explanation``.
    """

    job_id: str
    scan_type: str
    target: str
    status: str
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    threat_score: Optional[int] = None
    verdict: Optional[str] = None
    result: Optional[dict[str, Any]] = Field(
        None,
        description="Full structured analysis result (Phase 2).",
    )
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Paginated list of the user's recent scans."""

    scans: list[ScanResultResponse]
    total: int
