"""
URL submission and scan endpoint.

``POST /api/scan/url`` — accepts a JSON body with a URL, creates a
``Scan`` record, and dispatches an RQ task for WHOIS + DNS analysis.
"""

import logging
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.scan import Scan, ScanStatus, ScanType
from app.schemas.scan import ScanSubmitResponse, UrlScanRequest
from app.tasks.scan_tasks import scan_url_task
from app.core.rq_setup import get_queue
from app.core.limiter import limiter, get_rate_limit
from app.core.auth_deps import get_current_user, check_daily_quota
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["URL Scanning"])


@router.post(
    "/url",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a URL for threat analysis",
)
@limiter.limit(get_rate_limit)
async def submit_url_scan(
    request: Request,
    payload: UrlScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _quota: None = Depends(check_daily_quota),
) -> ScanSubmitResponse:
    """
    Submit a URL for background WHOIS and DNS analysis.
    """
    # ── Validate URL ─────────────────────────
    url = payload.url.strip()
    parsed = urlparse(url if "://" in url else f"https://{url}")

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL: could not extract a hostname",
        )

    # ── Create Scan record ───────────────────
    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        scan_type=ScanType.URL,
        target=url,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    await db.flush()

    # ── Dispatch RQ task ─────────────────
    from rq import Retry
    queue = get_queue("default")
    queue.enqueue(
        scan_url_task, str(scan_id), url,
        job_timeout=120,
        retry=Retry(max=3, interval=[10, 30, 60])
    )
    
    logger.info(
        "URL scan queued — job_id=%s  url=%s",
        scan_id, url,
    )

    return ScanSubmitResponse(job_id=str(scan_id), status="queued")
