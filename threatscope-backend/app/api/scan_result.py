import logging
import uuid
import socket

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.limiter import limiter, get_rate_limit
from app.core.auth_deps import get_current_user, check_daily_quota
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus
from app.schemas.scan import ScanHistoryResponse, ScanResultResponse, IpScanRequest, ScanSubmitResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["Scan Results"])


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────
def _scan_to_response(scan: Scan) -> ScanResultResponse:
    """Map a Scan ORM instance to its Pydantic response schema."""
    res_json = scan.result_json.copy() if scan.result_json else None
    if res_json and "screenshot" in res_json:
        ss_info = res_json["screenshot"]
        if isinstance(ss_info, dict) and ss_info.get("screenshot_path"):
            from app.core.storage import get_presigned_url
            try:
                ss_info["screenshot_url"] = get_presigned_url(ss_info["screenshot_path"])
            except Exception:
                ss_info["screenshot_url"] = None

    return ScanResultResponse(
        job_id=str(scan.id),
        scan_type=scan.scan_type.value,
        target=scan.target,
        status=scan.status.value,
        file_hash_md5=scan.file_hash_md5,
        file_hash_sha256=scan.file_hash_sha256,
        threat_score=scan.threat_score,
        verdict=scan.verdict.value if scan.verdict else None,
        result=res_json,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


# ─────────────────────────────────────────────────────────────
# GET /api/scan/history  (MUST come before /{job_id})
# ─────────────────────────────────────────────────────────────
@router.get(
    "/history",
    response_model=ScanHistoryResponse,
    summary="Get global scan history",
)
async def get_scan_history(
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryResponse:
    """
    Return the 20 most recent scan jobs globally,
    ordered newest-first.
    """
    result = await db.execute(
        select(Scan)
        .order_by(desc(Scan.created_at))
        .limit(20)
    )
    scans = result.scalars().all()

    return ScanHistoryResponse(
        scans=[_scan_to_response(s) for s in scans],
        total=len(scans),
    )


# ─────────────────────────────────────────────────────────────
# POST /api/scan/ip
# ─────────────────────────────────────────────────────────────
@router.post(
    "/ip",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit an IP address for threat analysis",
)
@limiter.limit(get_rate_limit)
async def submit_ip_scan(
    request: Request,
    payload: IpScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _quota: None = Depends(check_daily_quota),
) -> ScanSubmitResponse:
    """
    Submit an IP address for background WHOIS, reverse DNS, and reputation analysis.
    """
    ip = payload.target.strip()

    # Validate IP address format
    is_valid = False
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, ip)
            is_valid = True
            break
        except OSError:
            pass

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address format.",
        )

    # Create Scan record
    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        scan_type=ScanType.IP,
        target=ip,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    await db.flush()

    # Enqueue background analysis task
    from rq import Retry
    from app.core.rq_setup import get_queue
    from app.tasks.scan_tasks import scan_ip_task

    queue = get_queue("default")
    queue.enqueue(
        scan_ip_task, str(scan_id), ip,
        job_timeout=120,
        retry=Retry(max=3, interval=[10, 30, 60])
    )

    logger.info(
        "IP scan queued — job_id=%s  ip=%s",
        scan_id, ip,
    )

    return ScanSubmitResponse(job_id=str(scan_id), status="queued")


# ─────────────────────────────────────────────────────────────
# GET /api/scan/{job_id}
# ─────────────────────────────────────────────────────────────
@router.get(
    "/{job_id}",
    response_model=ScanResultResponse,
    summary="Poll scan status and results",
)
async def get_scan_result(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanResultResponse:
    """
    Retrieve the current status, threat score, verdict, and full
    analysis results for a scan job.

    Clients should poll this endpoint until ``status`` is
    ``"completed"`` or ``"failed"``.
    """
    # ── Validate UUID format ─────────────────
    try:
        scan_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job_id — must be a valid UUID",
        )

    # ── Fetch scan ───────────────────────────
    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{job_id}' not found",
        )

    return _scan_to_response(scan)
