"""
File upload and scan submission endpoint.

``POST /api/scan/file`` — accepts a multipart file upload, validates
size and MIME type, stores the file in MinIO, creates a ``Scan``
record, and dispatches an RQ background task for analysis.
"""

import logging
import uuid
import magic
try:
    magic.from_buffer(b"", mime=True)
    _has_magic = True
except Exception:
    _has_magic = False

import puremagic

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.storage import upload_file
from app.models.scan import Scan, ScanStatus, ScanType
from app.schemas.scan import ScanSubmitResponse
from app.tasks.scan_tasks import scan_file_task
from app.core.rq_setup import get_queue
from app.core.limiter import limiter, get_rate_limit
from app.core.auth_deps import get_current_user, check_daily_quota
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["File Scanning"])


@router.post(
    "/file",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a file for malware analysis",
)
@limiter.limit(get_rate_limit)
async def upload_scan_file(
    request: Request,
    file: UploadFile = File(..., description="File to analyse (max 50 MB)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _quota: None = Depends(check_daily_quota),
) -> ScanSubmitResponse:
    """
    Upload a file for background malware analysis.
    """
    # ── Read file bytes ──────────────────────
    file_data = await file.read()

    # ── Validate file size ───────────────────
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(file_data) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"File size ({len(file_data):,} bytes) exceeds the "
                f"{settings.MAX_FILE_SIZE_MB} MB limit"
            ),
        )

    if len(file_data) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # ── Validate MIME type with magic ────────
    if _has_magic:
        try:
            actual_mime = magic.from_buffer(file_data, mime=True)
        except Exception:
            try:
                actual_mime = puremagic.from_string(file_data, mime=True)
            except Exception:
                actual_mime = "application/octet-stream"
    else:
        try:
            actual_mime = puremagic.from_string(file_data, mime=True)
        except Exception:
            actual_mime = "application/octet-stream"
    content_type = file.content_type or actual_mime
    blocked_types = {
        "text/html",
        "text/javascript",
        "application/javascript",
        "application/x-httpd-php",
    }
    if actual_mime in blocked_types or content_type in blocked_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MIME type '{actual_mime}' is not permitted for scanning",
        )

    # ── Upload to MinIO ──────────────────────
    scan_id = uuid.uuid4()
    extension = (
        file.filename.rsplit(".", 1)[-1]
        if file.filename and "." in file.filename
        else "bin"
    )
    object_name = f"users/{current_user.id}/{scan_id}.{extension}"

    try:
        upload_file(file_data, object_name, actual_mime)
    except Exception as exc:
        logger.error("MinIO upload failed: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store the uploaded file — please try again",
        )

    # ── Create Scan record ───────────────────
    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        scan_type=ScanType.FILE,
        target=file.filename or "unknown",
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    await db.flush()

    # ── Dispatch RQ task ─────────────────
    from rq import Retry
    queue = get_queue("default")
    queue.enqueue(
        scan_file_task, str(scan_id), object_name,
        job_timeout=120,
        retry=Retry(max=3, interval=[10, 30, 60])
    )
    
    logger.info(
        "File scan queued — job_id=%s  file=%s",
        scan_id, file.filename,
    )

    return ScanSubmitResponse(job_id=str(scan_id), status="queued")
