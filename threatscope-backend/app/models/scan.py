"""
SQLAlchemy model for the Scan entity.

Represents a single analysis job — file upload, URL submission,
or IP lookup — tracked from *queued* through *completed* or *failed*.
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanType(str, enum.Enum):
    """Category of scan target."""

    FILE = "file"
    URL = "url"
    IP = "ip"


class ScanStatus(str, enum.Enum):
    """Lifecycle status of a scan job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(str, enum.Enum):
    """Threat verdict assigned after analysis."""

    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Scan(Base):
    """
    Scan job model.

    The ``id`` doubles as the public ``job_id`` returned to clients.

    Attributes:
        id:               Unique job identifier (UUID v4).
        user_id:          Owner (nullable for future anonymous scans).
        scan_type:        file / url / ip.
        target:           Original filename, URL, or IP address.
        file_hash_md5:    MD5 digest (populated after file analysis).
        file_hash_sha256: SHA-256 digest (populated after file analysis).
        status:           Current job lifecycle state.
        threat_score:     0-100 threat rating (nullable until completed).
        verdict:          Human-readable classification of threat level.
        result_json:      Full structured analysis output (JSONB column).
        created_at:       Job creation timestamp (UTC).
        completed_at:     Job completion timestamp (UTC, nullable).
    """

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    file_hash_md5: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    file_hash_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        default=ScanStatus.QUEUED,
        nullable=False,
    )
    threat_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    verdict: Mapped[Verdict | None] = mapped_column(
        Enum(Verdict),
        nullable=True,
    )
    result_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<Scan id={self.id} type={self.scan_type.value} "
            f"status={self.status.value}>"
        )
