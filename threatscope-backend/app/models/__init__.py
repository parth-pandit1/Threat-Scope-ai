"""SQLAlchemy models — re-exported for convenient access."""

from app.models.scan import Scan, ScanType, ScanStatus, Verdict

__all__ = [
    "Scan",
    "ScanType",
    "ScanStatus",
    "Verdict",
]
