"""
Integration/API level tests for threatscope scan endpoints.
"""

import uuid
from unittest.mock import MagicMock
from app.models.scan import Scan, ScanType, ScanStatus

def test_upload_file_success(client):
    """Verify that uploading a valid file yields 202 and a job UUID."""
    files = {"file": ("malicious_sample.bin", b"some mock binary executable bytes", "application/octet-stream")}
    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 202
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    
    # Check if job_id is valid UUID
    parsed_uuid = uuid.UUID(data["job_id"])
    assert parsed_uuid is not None

def test_upload_file_oversized(client, monkeypatch):
    """Verify that uploading an oversized file returns a 413 payload too large."""
    from app.core.config import settings
    # Override settings limit to 0 MB to force failure immediately without using memory
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 0)
    
    files = {"file": ("malicious_sample.bin", b"some bytes", "application/octet-stream")}
    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]

def test_get_scan_result_invalid_uuid(client):
    """Verify that polling with an invalid UUID returns 400."""
    response = client.get("/api/scan/not-a-valid-uuid")
    assert response.status_code == 400
    assert "must be a valid UUID" in response.json()["detail"]

def test_get_scan_result_not_found(client, mock_db_session):
    """Verify that polling a non-existent job returns 404."""
    job_uuid = uuid.uuid4()
    
    # Mock empty result from DB
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_exec_result
    
    response = client.get(f"/api/scan/{job_uuid}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

def test_get_scan_result_success(client, mock_db_session):
    """Verify that polling an existing scan returns the scan details."""
    from datetime import datetime, timezone
    job_uuid = uuid.uuid4()
    mock_scan = Scan(
        id=job_uuid,
        scan_type=ScanType.FILE,
        target="malicious_sample.bin",
        status=ScanStatus.QUEUED,
        created_at=datetime.now(timezone.utc)
    )
    
    # Mock DB hit
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = mock_scan
    mock_db_session.execute.return_value = mock_exec_result
    
    response = client.get(f"/api/scan/{job_uuid}")
    assert response.status_code == 200
    data = response.json()
    assert data["job_id"] == str(job_uuid)
    assert data["status"] == "queued"
    assert data["target"] == "malicious_sample.bin"


def test_upload_ip_success(client):
    """Verify that posting a valid IP yields 202 and a job UUID."""
    payload = {"target": "8.8.8.8"}
    response = client.post("/api/scan/ip", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    uuid.UUID(data["job_id"])


def test_upload_ip_invalid(client):
    """Verify that posting an invalid IP yields 400."""
    payload = {"target": "not-an-ip"}
    response = client.post("/api/scan/ip", json=payload)
    assert response.status_code == 400
    assert "Invalid IP address format" in response.json()["detail"]
