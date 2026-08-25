"""
Pytest fixtures and configuration.
"""

import sys
from unittest.mock import AsyncMock, MagicMock

# Mock ssdeep, yara, and magic to avoid import/compile errors on Windows local testing
sys.modules['ssdeep'] = MagicMock()
sys.modules['yara'] = MagicMock()
sys.modules['magic'] = MagicMock()
sys.modules['magic'].from_buffer = MagicMock(return_value="application/octet-stream")

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import get_db

@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.scalar = AsyncMock()
    session.scalars = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session

@pytest.fixture(autouse=True)
def override_dependencies(mock_db_session, monkeypatch):
    """Override FastAPI dependencies and core storage/redis methods."""
    # Override get_db dependency
    async def _get_db():
        yield mock_db_session

    app.dependency_overrides[get_db] = _get_db

    # Mock MinIO storage methods
    mock_upload = MagicMock(return_value="test_object_name")
    mock_download = MagicMock(return_value=b"test_file_bytes")
    monkeypatch.setattr("app.core.storage.upload_file", mock_upload)
    monkeypatch.setattr("app.core.storage.download_file", mock_download)
    monkeypatch.setattr("app.core.storage.ensure_bucket_exists", MagicMock())
    monkeypatch.setattr("app.api.scan_file.upload_file", mock_upload)
    monkeypatch.setattr("app.main.ensure_bucket_exists", MagicMock())
    monkeypatch.setattr("app.main.get_minio_client", MagicMock())

    # Mock Redis connection methods
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.setex.return_value = True
    monkeypatch.setattr("app.core.rq_setup.redis_conn", mock_redis)
    monkeypatch.setattr("app.main.redis_conn", mock_redis)

    # Mock RQ get_queue to prevent connecting to redis during endpoint testing
    mock_queue = MagicMock()
    mock_queue.enqueue = MagicMock()
    monkeypatch.setattr("app.api.scan_file.get_queue", MagicMock(return_value=mock_queue))
    monkeypatch.setattr("app.api.scan_url.get_queue", MagicMock(return_value=mock_queue))

    # Mock YARA rules methods
    monkeypatch.setattr("app.analysis.yara_manager.get_rules", MagicMock(return_value=None))

    yield

    app.dependency_overrides.clear()

@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)
