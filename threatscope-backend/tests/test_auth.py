import uuid
from unittest.mock import MagicMock
import pytest
from app.models.user import User, UserTier
from app.core.auth_deps import get_password_hash, get_current_user
from app.main import app
from datetime import datetime, timezone


@pytest.fixture(autouse=True)
def clean_auth_overrides():
    """Remove default mock get_current_user override so auth tests use the real dependency."""
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]
    yield


def test_register_user_success(client, mock_db_session):
    """Verify that registering a new email succeeds and returns profile details."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    payload = {"email": "newuser@example.com", "password": "secretpassword"}
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "api_key" in data
    assert data["tier"] == "free"
    assert data["is_admin"] is False


def test_register_user_duplicate(client, mock_db_session):
    """Verify that registering an already registered email fails with 400."""
    existing_user = User(
        id=uuid.uuid4(),
        email="existing@example.com",
        hashed_password="somehash",
        api_key="ts_existingkey",
        tier=UserTier.FREE,
        is_admin=False,
        is_banned=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_user
    mock_db_session.execute.return_value = mock_result

    payload = {"email": "existing@example.com", "password": "secretpassword"}
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


def test_login_user_success(client, mock_db_session):
    """Verify that correct credentials return 200 and set access/refresh cookies."""
    hashed_pwd = get_password_hash("validpass")
    mock_user = User(
        id=uuid.uuid4(),
        email="loginuser@example.com",
        hashed_password=hashed_pwd,
        tier=UserTier.FREE,
        api_key="ts_testkey123",
        is_admin=False,
        is_banned=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db_session.execute.return_value = mock_result

    payload = {"email": "loginuser@example.com", "password": "validpass"}
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 200
    
    # Check JSON response
    data = response.json()
    assert data["user"]["email"] == "loginuser@example.com"
    assert "access_token" in data
    
    # Check cookies
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies


def test_login_user_invalid_credentials(client, mock_db_session):
    """Verify that login fails with 401 when given an invalid password."""
    hashed_pwd = get_password_hash("validpass")
    mock_user = User(
        id=uuid.uuid4(),
        email="loginuser@example.com",
        hashed_password=hashed_pwd,
        tier=UserTier.FREE,
        api_key="ts_testkey123",
        is_admin=False,
        is_banned=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db_session.execute.return_value = mock_result

    payload = {"email": "loginuser@example.com", "password": "wrongpassword"}
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 401
    assert "Invalid email address or password" in response.json()["detail"]


def test_scan_submissions_unauthenticated(client):
    """Verify that posting scans without any token/key returns 401."""
    # File upload
    files = {"file": ("test.txt", b"content", "text/plain")}
    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 401

    # URL upload
    response = client.post("/api/scan/url", json={"url": "http://google.com"})
    assert response.status_code == 401

    # IP upload
    response = client.post("/api/scan/ip", json={"target": "8.8.8.8"})
    assert response.status_code == 401


def test_scan_submission_with_api_key(client, mock_db_session):
    """Verify that posting scans with a valid programmatic api key header succeeds."""
    mock_user = User(
        id=uuid.uuid4(),
        email="apikeyuser@example.com",
        hashed_password="somehash",
        api_key="ts_validkey",
        tier=UserTier.FREE,
        is_admin=False,
        is_banned=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db_session.execute.return_value = mock_result

    headers = {"x-api-key": "ts_validkey"}
    response = client.post("/api/scan/ip", json={"target": "8.8.8.8"}, headers=headers)
    assert response.status_code == 202


def test_ban_user_as_non_admin(client, mock_db_session):
    """Verify that non-admins cannot ban users (returns 403)."""
    normal_user = User(
        id=uuid.uuid4(),
        email="user@example.com",
        hashed_password="somehash",
        is_admin=False,
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = normal_user
    mock_db_session.execute.return_value = mock_result

    # Non-admin calls ban
    headers = {"x-api-key": "ts_normal_key"}
    payload = {"email": "victim@example.com", "is_banned": True}
    response = client.post("/api/admin/ban", json=payload, headers=headers)
    assert response.status_code == 403


def test_ban_user_as_admin_success(client, mock_db_session):
    """Verify that admins can successfully ban users."""
    admin_user = User(
        id=uuid.uuid4(),
        email="admin@example.com",
        hashed_password="somehash",
        is_admin=True,
    )
    victim_user = User(
        id=uuid.uuid4(),
        email="victim@example.com",
        hashed_password="somehash",
        is_banned=False,
    )
    
    # We mock first DB select (admin validation) and second DB select (finding victim)
    mock_exec_admin = MagicMock()
    mock_exec_admin.scalar_one_or_none.return_value = admin_user
    
    mock_exec_victim = MagicMock()
    mock_exec_victim.scalar_one_or_none.return_value = victim_user
    
    # Session execute side_effect
    mock_db_session.execute.side_effect = [mock_exec_admin, mock_exec_victim]

    headers = {"x-api-key": "ts_admin_key"}
    payload = {"email": "victim@example.com", "is_banned": True}
    response = client.post("/api/admin/ban", json=payload, headers=headers)
    assert response.status_code == 200
    assert "successfully banned" in response.json()["message"]
    assert victim_user.is_banned is True


def test_banned_user_access_blocked(client, mock_db_session):
    """Verify that banned users are blocked with 403."""
    banned_user = User(
        id=uuid.uuid4(),
        email="banned@example.com",
        hashed_password="somehash",
        is_banned=True,
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = banned_user
    mock_db_session.execute.return_value = mock_result

    # Banned user tries to scan
    headers = {"x-api-key": "ts_banned_key"}
    response = client.post("/api/scan/ip", json={"target": "8.8.8.8"}, headers=headers)
    assert response.status_code == 403
    assert "account is banned" in response.json()["detail"]


def test_daily_quota_exceeded(client, mock_db_session):
    """Verify that exceeding daily quota returns 429."""
    user = User(
        id=uuid.uuid4(),
        email="freeuser@example.com",
        hashed_password="somehash",
        tier=UserTier.FREE,
    )
    
    # First query resolves the user
    mock_exec_user = MagicMock()
    mock_exec_user.scalar_one_or_none.return_value = user
    
    # Second query counts the scans today (returns 25, which exceeds Free tier 20 limit)
    mock_exec_count = MagicMock()
    mock_exec_count.scalar.return_value = 25
    
    mock_db_session.execute.side_effect = [mock_exec_user, mock_exec_count]

    headers = {"x-api-key": "ts_free_key"}
    response = client.post("/api/scan/ip", json={"target": "8.8.8.8"}, headers=headers)
    assert response.status_code == 429
    assert "Daily scan quota exceeded" in response.json()["detail"]
