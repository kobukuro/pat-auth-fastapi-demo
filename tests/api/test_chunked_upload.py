"""
Integration tests for chunked upload API endpoints.

Tests the complete chunked upload flow including initialization,
chunk uploads, progress tracking, and auto-completion.
"""
import pytest
from io import BytesIO

from tests.constants import URLs


# Helper functions
def _get_jwt(client, email="chunked@example.com") -> str:
    """Helper to register and login, returning JWT token."""
    client.post(
        URLs.REGISTER,
        json={"email": email, "password": "Password123!"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": email, "password": "Password123!"},
    )
    return response.json()["data"]["access_token"]


def _create_pat(client, jwt, scopes, expires_in_days=30, name="Test Token") -> str:
    """Helper to create a PAT with given scopes."""
    response = client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": name,
            "scopes": scopes,
            "expires_in_days": expires_in_days,
        },
    )
    return response.json()["data"]["token"]


# Fixtures
@pytest.fixture
def auth_pat(client):
    """Create and return a PAT with fcs:write scope for testing."""
    jwt = _get_jwt(client, email="user1@example.com")
    return _create_pat(client, jwt, ["fcs:write"], name="User1 Token")


@pytest.fixture
def auth_pat_analyze(client):
    """Create and return a PAT with fcs:analyze scope for testing task status."""
    jwt = _get_jwt(client, email="user1@example.com")
    return _create_pat(client, jwt, ["fcs:analyze"], name="User1 Analyze Token")


@pytest.fixture
def test_pat(client):
    """Create and return a different PAT for permission testing."""
    jwt = _get_jwt(client, email="user2@example.com")
    return _create_pat(client, jwt, ["fcs:write"], name="User2 Token")


def test_init_chunked_upload(client, auth_pat):
    """Test initializing chunked upload session."""
    response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 157286400,  # 150MB
            "chunk_size": 5242880,   # 5MB
            "is_public": True,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert "task_id" in data["data"]
    assert data["data"]["total_chunks"] == 30  # 150MB / 5MB
    assert data["data"]["status"] == "processing"


def test_upload_chunk(client, auth_pat):
    """Test uploading a single chunk."""
    # First init session
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 10485760,  # 10MB
            "chunk_size": 5242880,  # 5MB
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # Upload chunk 0
    chunk_data = b"x" * 5242880  # 5MB

    response = client.post(
        "/api/v1/fcs/upload/chunk",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk_0.dat", BytesIO(chunk_data), "application/octet-stream")},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["data"]["uploaded_chunks"] == 1
    assert data["data"]["progress_percentage"] == 50.0


def test_get_upload_status(client, auth_pat, auth_pat_analyze):
    """Test getting upload status (US-MVP-003)."""
    # Init session
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 10485760,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # Get status (needs fcs:analyze scope)
    response = client.get(
        f"/api/v1/fcs/tasks/{task_id}",
        headers={"Authorization": f"Bearer {auth_pat_analyze}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["task_id"] == task_id
    assert data["data"]["task_type"] == "chunked_upload"
    assert data["data"]["status"] == "processing"
    assert "result" in data["data"]


def test_abort_upload(client, auth_pat):
    """Test aborting upload session."""
    # Init session
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 10485760,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # Abort
    response = client.post(
        "/api/v1/fcs/upload/abort",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={"task_id": task_id},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["status"] == "failed"


def test_permission_checks(client, auth_pat, test_pat):
    """Test that users can only access their own upload sessions."""
    # User 1 creates session
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 10485760,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # User 2 tries to abort User 1's session (should fail)
    response = client.post(
        "/api/v1/fcs/upload/abort",
        headers={"Authorization": f"Bearer {test_pat}"},  # Different user
        data={"task_id": task_id},
    )

    assert response.status_code == 403


@pytest.mark.parametrize("file_size,chunk_size,total_chunks,expected_chunks", [
    (5242880, 5242880, 1, 1),      # 1 file = 1 chunk
    (10485760, 5242880, 2, 2),     # 10MB / 5MB = 2 chunks
    (15728640, 5242880, 3, 3),     # 15MB / 5MB = 3 chunks (ceiling)
])
def test_chunk_calculation(client, auth_pat, file_size, chunk_size, total_chunks, expected_chunks):
    """Test that chunk count is calculated correctly."""
    response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["data"]["total_chunks"] == expected_chunks
