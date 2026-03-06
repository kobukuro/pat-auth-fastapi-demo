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
    """Create and return a PAT with fcs:analyze scope for testing statistics tasks."""
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

    # Upload chunk 0 - use real FCS header + padding to pass validation
    # FCS files must start with "FCS" magic number
    fcs_header = b"FCS3.0         256  "
    chunk_data = fcs_header + b"x" * (5242880 - len(fcs_header))  # Pad to 5MB

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


def test_get_upload_status(client, auth_pat):
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

    # Get status (chunked_upload tasks need fcs:write scope)
    response = client.get(
        f"/api/v1/fcs/tasks/{task_id}",
        headers={"Authorization": f"Bearer {auth_pat}"},
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


def test_upload_invalid_fcs_file_rejected_on_first_chunk(client, auth_pat):
    """Test that non-FCS files are rejected on first chunk upload."""
    # Init session - use .fcs extension to pass init validation
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "invalid.fcs",  # Use .fcs extension
            "file_size": 5242880,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # Upload invalid first chunk (not FCS format - doesn't start with "FCS")
    chunk_data = b"\xe0\xe0\xe0" + b"x" * 5242877  # Starts with invalid bytes

    response = client.post(
        "/api/v1/fcs/upload/chunk",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk_0.dat", BytesIO(chunk_data), "application/octet-stream")},
    )

    # Should return 400 with safe error message (no internal details)
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["message"] == "Invalid FCS file format"  # Generic message, no internal details leaked


def test_upload_valid_fcs_file_accepted(client, auth_pat):
    """Test that valid FCS files are accepted."""
    # Read real FCS file to get actual size
    with open("app/data/sample.fcs", "rb") as f:
        chunk_data = f.read()
    file_size = len(chunk_data)

    # Init session
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": file_size,
            "chunk_size": file_size,  # Upload as single chunk
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    response = client.post(
        "/api/v1/fcs/upload/chunk",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk_0.dat", BytesIO(chunk_data), "application/octet-stream")},
    )

    # Should return 202 (accepted)
    assert response.status_code == 202


def test_upload_chunk_with_wrong_task_type_returns_400(client, auth_pat, db):
    """Test that uploading a chunk with a statistics task_id returns 400."""
    from app.models.background_task import BackgroundTask, TaskType
    from app.models.user import User

    # Get the actual user_id from the database
    user = db.query(User).filter_by(email="user1@example.com").first()
    assert user is not None, "Test user should exist"

    # Create a statistics task (not chunked upload)
    stats_task = BackgroundTask(
        user_id=user.id,
        task_type=TaskType.STATISTICS,
        status="pending",
        extra_data={"file_id": 1}
    )
    db.add(stats_task)
    db.commit()
    db.refresh(stats_task)

    # Try to upload chunk to statistics task
    fcs_header = b"FCS3.0         256  "
    chunk_data = fcs_header + b"x" * (5242880 - len(fcs_header))  # Pad to 5MB

    response = client.post(
        "/api/v1/fcs/upload/chunk",
        headers={"Authorization": f"Bearer {auth_pat}"},
        data={
            "task_id": stats_task.id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk_0.dat", BytesIO(chunk_data), "application/octet-stream")},
    )

    # Should return 400 with error message about not being an upload session
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "not an upload session" in data["message"]

    # Clean up
    db.delete(stats_task)
    db.commit()
