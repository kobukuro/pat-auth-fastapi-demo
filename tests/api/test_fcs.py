"""
Tests for FCS API endpoints.

This test suite covers the FCS parameters endpoint, including:
- Sample file access with various scopes
- Permission hierarchy validation
- Cross-resource isolation
- Error handling for unauthorized/forbidden requests
"""
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.pat import PersonalAccessToken
from app.services.pat import has_permission
from tests.constants import URLs


def _get_jwt(client) -> str:
    """Helper to register and login, returning JWT token."""
    client.post(
        URLs.REGISTER,
        json={"email": "fcs@example.com", "password": "Password123!"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": "fcs@example.com", "password": "Password123!"},
    )
    return response.json()["data"]["access_token"]


def _check_has_permission(db, scope_names, required_scope):
    """Helper to check permission using scope names instead of Scope objects."""
    from app.services.pat import get_scopes_by_names
    scopes = get_scopes_by_names(db, scope_names)
    return has_permission(db, scopes, required_scope)


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


def _get_jwt_with_email(client, email):
    """Register and login with specific email, return JWT token."""
    client.post(
        URLs.REGISTER,
        json={"email": email, "password": "Password123!"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": email, "password": "Password123!"},
    )
    return response.json()["data"]["access_token"]


# Success Tests - Sample File Access


def test_fcs_parameters_sample_file_with_fcs_read(client):
    """Test access with exact required scope (fcs:read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "data" in data
    assert data["data"]["total_events"] == 34297
    assert data["data"]["total_parameters"] == 26
    assert len(data["data"]["parameters"]) == 26


def test_fcs_parameters_sample_file_with_fcs_write(client):
    """Test access with fcs:write scope (higher than read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["total_parameters"] == 26


def test_fcs_parameters_sample_file_with_fcs_analyze(client):
    """Test access with fcs:analyze scope (highest level)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True


def test_fcs_parameters_first_parameter_structure(client):
    """Test that first parameter has correct structure."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    params = data["data"]["parameters"]

    # First parameter should be FSC-H based on requirements
    first_param = params[0]
    assert first_param["index"] == 1
    assert first_param["pnn"] == "FSC-H"
    assert first_param["pns"] == "FSC-H"
    assert first_param["range"] == 16777215
    assert first_param["display"] in ["LIN", "LOG"]


def test_fcs_parameters_all_required_fields(client):
    """Test that all parameters have required fields."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    params = data["data"]["parameters"]

    for param in params:
        assert "index" in param
        assert "pnn" in param
        assert "pns" in param
        assert "range" in param
        assert "display" in param
        assert isinstance(param["index"], int)
        assert isinstance(param["range"], int)


# Permission Denied Tests


def test_fcs_parameters_forbidden_without_fcs_scope(client):
    """Test 403 when required fcs scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read", "users:read"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "fcs:read"


def test_fcs_parameters_forbidden_workspaces_scope(client):
    """Test that workspaces scopes don't grant fcs access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403


def test_fcs_parameters_forbidden_users_scope(client):
    """Test that users scopes don't grant fcs access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403


# Unauthorized Tests


def test_fcs_parameters_unauthorized_no_token(client):
    """Test 401 when no token provided."""
    response = client.get(URLs.FCS_PARAMETERS)

    assert response.status_code == 401


def test_fcs_parameters_unauthorized_invalid_token(client):
    """Test 401 with invalid token."""
    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "Unauthorized"
    assert data["message"] == "Invalid token"


def test_fcs_parameters_unauthorized_jwt_instead_of_pat(client):
    """Test that JWT tokens are not accepted for this endpoint."""
    jwt = _get_jwt(client)

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    # JWT doesn't start with "pat_", so should be treated as invalid PAT
    assert response.status_code == 401


def test_fcs_parameters_unauthorized_non_pat_token(client):
    """Test that tokens not starting with 'pat_' are rejected."""
    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": "Bearer some_random_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["message"] == "Invalid token"


# Scope Hierarchy Tests


def test_fcs_scope_hierarchy_analyze_grants_read(client, db):
    """Verify fcs:analyze grants fcs:read access."""
    assert _check_has_permission(db, ["fcs:analyze"], "fcs:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_scope_hierarchy_write_grants_read(client, db):
    """Verify fcs:write grants fcs:read access."""
    assert _check_has_permission(db, ["fcs:write"], "fcs:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_scope_hierarchy_read_does_not_grant_write(db):
    """Verify fcs:read does NOT grant fcs:write access."""
    assert _check_has_permission(db, ["fcs:read"], "fcs:write") is False


def test_fcs_scope_hierarchy_write_does_not_grant_analyze(db):
    """Verify fcs:write does NOT grant fcs:analyze access."""
    assert _check_has_permission(db, ["fcs:write"], "fcs:analyze") is False


# Cross-Resource Isolation Tests


def test_fcs_no_cross_resource_workspaces_to_fcs(db):
    """Verify workspaces:admin does NOT grant fcs:read access."""
    assert _check_has_permission(db, ["workspaces:admin"], "fcs:read") is False


def test_fcs_no_cross_resource_users_to_fcs(db):
    """Verify users:write does NOT grant fcs:read access."""
    assert _check_has_permission(db, ["users:write"], "fcs:read") is False


def test_fcs_cross_resource_with_correct_scope(client):
    """Test that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read", "fcs:read"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


# Token State Tests


def test_fcs_parameters_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["success"] is False
    assert data["message"] == "Token revoked"


def test_fcs_parameters_unauthorized_expired_token(client, db):
    """Test 401 with expired token."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["fcs:read"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["success"] is False
    assert data["message"] == "Token expired"


# ========================================
# FCS Events Endpoint Tests
# ========================================


def test_fcs_events_sample_file_with_fcs_read(client):
    """Test access with exact required scope (fcs:read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["total_events"] == 34297
    assert data["data"]["limit"] == 100
    assert data["data"]["offset"] == 0
    assert len(data["data"]["events"]) == 100


def test_fcs_events_with_custom_limit(client):
    """Test pagination with custom limit."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?limit=50",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["limit"] == 50
    assert len(data["data"]["events"]) == 50


def test_fcs_events_with_offset(client):
    """Test pagination with offset."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?offset=100",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["offset"] == 100
    assert len(data["data"]["events"]) == 100


def test_fcs_events_with_limit_and_offset(client):
    """Test pagination with both limit and offset."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?limit=25&offset=200",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["limit"] == 25
    assert data["data"]["offset"] == 200
    assert len(data["data"]["events"]) == 25


def test_fcs_events_offset_beyond_total(client):
    """Test when offset exceeds total events."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?offset=100000",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["events"] == []


def test_fcs_events_first_event_structure(client):
    """Test that first event has correct structure."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    events = data["data"]["events"]
    first_event = events[0]

    # Check that expected parameter names exist
    expected_params = ["FSC-H", "FSC-A", "SSC-H", "SSC-A"]
    for param in expected_params:
        assert param in first_event

    # Check that values are numeric
    for value in first_event.values():
        assert isinstance(value, (int, float))


def test_fcs_events_all_events_have_same_parameters(client):
    """Test that all events have consistent parameter structure."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    events = data["data"]["events"]

    # Get parameter names from first event
    first_event_params = set(events[0].keys())

    # Verify all events have same parameters
    for event in events[1:]:
        assert set(event.keys()) == first_event_params


def test_fcs_events_forbidden_without_fcs_scope(client):
    """Test 403 when required fcs scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read", "users:read"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "fcs:read"


def test_fcs_events_unauthorized_no_token(client):
    """Test 401 when no token provided."""
    response = client.get(URLs.FCS_EVENTS)
    assert response.status_code == 401


def test_fcs_events_unauthorized_invalid_token(client):
    """Test 401 with invalid token."""
    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert response.status_code == 401


def test_fcs_events_with_fcs_write_scope(client):
    """Test access with fcs:write scope (higher than read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_events_with_fcs_analyze_scope(client):
    """Test access with fcs:analyze scope (highest level)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.get(
        URLs.FCS_EVENTS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_events_limit_max_value(client):
    """Test maximum limit value (10000)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?limit=10000",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_events_limit_exceeds_max(client):
    """Test that limit exceeding max is rejected."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?limit=10001",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 422  # Validation error


def test_fcs_events_negative_limit(client):
    """Test that negative limit is rejected."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?limit=-1",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 422


def test_fcs_events_negative_offset(client):
    """Test that negative offset is rejected."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        f"{URLs.FCS_EVENTS}?offset=-1",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 422


# ========================================
# FCS Upload Endpoint Tests
# ========================================


def test_fcs_upload_success_with_valid_fcs_file(client):
    """Test successful FCS file upload with chunked upload flow (fcs:write scope)."""
    import os
    import time
    from io import BytesIO

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])
    pat_analyze = _create_pat(client, jwt, ["fcs:analyze"], name="Analyze Token")

    # Read sample FCS file to get its size
    sample_fcs_path = "app/data/sample.fcs"
    file_size = os.path.getsize(sample_fcs_path)
    chunk_size = 5 * 1024 * 1024  # 5MB chunks

    # 1. Initialize chunked upload
    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )

    assert init_response.status_code == 201
    init_data = init_response.json()["data"]
    task_id = init_data["task_id"]
    total_chunks = init_data["total_chunks"]

    # 2. Upload all chunks
    with open(sample_fcs_path, "rb") as f:
        for chunk_num in range(total_chunks):
            chunk_data = f.read(chunk_size)
            chunk_file = BytesIO(chunk_data)

            response = client.post(
                "/api/v1/fcs/upload/chunk",
                headers={"Authorization": f"Bearer {pat}"},
                data={
                    "task_id": task_id,
                    "chunk_number": chunk_num,
                },
                files={"chunk": (f"chunk_{chunk_num}.dat", chunk_file, "application/octet-stream")},
            )

            assert response.status_code == 202

    # 3. The upload should auto-complete, check task status
    # Poll for completion (with timeout)
    max_wait = 10  # seconds
    start = time.time()

    while time.time() - start < max_wait:
        status_response = client.get(
            f"/api/v1/fcs/tasks/{task_id}",
            headers={"Authorization": f"Bearer {pat_analyze}"},
        )

        assert status_response.status_code == 200
        status_data = status_response.json()["data"]

        if status_data["status"] == "completed":
            # Verify the result
            assert "result" in status_data
            result = status_data["result"]
            assert "file_id" in result
            assert result["filename"] == "sample.fcs"
            assert result["total_events"] == 34297
            assert result["total_parameters"] == 26
            break

        time.sleep(0.5)
    else:
        pytest.fail("Upload did not complete within timeout period")


def test_fcs_upload_forbidden_without_fcs_write_scope(client):
    """Test 403 when trying to initialize upload without fcs:write scope."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read"])

    # Try to initialize chunked upload without fcs:write scope
    response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat}"},
        data={
            "filename": "sample.fcs",
            "file_size": 1048576,
            "chunk_size": 524288,
            "is_public": True,
        },
    )

    assert response.status_code == 403


def test_fcs_upload_rejects_non_fcs_file(client):
    """Test 400 when uploading non-.fcs file."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])

    # Try to initialize upload with wrong extension
    response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat}"},
        data={
            "filename": "test.txt",  # Wrong extension
            "file_size": 100,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "Invalid file type" in data["message"]


# ========================================
# FCS Statistics Endpoint Tests
# ========================================


def test_fcs_statistics_returns_404_when_not_calculated(client):
    """Test GET /statistics returns 404 when statistics not calculated yet."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    # Sample file statistics haven't been calculated yet
    response = client.get(
        URLs.FCS_STATISTICS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert "calculate" in data["message"]


def test_fcs_statistics_returns_202_when_calculation_in_progress(client, db):
    """Test GET /statistics returns 202 when calculation is in progress."""
    from app.models.background_task import BackgroundTask
    from app.models.user import User

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    # Get the actual user_id from the database
    user = db.query(User).filter_by(email="fcs@example.com").first()
    assert user is not None, "Test user should exist"

    # Create an in-progress task for sample file (fcs_file_id = NULL)
    task = BackgroundTask(
        task_type="statistics",
        fcs_file_id=None,  # NULL for sample file
        status="pending",
        user_id=user.id,  # Use actual user ID
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    # Get statistics - should return 202 with task info
    response = client.get(
        URLs.FCS_STATISTICS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 202  # Changed from 404
    data = response.json()
    assert data["success"] is True
    assert data["data"]["status"] == "pending"
    assert data["data"]["task_id"] == task.id
    assert "in progress" in data["data"]["message"].lower()

    # Clean up
    db.delete(task)
    db.commit()


def test_fcs_statistics_calculate_triggers_background_task(client):
    """Test POST /statistics/calculate triggers background task."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.post(
        URLs.FCS_STATISTICS_CALCULATE,
        headers={"Authorization": f"Bearer {pat}"},
        json={},  # Empty body = sample file
    )

    assert response.status_code == 202
    resp = response.json()
    assert resp["success"] is True
    data = response.json()["data"]
    assert "task_id" in data
    assert data["status"] == "pending"
    assert isinstance(data["task_id"], int)


def test_fcs_statistics_calculate_returns_cached_if_exists(client, db):
    """Test POST /statistics/calculate returns cached results if already calculated."""
    from app.models.background_task import BackgroundTask
    from app.models.fcs_statistics import FCSStatistics
    from app.services.fcs_statistics import calculate_fcs_statistics

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    # First, calculate statistics to populate cache
    sample_fcs_path = "app/data/sample.fcs"
    result = calculate_fcs_statistics(sample_fcs_path)

    # Manually populate cache
    stats_record = FCSStatistics(
        file_id="sample",
        fcs_file_id=None,
        statistics=result.statistics,
        total_events=result.total_events,
    )
    db.add(stats_record)
    db.commit()

    # Now call calculate API - should return cached results
    response = client.post(
        URLs.FCS_STATISTICS_CALCULATE,
        headers={"Authorization": f"Bearer {pat}"},
        json={},
    )

    assert response.status_code == 202
    resp = response.json()
    assert resp["success"] is True
    data = response.json()["data"]
    assert data["status"] == "completed"
    assert data["result"]["total_events"] == 34297
    assert len(data["result"]["statistics"]) == 26

    # Clean up
    db.delete(stats_record)
    db.commit()


# ========================================
# Task Status Endpoint Tests
# ========================================


def test_fcs_task_status_returns_404_for_invalid_task(client):
    """Test GET /tasks/{id} returns 404 for non-existent task."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.get(
        f"{URLs.FCS_TASKS}/999",
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 404


# ========================================
# Scope Hierarchy for Statistics
# ========================================


def test_fcs_statistics_requires_analyze_scope(client, db):
    """Test that fcs:analyze scope is required (not just read)."""
    from app.services.pat import has_permission

    # fcs:read should NOT grant fcs:analyze access
    assert _check_has_permission(db, ["fcs:read"], "fcs:analyze") is False


def test_fcs_analyze_grants_statistics_access(client):
    """Test that fcs:analyze grants access to statistics endpoints."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    # Should be able to trigger calculation
    response = client.post(
        URLs.FCS_STATISTICS_CALCULATE,
        headers={"Authorization": f"Bearer {pat}"},
        json={},
    )

    assert response.status_code == 202


# ========================================
# Dynamic Scope Tests for Task Status
# ========================================


def test_task_status_chunked_upload_requires_fcs_write(client, db):
    """Test that chunked_upload tasks require fcs:write scope."""
    jwt = _get_jwt(client)

    # Create PATs with different scopes
    pat_read = _create_pat(client, jwt, ["fcs:read"], name="Read Token")
    pat_write = _create_pat(client, jwt, ["fcs:write"], name="Write Token")

    # Create a chunked_upload task via API
    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test.fcs",
            "file_size": 10485760,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    task_id = init_response.json()["data"]["task_id"]

    # Test with fcs:read (should fail)
    response = client.get(
        URLs.FCS_TASKS.format(task_id),
        headers={"Authorization": f"Bearer {pat_read}"},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["data"]["required_scope"] == "fcs:write"

    # Test with fcs:write (should succeed)
    response = client.get(
        URLs.FCS_TASKS.format(task_id),
        headers={"Authorization": f"Bearer {pat_write}"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["task_type"] == "chunked_upload"


def test_task_status_statistics_requires_fcs_analyze(client, db):
    """Test that statistics tasks require fcs:analyze scope."""
    jwt = _get_jwt(client)

    # Create PATs with different scopes
    pat_write = _create_pat(client, jwt, ["fcs:write"], name="Write Token")
    pat_analyze = _create_pat(client, jwt, ["fcs:analyze"], name="Analyze Token")

    # Create a statistics task via API
    calc_response = client.post(
        URLs.FCS_STATISTICS_CALCULATE,
        headers={"Authorization": f"Bearer {pat_analyze}"},
        json={},  # Empty body = sample file
    )
    task_id = calc_response.json()["data"]["task_id"]

    # Test with fcs:write (should fail - write < analyze)
    response = client.get(
        URLs.FCS_TASKS.format(task_id),
        headers={"Authorization": f"Bearer {pat_write}"},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["data"]["required_scope"] == "fcs:analyze"

    # Test with fcs:analyze (should succeed)
    response = client.get(
        URLs.FCS_TASKS.format(task_id),
        headers={"Authorization": f"Bearer {pat_analyze}"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["task_type"] == "statistics"


def test_task_status_scope_inheritance_works(client, db):
    """Test that higher scopes grant access (analyze grants write access)."""
    jwt = _get_jwt(client)

    # Create PAT with fcs:analyze
    pat_analyze = _create_pat(client, jwt, ["fcs:analyze"], name="Analyze Token")

    # Create chunked_upload task via API
    upload_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_analyze}"},
        data={
            "filename": "test.fcs",
            "file_size": 10485760,
            "chunk_size": 5242880,
            "is_public": True,
        },
    )
    upload_task_id = upload_response.json()["data"]["task_id"]

    # Create statistics task via API
    stats_response = client.post(
        URLs.FCS_STATISTICS_CALCULATE,
        headers={"Authorization": f"Bearer {pat_analyze}"},
        json={},
    )
    stats_task_id = stats_response.json()["data"]["task_id"]

    # fcs:analyze should grant access to both
    response1 = client.get(
        URLs.FCS_TASKS.format(upload_task_id),
        headers={"Authorization": f"Bearer {pat_analyze}"},
    )
    assert response1.status_code == 200

    response2 = client.get(
        URLs.FCS_TASKS.format(stats_task_id),
        headers={"Authorization": f"Bearer {pat_analyze}"},
    )
    assert response2.status_code == 200


# ========================================
# Private File Access Control Tests
# ========================================


def _upload_fcs_file_and_wait(client, pat_write, filename, is_public):
    """Helper to upload FCS file via chunked upload and wait for completion.

    Returns the file_id from the completed upload.
    """
    import os
    import time
    from io import BytesIO

    sample_fcs_path = "app/data/sample.fcs"
    file_size = os.path.getsize(sample_fcs_path)
    chunk_size = 5 * 1024 * 1024  # 5MB

    # 1. Initialize chunked upload
    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": filename,
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": is_public,
        },
    )

    assert init_response.status_code == 201
    init_data = init_response.json()["data"]
    task_id = init_data["task_id"]
    total_chunks = init_data["total_chunks"]

    # 2. Upload all chunks
    with open(sample_fcs_path, "rb") as f:
        for chunk_num in range(total_chunks):
            chunk_data = f.read(chunk_size)
            chunk_file = BytesIO(chunk_data)

            response = client.post(
                "/api/v1/fcs/upload/chunk",
                headers={"Authorization": f"Bearer {pat_write}"},
                data={
                    "task_id": task_id,
                    "chunk_number": chunk_num,
                },
                files={"chunk": (f"chunk_{chunk_num}.dat", chunk_file, "application/octet-stream")},
            )

            assert response.status_code == 202

    # 3. Wait for upload completion
    max_wait = 10  # seconds
    start = time.time()
    file_id = None

    while time.time() - start < max_wait:
        status_response = client.get(
            f"/api/v1/fcs/tasks/{task_id}",
            headers={"Authorization": f"Bearer {pat_write}"},
        )

        assert status_response.status_code == 200
        status_data = status_response.json()["data"]

        if status_data["status"] == "completed":
            assert "result" in status_data
            result = status_data["result"]
            file_id = result["file_id"]
            break

        time.sleep(0.5)
    else:
        pytest.fail("Upload did not complete within timeout period")

    return file_id


def test_public_file_accessible_by_other_user(client):
    """Public files can be accessed by any user with fcs:read scope."""
    # User 1: Upload public file
    jwt1 = _get_jwt_with_email(client, "user1_public@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")
    pat1_read = _create_pat(client, jwt1, ["fcs:read"], name="User1 Read Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "public_test.fcs", is_public=True)

    # User 2: Should be able to access the public file
    jwt2 = _get_jwt_with_email(client, "user2_public@example.com")
    pat2_read = _create_pat(client, jwt2, ["fcs:read"], name="User2 Read Token")

    response = client.get(
        f"{URLs.FCS_PARAMETERS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat2_read}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "data" in data


def test_private_file_owner_can_access(client):
    """Private file owner can access their own files."""
    # User 1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1_private@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")
    pat1_read = _create_pat(client, jwt1, ["fcs:read"], name="User1 Read Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "private_test.fcs", is_public=False)

    # User 1 (owner): Should access successfully
    response = client.get(
        f"{URLs.FCS_PARAMETERS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat1_read}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "data" in data


def test_private_file_non_owner_denied_403(client):
    """Non-owners get 403 when accessing private files."""
    # User 1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1_private2@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "private_test2.fcs", is_public=False)

    # User 2 (non-owner): Should be denied with 403
    jwt2 = _get_jwt_with_email(client, "user2_private2@example.com")
    pat2_read = _create_pat(client, jwt2, ["fcs:read"], name="User2 Read Token")

    response = client.get(
        f"{URLs.FCS_PARAMETERS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat2_read}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["success"] is False
    assert "Private file - access denied" in data["message"]


def test_private_file_access_control_parameters_endpoint(client):
    """Full integration test for parameters endpoint with private file."""
    # User 1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1_params@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")
    pat1_read = _create_pat(client, jwt1, ["fcs:read"], name="User1 Read Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "private_params.fcs", is_public=False)

    # User 1 (owner): Should access successfully
    response = client.get(
        f"{URLs.FCS_PARAMETERS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat1_read}"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["total_parameters"] == 26

    # User 2 (non-owner): Should be denied with 403
    jwt2 = _get_jwt_with_email(client, "user2_params@example.com")
    pat2_read = _create_pat(client, jwt2, ["fcs:read"], name="User2 Read Token")

    response = client.get(
        f"{URLs.FCS_PARAMETERS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat2_read}"},
    )
    assert response.status_code == 403
    assert "Private file - access denied" in response.json()["message"]


def test_private_file_access_control_events_endpoint(client):
    """Full integration test for events endpoint with private file."""
    # User 1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1_events@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")
    pat1_read = _create_pat(client, jwt1, ["fcs:read"], name="User1 Read Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "private_events.fcs", is_public=False)

    # User 1 (owner): Should access successfully
    response = client.get(
        f"{URLs.FCS_EVENTS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat1_read}"},
    )
    assert response.status_code == 200
    assert len(response.json()["data"]["events"]) > 0

    # User 2 (non-owner): Should be denied with 403
    jwt2 = _get_jwt_with_email(client, "user2_events@example.com")
    pat2_read = _create_pat(client, jwt2, ["fcs:read"], name="User2 Read Token")

    response = client.get(
        f"{URLs.FCS_EVENTS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat2_read}"},
    )
    assert response.status_code == 403
    assert "Private file - access denied" in response.json()["message"]


def test_private_file_access_control_statistics_endpoint(client, db):
    """Full integration test for statistics endpoint with private file."""
    from app.models.fcs_statistics import FCSStatistics
    from app.services.fcs_statistics import calculate_fcs_statistics

    # User 1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1_stats@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"], name="User1 Write Token")
    pat1_analyze = _create_pat(client, jwt1, ["fcs:analyze"], name="User1 Analyze Token")

    file_id = _upload_fcs_file_and_wait(client, pat1_write, "private_stats.fcs", is_public=False)

    # Manually calculate statistics to populate cache (bypassing background task)
    from app.models.fcs_file import FCSFile

    fcs_file = db.query(FCSFile).filter(FCSFile.file_id == file_id).first()
    assert fcs_file is not None

    result = calculate_fcs_statistics(fcs_file.file_path)

    # Populate cache
    stats_record = FCSStatistics(
        file_id=file_id,
        fcs_file_id=fcs_file.id,
        statistics=result.statistics,
        total_events=result.total_events,
    )
    db.add(stats_record)
    db.commit()

    # User 1 (owner): Should access statistics successfully
    response = client.get(
        f"{URLs.FCS_STATISTICS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat1_analyze}"},
    )
    assert response.status_code == 200
    assert "data" in response.json()

    # User 2 (non-owner): Should be denied with 403
    jwt2 = _get_jwt_with_email(client, "user2_stats@example.com")
    pat2_analyze = _create_pat(client, jwt2, ["fcs:analyze"], name="User2 Analyze Token")

    response = client.get(
        f"{URLs.FCS_STATISTICS}?file_id={file_id}",
        headers={"Authorization": f"Bearer {pat2_analyze}"},
    )
    assert response.status_code == 403
    assert "Private file - access denied" in response.json()["message"]


# ========================================
# Chunk Size Validation Tests
# ========================================


def test_chunk_oversized_rejected(client, db):
    """Test that oversized chunks are rejected with 400 error."""
    from app.models.background_task import BackgroundTask

    jwt = _get_jwt(client)
    pat_write = _create_pat(client, jwt, ["fcs:write"])

    # Initialize upload with 1MB chunk_size
    file_size = 3 * 1024 * 1024  # 3MB
    chunk_size = 1 * 1024 * 1024  # 1MB

    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )
    assert init_response.status_code == 201
    task_id = init_response.json()["data"]["task_id"]

    # Create oversized chunk (2MB instead of 1MB)
    oversized_chunk = b"FCS" + b"\x00" * 10 + b"\x00\x00\x00\x00" + b"x" * (2 * 1024 * 1024 - 18)

    from io import BytesIO

    chunk_file = BytesIO(oversized_chunk)

    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk.fcs", chunk_file, "application/octet-stream")},
    )

    # Debug: print response if test fails
    if response.status_code != 400:
        print(f"Response status: {response.status_code}")
        print(f"Response data: {response.json()}")

    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "size mismatch" in data["message"].lower()
    assert f"Expected {chunk_size}" in data["message"]


def test_chunk_undersized_rejected(client, db):
    """Test that undersized chunks are rejected (except last chunk)."""
    from io import BytesIO

    jwt = _get_jwt(client)
    pat_write = _create_pat(client, jwt, ["fcs:write"])

    # Initialize upload with 1MB chunk_size
    file_size = 3 * 1024 * 1024  # 3MB (exactly 3 chunks)
    chunk_size = 1 * 1024 * 1024  # 1MB

    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )
    assert init_response.status_code == 201
    task_id = init_response.json()["data"]["task_id"]

    # Create undersized chunk (500KB instead of 1MB)
    undersized_chunk = b"FCS" + b"\x00" * 10 + b"\x00\x00\x00\x00" + b"x" * (500 * 1024 - 18)
    chunk_file = BytesIO(undersized_chunk)

    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,  # First chunk, should be full size
        },
        files={"chunk": ("chunk.fcs", chunk_file, "application/octet-stream")},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "size mismatch" in data["message"].lower()


def test_last_chunk_can_be_smaller(client, db):
    """Test that the last chunk can be smaller than chunk_size."""
    from io import BytesIO

    jwt = _get_jwt(client)
    pat_write = _create_pat(client, jwt, ["fcs:write"])

    # Initialize upload where last chunk is smaller
    # Use a file_size that will have exactly 3 chunks with the last one smaller
    file_size = 2 * 1024 * 1024 + 500 * 1024  # 2.5MB
    chunk_size = 1 * 1024 * 1024  # 1MB

    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )
    assert init_response.status_code == 201
    task_id = init_response.json()["data"]["task_id"]
    total_chunks = init_response.json()["data"]["total_chunks"]

    assert total_chunks == 3  # 2 full chunks + 1 partial

    # Upload first chunk (full size)
    chunk_data = b"FCS" + b"\x00" * 100  # Simple FCS header
    chunk_data += b"x" * (chunk_size - len(chunk_data))
    chunk_file = BytesIO(chunk_data)

    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk0.fcs", chunk_file, "application/octet-stream")},
    )
    assert response.status_code == 202

    # Upload last chunk (smaller than chunk_size)
    # Note: We're skipping chunk 1 to avoid triggering auto-completion
    last_chunk_size = 500 * 1024
    last_chunk = b"FCS" + b"\x00" * 100
    last_chunk += b"x" * (last_chunk_size - len(last_chunk))
    last_chunk_file = BytesIO(last_chunk)

    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 2,  # Last chunk (skip chunk 1)
        },
        files={"chunk": ("chunk2.fcs", last_chunk_file, "application/octet-stream")},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["data"]["uploaded_chunks"] == 2
    # Verify the smaller chunk was accepted


def test_chunk_offset_calculation(client, db):
    """Test that chunks are written at correct offsets."""
    import time
    from app.models.background_task import BackgroundTask
    from app.storage.local import LocalStorageBackend
    from app.config import settings
    from io import BytesIO

    jwt = _get_jwt(client)
    pat_write = _create_pat(client, jwt, ["fcs:write"])

    # Initialize upload
    file_size = 3 * 1024 * 1024  # 3MB (3 chunks, we'll only upload 2 to avoid completion)
    chunk_size = 1 * 1024 * 1024  # 1MB

    init_response = client.post(
        URLs.FCS_UPLOAD,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )
    assert init_response.status_code == 201
    task_id = init_response.json()["data"]["task_id"]

    # Create two distinct chunks with different patterns
    chunk0_data = b"FCS" + b"\x00" * 100 + b"A" * (chunk_size - 103)
    chunk1_data = b"FCS" + b"\x00" * 100 + b"B" * (chunk_size - 103)

    # Upload chunk 0
    chunk0_file = BytesIO(chunk0_data)
    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 0,
        },
        files={"chunk": ("chunk0.fcs", chunk0_file, "application/octet-stream")},
    )
    assert response.status_code == 202

    # Upload chunk 1 (skip chunk 2 to avoid auto-completion)
    chunk1_file = BytesIO(chunk1_data)
    response = client.post(
        URLs.FCS_UPLOAD_CHUNK,
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "task_id": task_id,
            "chunk_number": 1,
        },
        files={"chunk": ("chunk1.fcs", chunk1_file, "application/octet-stream")},
    )
    assert response.status_code == 202

    # Verify offsets by reading temp file
    storage = LocalStorageBackend(settings.STORAGE_BASE_PATH)
    temp_path = storage._get_temp_file_path(str(task_id), "")

    import aiofiles
    import asyncio

    async def verify_offsets():
        async with aiofiles.open(temp_path, 'rb') as f:
            # Read first chunk (offset 0)
            await f.seek(0)
            chunk0_read = await f.read(chunk_size)
            assert chunk0_read == chunk0_data, "Chunk 0 data mismatch"

            # Read second chunk (offset chunk_size)
            await f.seek(chunk_size)
            chunk1_read = await f.read(chunk_size)
            assert chunk1_read == chunk1_data, "Chunk 1 data mismatch"

    asyncio.run(verify_offsets())

