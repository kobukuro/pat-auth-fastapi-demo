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
        json={"email": "fcs@example.com", "password": "password123"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": "fcs@example.com", "password": "password123"},
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
    data = response.json()["detail"]
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
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


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
    assert data["detail"]["message"] == "Invalid token"


# Scope Hierarchy Tests


def test_fcs_scope_hierarchy_analyze_grants_read(client, db):
    """Verify fcs:analyze grants fcs:read access."""
    assert has_permission(db, ["fcs:analyze"], "fcs:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_scope_hierarchy_write_grants_read(client, db):
    """Verify fcs:write grants fcs:read access."""
    assert has_permission(db, ["fcs:write"], "fcs:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:write"])

    response = client.get(
        URLs.FCS_PARAMETERS,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_fcs_scope_hierarchy_read_does_not_grant_write(db):
    """Verify fcs:read does NOT grant fcs:write access."""
    assert has_permission(db, ["fcs:read"], "fcs:write") is False


def test_fcs_scope_hierarchy_write_does_not_grant_analyze(db):
    """Verify fcs:write does NOT grant fcs:analyze access."""
    assert has_permission(db, ["fcs:write"], "fcs:analyze") is False


# Cross-Resource Isolation Tests


def test_fcs_no_cross_resource_workspaces_to_fcs(db):
    """Verify workspaces:admin does NOT grant fcs:read access."""
    assert has_permission(db, ["workspaces:admin"], "fcs:read") is False


def test_fcs_no_cross_resource_users_to_fcs(db):
    """Verify users:write does NOT grant fcs:read access."""
    assert has_permission(db, ["users:write"], "fcs:read") is False


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
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


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
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


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
    data = response.json()["detail"]
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


# Reserved tests for future file upload functionality
# These will be implemented when POST /api/v1/fcs/upload is added

# def test_fcs_parameters_uploaded_public_file(client):
#     """Test accessing a public uploaded file."""
#     pass

# def test_fcs_parameters_uploaded_private_file_owner(client):
#     """Test file owner accessing their private file."""
#     pass

# def test_fcs_parameters_uploaded_private_file_forbidden(client):
#     """Test non-owner cannot access private file."""
#     pass
