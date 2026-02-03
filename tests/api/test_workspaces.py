"""
Tests for workspaces stub endpoint.

This test suite covers the PAT-based authorization for the workspaces endpoint,
including scope hierarchy, permission checks, and error handling.
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
        json={"email": "workspace@example.com", "password": "password123"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": "workspace@example.com", "password": "password123"},
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


# Success Tests


def test_workspaces_success_with_exact_scope(client):
    """Test access with exact required scope (workspaces:read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/workspaces"
    assert data["data"]["method"] == "GET"
    assert data["data"]["required_scope"] == "workspaces:read"
    assert data["data"]["granted_by"] == "workspaces:read"
    assert data["data"]["your_scopes"] == ["workspaces:read"]


def test_workspaces_success_with_write_scope(client):
    """Test access with workspaces:write scope (higher than read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:write"
    assert data["data"]["your_scopes"] == ["workspaces:write"]


def test_workspaces_success_with_delete_scope(client):
    """Test access with workspaces:delete scope (higher than read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:delete"


def test_workspaces_success_with_admin_scope(client):
    """Test access with workspaces:admin scope (highest level)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_success_with_multiple_scopes(client):
    """Test access with multiple scopes including valid one."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:write", "users:read"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:write", "users:read"}


def test_workspaces_success_highest_scope_wins(client):
    """Test that highest granting scope is returned when multiple apply."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read", "workspaces:admin"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["granted_by"] == "workspaces:admin"


# Permission Denied Tests


def test_workspaces_forbidden_missing_scope(client):
    """Test 403 when required scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "users:read"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:read"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:read"}


def test_workspaces_forbidden_different_resource(client):
    """Test that scopes from different resources don't grant access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["data"]["required_scope"] == "workspaces:read"


# Unauthorized Tests


def test_workspaces_unauthorized_no_token(client):
    """Test 401 when no token provided."""
    response = client.get(URLs.WORKSPACES)

    assert response.status_code == 401


def test_workspaces_unauthorized_invalid_token(client):
    """Test 401 with invalid token."""
    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_workspaces_unauthorized_expired_token(client, db):
    """Test 401 with expired token."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["workspaces:read"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_workspaces_unauthorized_jwt_instead_of_pat(client):
    """Test that JWT tokens are not accepted for this endpoint."""
    jwt = _get_jwt(client)

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    # JWT doesn't start with "pat_", so should be treated as invalid PAT
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_unauthorized_non_pat_token(client):
    """Test that tokens not starting with 'pat_' are rejected."""
    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": "Bearer some_random_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["message"] == "Invalid token"


# Scope Hierarchy Tests


def test_workspaces_scope_hierarchy_admin_grants_read(client, db):
    """Verify workspaces:admin grants workspaces:read access."""
    assert has_permission(db, ["workspaces:admin"], "workspaces:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_scope_hierarchy_delete_grants_read(client, db):
    """Verify workspaces:delete grants workspaces:read access."""
    assert has_permission(db, ["workspaces:delete"], "workspaces:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:delete"


def test_workspaces_scope_hierarchy_write_grants_read(client, db):
    """Verify workspaces:write grants workspaces:read access."""
    assert has_permission(db, ["workspaces:write"], "workspaces:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:write"


def test_workspaces_scope_hierarchy_read_does_not_grant_write(db):
    """Verify workspaces:read does NOT grant workspaces:write access."""
    assert has_permission(db, ["workspaces:read"], "workspaces:write") is False


def test_workspaces_scope_hierarchy_write_does_not_grant_delete(db):
    """Verify workspaces:write does NOT grant workspaces:delete access."""
    assert has_permission(db, ["workspaces:write"], "workspaces:delete") is False


def test_workspaces_scope_hierarchy_delete_does_not_grant_admin(db):
    """Verify workspaces:delete does NOT grant workspaces:admin access."""
    assert has_permission(db, ["workspaces:delete"], "workspaces:admin") is False


# Cross-Resource Isolation Tests


def test_workspaces_no_cross_resource_fcs_to_workspaces(db):
    """Verify fcs:analyze does NOT grant workspaces:read access."""
    assert has_permission(db, ["fcs:analyze"], "workspaces:read") is False


def test_workspaces_no_cross_resource_workspaces_to_fcs(db):
    """Verify workspaces:admin does NOT grant fcs:read access."""
    assert has_permission(db, ["workspaces:admin"], "fcs:read") is False


def test_workspaces_no_cross_resource_users_to_workspaces(db):
    """Verify users:admin does NOT grant workspaces:read access."""
    assert has_permission(db, ["users:admin"], "workspaces:read") is False


def test_workspaces_cross_resource_multiple_scopes(client):
    """Test that having multiple resource scopes requires correct resource."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403


def test_workspaces_cross_resource_with_correct_scope(client):
    """Test that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:read"])

    response = client.get(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


# POST Endpoint Tests


def test_workspaces_post_success_with_exact_scope(client):
    """Test POST access with exact required scope (workspaces:write)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/workspaces"
    assert data["data"]["method"] == "POST"
    assert data["data"]["required_scope"] == "workspaces:write"
    assert data["data"]["granted_by"] == "workspaces:write"
    assert data["data"]["your_scopes"] == ["workspaces:write"]


def test_workspaces_post_success_with_delete_scope(client):
    """Test POST access with workspaces:delete scope (higher than write)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:delete"
    assert data["data"]["your_scopes"] == ["workspaces:delete"]


def test_workspaces_post_success_with_admin_scope(client):
    """Test POST access with workspaces:admin scope (highest level)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_post_success_with_multiple_scopes(client):
    """Test POST access with multiple scopes including valid one."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:write", "users:read"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:write", "users:read"}


def test_workspaces_post_success_highest_scope_wins(client):
    """Test that highest granting scope is returned when multiple apply."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write", "workspaces:admin"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_post_forbidden_read_scope_only(client):
    """Test 403 when only having workspaces:read scope (insufficient for POST)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:write"
    assert data["data"]["your_scopes"] == ["workspaces:read"]


def test_workspaces_post_forbidden_missing_scope(client):
    """Test 403 when required workspaces scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "users:read"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:read"}


def test_workspaces_post_forbidden_different_resource(client):
    """Test that scopes from different resources don't grant POST access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["data"]["required_scope"] == "workspaces:write"


def test_workspaces_post_unauthorized_no_token(client):
    """Test 401 when no token provided for POST."""
    response = client.post(URLs.WORKSPACES)

    assert response.status_code == 401


def test_workspaces_post_unauthorized_invalid_token(client):
    """Test 401 with invalid token for POST."""
    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_post_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token for POST."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_workspaces_post_unauthorized_expired_token(client, db):
    """Test 401 with expired token for POST."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["workspaces:write"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_workspaces_post_scope_hierarchy_admin_grants_write(client, db):
    """Verify workspaces:admin grants workspaces:write access."""
    assert has_permission(db, ["workspaces:admin"], "workspaces:write") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_post_scope_hierarchy_delete_grants_write(client, db):
    """Verify workspaces:delete grants workspaces:write access."""
    assert has_permission(db, ["workspaces:delete"], "workspaces:write") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:delete"


def test_workspaces_post_scope_hierarchy_write_does_not_grant_delete(db):
    """Verify workspaces:write does NOT grant workspaces:delete access."""
    assert has_permission(db, ["workspaces:write"], "workspaces:delete") is False


def test_workspaces_post_scope_hierarchy_read_does_not_grant_write(db):
    """Verify workspaces:read does NOT grant workspaces:write access."""
    assert has_permission(db, ["workspaces:read"], "workspaces:write") is False


def test_workspaces_post_cross_resource_with_correct_scope(client):
    """Test POST that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:write"])

    response = client.post(
        URLs.WORKSPACES,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


# DELETE Endpoint Tests


def test_workspaces_delete_success_with_exact_scope(client):
    """Test DELETE access with exact required scope (workspaces:delete)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("123"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/workspaces/123"
    assert data["data"]["method"] == "DELETE"
    assert data["data"]["required_scope"] == "workspaces:delete"
    assert data["data"]["granted_by"] == "workspaces:delete"
    assert data["data"]["your_scopes"] == ["workspaces:delete"]


def test_workspaces_delete_success_with_admin_scope(client):
    """Test DELETE access with workspaces:admin scope (higher than delete)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("456"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_delete_success_with_multiple_scopes(client):
    """Test DELETE access with multiple scopes including valid one."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:delete", "users:read"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("789"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:delete"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:delete", "users:read"}


def test_workspaces_delete_success_highest_scope_wins(client):
    """Test that highest granting scope is returned when multiple apply."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete", "workspaces:admin"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("999"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_delete_forbidden_read_scope_only(client):
    """Test 403 when only having workspaces:read scope (insufficient for DELETE)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("1"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:delete"
    assert data["data"]["your_scopes"] == ["workspaces:read"]


def test_workspaces_delete_forbidden_write_scope_only(client):
    """Test 403 when only having workspaces:write scope (insufficient for DELETE)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("2"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:delete"
    assert data["data"]["your_scopes"] == ["workspaces:write"]


def test_workspaces_delete_forbidden_missing_scope(client):
    """Test 403 when required workspaces scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "users:read"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("3"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:delete"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:read"}


def test_workspaces_delete_forbidden_different_resource(client):
    """Test that scopes from different resources don't grant DELETE access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("4"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["data"]["required_scope"] == "workspaces:delete"


def test_workspaces_delete_unauthorized_no_token(client):
    """Test 401 when no token provided for DELETE."""
    response = client.delete(URLs.WORKSPACES_DELETE.format("5"))

    assert response.status_code == 401


def test_workspaces_delete_unauthorized_invalid_token(client):
    """Test 401 with invalid token for DELETE."""
    response = client.delete(
        URLs.WORKSPACES_DELETE.format("6"),
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_delete_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token for DELETE."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("7"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_workspaces_delete_unauthorized_expired_token(client, db):
    """Test 401 with expired token for DELETE."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["workspaces:delete"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("8"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_workspaces_delete_scope_hierarchy_admin_grants_delete(client, db):
    """Verify workspaces:admin grants workspaces:delete access."""
    assert has_permission(db, ["workspaces:admin"], "workspaces:delete") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("9"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_delete_scope_hierarchy_delete_does_not_grant_admin(db):
    """Verify workspaces:delete does NOT grant workspaces:admin access."""
    assert has_permission(db, ["workspaces:delete"], "workspaces:admin") is False


def test_workspaces_delete_no_cross_resource_fcs_to_workspaces(db):
    """Verify fcs:analyze does NOT grant workspaces:delete access."""
    assert has_permission(db, ["fcs:analyze"], "workspaces:delete") is False


def test_workspaces_delete_cross_resource_with_correct_scope(client):
    """Test DELETE that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:delete"])

    response = client.delete(
        URLs.WORKSPACES_DELETE.format("10"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


# PUT Settings Endpoint Tests


def test_workspaces_settings_success_with_exact_scope(client):
    """Test PUT access with exact required scope (workspaces:admin)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("123"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/workspaces/123/settings"
    assert data["data"]["method"] == "PUT"
    assert data["data"]["required_scope"] == "workspaces:admin"
    assert data["data"]["granted_by"] == "workspaces:admin"
    assert data["data"]["your_scopes"] == ["workspaces:admin"]


def test_workspaces_settings_success_with_multiple_scopes(client):
    """Test PUT access with multiple scopes including admin."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:admin", "users:write"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("456"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "workspaces:admin"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:admin", "users:write"}


def test_workspaces_settings_success_highest_scope_wins(client):
    """Test that admin is returned when multiple workspaces scopes apply."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin", "workspaces:delete"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("789"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_settings_scope_hierarchy_only_admin_grants_access(client, db):
    """Verify only workspaces:admin grants access to settings endpoint."""
    assert has_permission(db, ["workspaces:read"], "workspaces:admin") is False
    assert has_permission(db, ["workspaces:write"], "workspaces:admin") is False
    assert has_permission(db, ["workspaces:delete"], "workspaces:admin") is False
    assert has_permission(db, ["workspaces:admin"], "workspaces:admin") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("999"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "workspaces:admin"


def test_workspaces_settings_forbidden_read_scope_only(client):
    """Test 403 when only having workspaces:read scope (insufficient for settings)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:read"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("1"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:admin"
    assert data["data"]["your_scopes"] == ["workspaces:read"]


def test_workspaces_settings_forbidden_write_scope_only(client):
    """Test 403 when only having workspaces:write scope (insufficient for settings)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:write"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("2"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:admin"
    assert data["data"]["your_scopes"] == ["workspaces:write"]


def test_workspaces_settings_forbidden_delete_scope_only(client):
    """Test 403 when only having workspaces:delete scope (insufficient for settings)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:delete"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("3"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:admin"
    assert data["data"]["your_scopes"] == ["workspaces:delete"]


def test_workspaces_settings_forbidden_missing_scope(client):
    """Test 403 when required workspaces scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "users:read"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("4"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "workspaces:admin"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:read"}


def test_workspaces_settings_forbidden_different_resource(client):
    """Test that scopes from different resources don't grant PUT settings access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("5"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["data"]["required_scope"] == "workspaces:admin"


def test_workspaces_settings_unauthorized_no_token(client):
    """Test 401 when no token provided for PUT settings."""
    response = client.put(URLs.WORKSPACES_SETTINGS.format("6"))

    assert response.status_code == 401


def test_workspaces_settings_unauthorized_invalid_token(client):
    """Test 401 with invalid token for PUT settings."""
    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("7"),
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_settings_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token for PUT settings."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["workspaces:admin"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("8"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_workspaces_settings_unauthorized_expired_token(client, db):
    """Test 401 with expired token for PUT settings."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["workspaces:admin"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("9"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_workspaces_settings_unauthorized_jwt_instead_of_pat(client):
    """Test that JWT tokens are not accepted for the settings endpoint."""
    jwt = _get_jwt(client)

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("10"),
        headers={"Authorization": f"Bearer {jwt}"},
    )

    # JWT doesn't start with "pat_", so should be treated as invalid PAT
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_settings_unauthorized_non_pat_token(client):
    """Test that tokens not starting with 'pat_' are rejected."""
    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("11"),
        headers={"Authorization": "Bearer some_random_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["message"] == "Invalid token"


def test_workspaces_settings_no_cross_resource(db):
    """Verify fcs:analyze does NOT grant workspaces:admin access."""
    assert has_permission(db, ["fcs:analyze"], "workspaces:admin") is False


def test_workspaces_settings_cross_resource_with_correct_scope(client):
    """Test PUT settings that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:admin"])

    response = client.put(
        URLs.WORKSPACES_SETTINGS.format("12"),
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


def test_workspaces_settings_scope_hierarchy_read_does_not_grant_admin(db):
    """Verify workspaces:read does NOT grant workspaces:admin access."""
    assert has_permission(db, ["workspaces:read"], "workspaces:admin") is False


def test_workspaces_settings_scope_hierarchy_write_does_not_grant_admin(db):
    """Verify workspaces:write does NOT grant workspaces:admin access."""
    assert has_permission(db, ["workspaces:write"], "workspaces:admin") is False


def test_workspaces_settings_scope_hierarchy_delete_does_not_grant_admin(db):
    """Verify workspaces:delete does NOT grant workspaces:admin access."""
    assert has_permission(db, ["workspaces:delete"], "workspaces:admin") is False
