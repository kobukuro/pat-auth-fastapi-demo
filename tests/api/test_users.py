"""
Tests for users stub endpoint.

This test suite covers the PAT-based authorization for the users endpoint,
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
        json={"email": "user@example.com", "password": "Password123!"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"email": "user@example.com", "password": "Password123!"},
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


def test_users_me_success_with_exact_scope(client):
    """Test access with exact required scope (users:read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:read"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/users/me"
    assert data["data"]["method"] == "GET"
    assert data["data"]["required_scope"] == "users:read"
    assert data["data"]["granted_by"] == "users:read"
    assert data["data"]["your_scopes"] == ["users:read"]


def test_users_me_success_with_write_scope(client):
    """Test access with users:write scope (higher than read)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "users:write"
    assert data["data"]["your_scopes"] == ["users:write"]


def test_users_me_success_with_multiple_scopes(client):
    """Test access with multiple scopes including valid one."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "users:write", "workspaces:read"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "users:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:write", "workspaces:read"}


def test_users_me_success_highest_scope_wins(client):
    """Test that highest granting scope is returned when multiple apply."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:read", "users:write"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["data"]["granted_by"] == "users:write"


# Permission Denied Tests


def test_users_me_forbidden_missing_scope(client):
    """Test 403 when required scope is missing."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:read"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "users:read"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:read"}


def test_users_me_forbidden_different_resource(client):
    """Test that scopes from different resources don't grant access."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:admin"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["data"]["required_scope"] == "users:read"


# Unauthorized Tests


def test_users_me_unauthorized_no_token(client):
    """Test 401 when no token provided."""
    response = client.get(URLs.USERS_ME)

    assert response.status_code == 401


def test_users_me_unauthorized_invalid_token(client):
    """Test 401 with invalid token."""
    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_users_me_unauthorized_revoked_token(client, db):
    """Test 401 with revoked token."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:read"])

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_users_me_unauthorized_expired_token(client, db):
    """Test 401 with expired token."""
    jwt = _get_jwt(client)

    # Create a normal token first
    pat = _create_pat(client, jwt, ["users:read"], name="Expired Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_users_me_unauthorized_jwt_instead_of_pat(client):
    """Test that JWT tokens are not accepted for this endpoint."""
    jwt = _get_jwt(client)

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    # JWT doesn't start with "pat_", so should be treated as invalid PAT
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Invalid token"


def test_users_me_unauthorized_non_pat_token(client):
    """Test that tokens not starting with 'pat_' are rejected."""
    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": "Bearer some_random_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["message"] == "Invalid token"


# Scope Hierarchy Tests


def test_users_me_scope_hierarchy_write_grants_read(client, db):
    """Verify users:write grants users:read access."""
    assert has_permission(db, ["users:write"], "users:read") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "users:write"


def test_users_me_scope_hierarchy_read_does_not_grant_write(db):
    """Verify users:read does NOT grant users:write access."""
    assert has_permission(db, ["users:read"], "users:write") is False


# Cross-Resource Isolation Tests


def test_users_me_no_cross_resource_workspaces_to_users(db):
    """Verify workspaces:admin does NOT grant users:read access."""
    assert has_permission(db, ["workspaces:admin"], "users:read") is False


def test_users_me_no_cross_resource_fcs_to_users(db):
    """Verify fcs:analyze does NOT grant users:read access."""
    assert has_permission(db, ["fcs:analyze"], "users:read") is False


def test_users_me_cross_resource_multiple_scopes(client):
    """Test that having multiple resource scopes requires correct resource."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:admin"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403


def test_users_me_cross_resource_with_correct_scope(client):
    """Test that having correct scope works regardless of other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:read"])

    response = client.get(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200


# PUT /me Tests

# Success Tests for PUT /me


def test_users_me_put_success_with_exact_scope(client):
    """Test PUT /me with PAT having exact required scope (users:write)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"], name="Write Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["endpoint"] == "/api/v1/users/me"
    assert data["data"]["method"] == "PUT"
    assert data["data"]["required_scope"] == "users:write"
    assert data["data"]["granted_by"] == "users:write"
    assert data["data"]["your_scopes"] == ["users:write"]


def test_users_me_put_success_with_multiple_scopes(client):
    """Test PUT /me with PAT having multiple scopes including users:write."""
    jwt = _get_jwt(client)
    pat = _create_pat(
        client, jwt, ["fcs:read", "users:write", "workspaces:read"], name="Multi Scope Token"
    )

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "users:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "users:write", "workspaces:read"}


def test_users_me_put_success_write_only(client):
    """Test PUT /me with PAT having only users:write scope."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"], name="Write Only Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "users:write"


def test_users_me_put_success_with_read_write_both(client):
    """Test PUT /me with PAT having both users:read and users:write."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:read", "users:write"], name="Read Write Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    # Higher scope should be reported as granting access
    assert data["data"]["granted_by"] == "users:write"


def test_users_me_put_success_cross_resource_with_correct_scope(client):
    """Test PUT /me with PAT having users:write plus other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "users:write"], name="Cross Resource Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["granted_by"] == "users:write"


# Permission Denied Tests for PUT /me


def test_users_me_put_forbidden_read_scope_only(client):
    """Test PUT /me returns 403 when PAT has only users:read (insufficient)."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:read"], name="Read Only Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "users:write"
    assert data["data"]["your_scopes"] == ["users:read"]


def test_users_me_put_forbidden_missing_scope(client):
    """Test PUT /me returns 403 when PAT lacks users scope entirely."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:read", "workspaces:read"], name="Other Resources Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["error"] == "Forbidden"
    assert data["data"]["required_scope"] == "users:write"
    assert set(data["data"]["your_scopes"]) == {"fcs:read", "workspaces:read"}


def test_users_me_put_forbidden_different_resource(client):
    """Test PUT /me returns 403 when PAT has only other resource scopes."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:admin"], name="Different Resources")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
    data = response.json()["detail"]
    assert data["success"] is False
    assert data["data"]["required_scope"] == "users:write"


# Unauthorized Tests for PUT /me


def test_users_me_put_unauthorized_no_token(client):
    """Test PUT /me returns 401 when no token provided."""
    response = client.put(URLs.USERS_ME)

    assert response.status_code == 401


def test_users_me_put_unauthorized_invalid_token(client):
    """Test PUT /me returns 401 with invalid token."""
    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["error"] == "Unauthorized"
    assert data["detail"]["message"] == "Invalid token"


def test_users_me_put_unauthorized_revoked_token(client, db):
    """Test PUT /me returns 401 with revoked token."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"], name="Revoked Write Token")

    # Revoke the token
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    pat_record.is_revoked = True
    db.commit()

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token revoked"


def test_users_me_put_unauthorized_expired_token(client, db):
    """Test PUT /me returns 401 with expired token."""
    jwt = _get_jwt(client)

    # Create a token first
    pat = _create_pat(client, jwt, ["users:write"], name="Expired Write Token")

    # Manually set expiration to the past in the database
    token_hash = hashlib.sha256(pat.encode()).hexdigest()
    pat_record = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
    ).scalar_one()
    # Set expiration to yesterday
    pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Token expired"


def test_users_me_put_unauthorized_jwt_instead_of_pat(client):
    """Test PUT /me returns 401 when JWT token is used instead of PAT."""
    jwt = _get_jwt(client)

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    # JWT doesn't start with "pat_", so should be treated as invalid PAT
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["success"] is False
    assert data["detail"]["message"] == "Invalid token"


def test_users_me_put_unauthorized_non_pat_token(client):
    """Test PUT /me returns 401 for tokens not starting with 'pat_'."""
    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": "Bearer some_random_token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["message"] == "Invalid token"


# Scope Hierarchy Tests for PUT /me


def test_users_me_put_scope_hierarchy_write_grants_access(client, db):
    """Verify users:write satisfies users:write requirement for PUT /me."""
    assert has_permission(db, ["users:write"], "users:write") is True

    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["users:write"], name="Hierarchy Write Token")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["granted_by"] == "users:write"


def test_users_me_put_scope_hierarchy_read_does_not_grant_write(db):
    """Verify users:read does NOT grant users:write access for PUT /me."""
    assert has_permission(db, ["users:read"], "users:write") is False


# Cross-Resource Isolation Tests for PUT /me


def test_users_me_put_no_cross_resource_workspaces_to_users(db):
    """Verify workspaces:admin does NOT grant users:write access."""
    assert has_permission(db, ["workspaces:admin"], "users:write") is False


def test_users_me_put_no_cross_resource_fcs_to_users(db):
    """Verify fcs:analyze does NOT grant users:write access."""
    assert has_permission(db, ["fcs:analyze"], "users:write") is False


def test_users_me_put_cross_resource_multiple_scopes(client):
    """Test PUT /me with multiple resource scopes but no correct user scope."""
    jwt = _get_jwt(client)
    pat = _create_pat(client, jwt, ["fcs:analyze", "workspaces:admin"], name="Cross Resources No Users")

    response = client.put(
        URLs.USERS_ME,
        headers={"Authorization": f"Bearer {pat}"},
    )

    assert response.status_code == 403
