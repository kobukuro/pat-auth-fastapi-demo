import hashlib

from sqlalchemy import select

from app.models.pat import PersonalAccessToken
from app.services.pat import has_permission
from tests.constants import URLs


def _get_jwt(client) -> str:
    """Helper to register and login, returning JWT token."""
    client.post(
        URLs.REGISTER,
        json={"username": "tokenuser", "password": "password123"},
    )
    response = client.post(
        URLs.LOGIN,
        json={"username": "tokenuser", "password": "password123"},
    )
    return response.json()["data"]["access_token"]


def test_create_token_success(client):
    jwt = _get_jwt(client)

    response = client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": "My Test Token",
            "scopes": ["fcs:read", "users:read"],
            "expires_in_days": 30,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["data"]["name"] == "My Test Token"
    assert "token" in data["data"]
    assert data["data"]["token"].startswith("pat_")
    assert data["data"]["scopes"] == ["fcs:read", "users:read"]
    assert "created_at" in data["data"]
    assert "expires_at" in data["data"]


def test_create_token_without_jwt(client):
    response = client.post(
        URLs.TOKENS,
        json={
            "name": "My Test Token",
            "scopes": ["fcs:read"],
            "expires_in_days": 30,
        },
    )

    assert response.status_code == 401


def test_create_token_invalid_jwt(client):
    response = client.post(
        URLs.TOKENS,
        headers={"Authorization": "Bearer invalid_token"},
        json={
            "name": "My Test Token",
            "scopes": ["fcs:read"],
            "expires_in_days": 30,
        },
    )

    assert response.status_code == 401


def test_create_token_invalid_scopes(client):
    jwt = _get_jwt(client)

    response = client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": "My Test Token",
            "scopes": ["invalid:scope"],
            "expires_in_days": 30,
        },
    )

    assert response.status_code == 400


def test_create_token_stored_securely(client, db):
    jwt = _get_jwt(client)

    response = client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": "Secure Token",
            "scopes": ["fcs:read"],
            "expires_in_days": 30,
        },
    )

    assert response.status_code == 201
    full_token = response.json()["data"]["token"]

    # Verify token is stored as hash, not plaintext
    pat = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.name == "Secure Token")
    ).scalar_one()

    # Token should not be stored in plaintext
    assert full_token not in pat.token_hash
    assert full_token not in pat.token_prefix

    # Token prefix should be first 8 chars
    assert pat.token_prefix == full_token[:8]

    # Token hash should be SHA-256 of full token
    expected_hash = hashlib.sha256(full_token.encode()).hexdigest()
    assert pat.token_hash == expected_hash


def test_scope_hierarchy_within_resource(db):
    """Test that higher level scopes include lower level scopes within same resource."""
    # workspaces:admin (level 4) should include workspaces:read (level 1)
    assert has_permission(db, ["workspaces:admin"], "workspaces:read") is True
    assert has_permission(db, ["workspaces:admin"], "workspaces:write") is True
    assert has_permission(db, ["workspaces:admin"], "workspaces:delete") is True
    assert has_permission(db, ["workspaces:admin"], "workspaces:admin") is True

    # workspaces:write (level 2) should include workspaces:read (level 1)
    assert has_permission(db, ["workspaces:write"], "workspaces:read") is True
    assert has_permission(db, ["workspaces:write"], "workspaces:write") is True
    # But not higher levels
    assert has_permission(db, ["workspaces:write"], "workspaces:delete") is False
    assert has_permission(db, ["workspaces:write"], "workspaces:admin") is False


def test_scope_hierarchy_no_cross_resource(db):
    """Test that scopes don't inherit across different resources."""
    # workspaces:admin should NOT give access to fcs:read
    assert has_permission(db, ["workspaces:admin"], "fcs:read") is False
    assert has_permission(db, ["workspaces:admin"], "users:read") is False

    # fcs:analyze should NOT give access to workspaces:read
    assert has_permission(db, ["fcs:analyze"], "workspaces:read") is False

    # Multiple scopes from different resources
    assert has_permission(db, ["workspaces:admin", "fcs:read"], "fcs:read") is True
    assert has_permission(db, ["workspaces:admin", "fcs:read"], "fcs:write") is False
