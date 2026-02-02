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


# List Tokens Tests


def test_list_tokens_success(client):
    """Test listing tokens with valid JWT."""
    jwt = _get_jwt(client)

    # Create multiple tokens
    for i in range(3):
        client.post(
            URLs.TOKENS,
            headers={"Authorization": f"Bearer {jwt}"},
            json={
                "name": f"Token {i}",
                "scopes": ["fcs:read"],
                "expires_in_days": 30,
            },
        )

    # List tokens
    response = client.get(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) == 3

    # Verify structure of first token
    token = data["data"][0]
    assert "id" in token
    assert "name" in token
    assert "token_prefix" in token
    assert token["token_prefix"].startswith("pat_")
    assert len(token["token_prefix"]) == 8
    assert "scopes" in token
    assert "created_at" in token
    assert "expires_at" in token
    assert "last_used_at" in token
    assert "is_revoked" in token


def test_list_tokens_empty(client):
    """Test listing tokens when user has none."""
    jwt = _get_jwt(client)

    response = client.get(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) == 0


def test_list_tokens_without_jwt(client):
    """Test that listing tokens requires authentication."""
    response = client.get(URLs.TOKENS)

    assert response.status_code == 401


def test_list_tokens_invalid_jwt(client):
    """Test that invalid JWT returns 401."""
    response = client.get(
        URLs.TOKENS,
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401


def test_list_tokens_isolation(client):
    """Test that users can only see their own tokens."""
    # Create first user and token
    jwt1 = _get_jwt(client)
    client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt1}"},
        json={
            "name": "User1 Token",
            "scopes": ["fcs:read"],
            "expires_in_days": 30,
        },
    )

    # Create second user and token
    client.post(
        URLs.REGISTER,
        json={"username": "user2", "password": "password123"},
    )
    login_response = client.post(
        URLs.LOGIN,
        json={"username": "user2", "password": "password123"},
    )
    jwt2 = login_response.json()["data"]["access_token"]

    client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt2}"},
        json={
            "name": "User2 Token",
            "scopes": ["users:read"],
            "expires_in_days": 30,
        },
    )

    # User1 should only see their own token
    response = client.get(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt1}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["name"] == "User1 Token"


def test_list_tokens_no_sensitive_data(client):
    """Test that full token and hash are not exposed."""
    jwt = _get_jwt(client)

    # Create a token
    create_response = client.post(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": "Test Token",
            "scopes": ["fcs:read"],
            "expires_in_days": 30,
        },
    )
    full_token = create_response.json()["data"]["token"]

    # List tokens
    list_response = client.get(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    token_data = list_response.json()["data"][0]

    # Verify sensitive fields are not present
    assert "token" not in token_data
    assert "token_hash" not in token_data
    assert full_token not in str(token_data)

    # Verify only prefix is shown
    assert token_data["token_prefix"] == full_token[:8]


def test_list_tokens_ordered_by_created_at(client):
    """Test that tokens are ordered by creation date (newest first)."""
    import time

    jwt = _get_jwt(client)

    # Create tokens with delay
    token_ids = []
    for i in range(3):
        response = client.post(
            URLs.TOKENS,
            headers={"Authorization": f"Bearer {jwt}"},
            json={
                "name": f"Token {i}",
                "scopes": ["fcs:read"],
                "expires_in_days": 30,
            },
        )
        token_ids.append(response.json()["data"]["id"])
        time.sleep(0.01)  # Ensure different timestamps

    # List tokens
    response = client.get(
        URLs.TOKENS,
        headers={"Authorization": f"Bearer {jwt}"},
    )

    tokens = response.json()["data"]
    # Should be in reverse order (newest first)
    assert tokens[0]["id"] == token_ids[2]
    assert tokens[1]["id"] == token_ids[1]
    assert tokens[2]["id"] == token_ids[0]
