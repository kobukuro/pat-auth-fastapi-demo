from tests.constants import URLs


def test_register_success(client):
    response = client.post(
        URLs.REGISTER,
        json={"username": "testuser", "password": "password123"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["data"]["username"] == "testuser"
    assert "id" in data["data"]
    assert "created_at" in data["data"]


def test_register_duplicate_username(client):
    # Register first time
    client.post(
        URLs.REGISTER,
        json={"username": "testuser", "password": "password123"},
    )

    # Try to register with same username
    response = client.post(
        URLs.REGISTER,
        json={"username": "testuser", "password": "password456"},
    )
    assert response.status_code == 400


def test_register_invalid_password_too_short(client):
    response = client.post(
        URLs.REGISTER,
        json={"username": "testuser", "password": "short"},
    )
    assert response.status_code == 422  # Validation error


def test_register_invalid_username_too_short(client):
    response = client.post(
        URLs.REGISTER,
        json={"username": "ab", "password": "password123"},
    )
    assert response.status_code == 422  # Validation error


def test_register_missing_fields(client):
    response = client.post(
        URLs.REGISTER,
        json={"username": "testuser"},
    )
    assert response.status_code == 422  # Validation error


# Login tests


def test_login_success(client):
    # Register first
    client.post(
        URLs.REGISTER,
        json={"username": "loginuser", "password": "password123"},
    )

    # Login
    response = client.post(
        URLs.LOGIN,
        json={"username": "loginuser", "password": "password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "access_token" in data["data"]
    assert data["data"]["token_type"] == "bearer"


def test_login_invalid_password(client):
    # Register first
    client.post(
        URLs.REGISTER,
        json={"username": "loginuser", "password": "password123"},
    )

    # Login with wrong password
    response = client.post(
        URLs.LOGIN,
        json={"username": "loginuser", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    response = client.post(
        URLs.LOGIN,
        json={"username": "nouser", "password": "password123"},
    )
    assert response.status_code == 401


def test_login_inactive_user(client, db):
    # Register first
    client.post(
        URLs.REGISTER,
        json={"username": "inactiveuser", "password": "password123"},
    )

    # Set user as inactive
    from app.models.user import User

    user = db.execute(
        __import__("sqlalchemy").select(User).where(User.username == "inactiveuser")
    ).scalar_one()
    user.is_active = False
    db.commit()

    # Login
    response = client.post(
        URLs.LOGIN,
        json={"username": "inactiveuser", "password": "password123"},
    )
    assert response.status_code == 403
