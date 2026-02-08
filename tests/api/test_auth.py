from tests.constants import URLs
from sqlalchemy import select


def test_register_success(client):
    response = client.post(
        URLs.REGISTER,
        json={"email": "test@example.com", "password": "Password123!"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["data"]["email"] == "test@example.com"
    assert "id" in data["data"]
    assert "created_at" in data["data"]


def test_register_duplicate_username(client):
    # Register first time
    client.post(
        URLs.REGISTER,
        json={"email": "test@example.com", "password": "Password123!"},
    )

    # Try to register with same email
    response = client.post(
        URLs.REGISTER,
        json={"email": "test@example.com", "password": "Password456!"},
    )
    assert response.status_code == 400


def test_register_invalid_password_too_short(client):
    response = client.post(
        URLs.REGISTER,
        json={"email": "test@example.com", "password": "short"},
    )
    assert response.status_code == 422  # Validation error


def test_register_invalid_email_format(client):
    response = client.post(
        URLs.REGISTER,
        json={"email": "invalid-email", "password": "Password123!"},
    )
    assert response.status_code == 422  # Validation error for invalid email


def test_register_missing_fields(client):
    response = client.post(
        URLs.REGISTER,
        json={"email": "test@example.com"},
    )
    assert response.status_code == 422  # Validation error


# Login tests


def test_login_success(client):
    # Register first
    client.post(
        URLs.REGISTER,
        json={"email": "login@example.com", "password": "Password123!"},
    )

    # Login
    response = client.post(
        URLs.LOGIN,
        json={"email": "login@example.com", "password": "Password123!"},
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
        json={"email": "login@example.com", "password": "Password123!"},
    )

    # Login with wrong password
    response = client.post(
        URLs.LOGIN,
        json={"email": "login@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    response = client.post(
        URLs.LOGIN,
        json={"email": "nouser@example.com", "password": "Password123!"},
    )
    assert response.status_code == 401


def test_login_inactive_user(client, db):
    # Register first
    client.post(
        URLs.REGISTER,
        json={"email": "inactive@example.com", "password": "Password123!"},
    )

    # Set user as inactive
    from app.models.user import User

    user = db.execute(select(User).where(User.email == "inactive@example.com")
    ).scalar_one()
    user.is_active = False
    db.commit()

    # Login
    response = client.post(
        URLs.LOGIN,
        json={"email": "inactive@example.com", "password": "Password123!"},
    )
    assert response.status_code == 403


def test_register_email_case_insensitive(client):
    """Test that email is case-insensitive."""
    # Register with uppercase email
    client.post(
        URLs.REGISTER,
        json={"email": "Test@Example.com", "password": "Password123!"},
    )

    # Try to register with lowercase version of same email
    response = client.post(
        URLs.REGISTER,
        json={"email": "test@example.com", "password": "Password456!"},
    )
    assert response.status_code == 400  # Should be treated as duplicate


def test_register_invalid_password_no_uppercase(client):
    """Test registration with password missing uppercase"""
    response = client.post(
        URLs.REGISTER,
        json={"email": "test1@example.com", "password": "password123!"},
    )
    assert response.status_code == 422
    data = response.json()
    assert "uppercase" in data["detail"][0]["msg"]


def test_register_invalid_password_no_lowercase(client):
    """Test registration with password missing lowercase"""
    response = client.post(
        URLs.REGISTER,
        json={"email": "test2@example.com", "password": "PASSWORD123!"},
    )
    assert response.status_code == 422


def test_register_invalid_password_no_digit(client):
    """Test registration with password missing digit"""
    response = client.post(
        URLs.REGISTER,
        json={"email": "test3@example.com", "password": "Password!"},
    )
    assert response.status_code == 422


def test_register_invalid_password_no_special(client):
    """Test registration with password missing special character"""
    response = client.post(
        URLs.REGISTER,
        json={"email": "test4@example.com", "password": "Password123"},
    )
    assert response.status_code == 422


def test_register_valid_password_complex(client):
    """Test registration with valid complex password"""
    response = client.post(
        URLs.REGISTER,
        json={"email": "test5@example.com", "password": "MyPass123!"},
    )
    assert response.status_code == 201
