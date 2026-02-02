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
