import pytest
from tests.constants import URLs


def test_rate_limit_middleware_blocks_over_limit(client):
    """Test middleware returns 429 when over limit."""
    # Send 60 requests
    for _ in range(60):
        client.get(URLs.WORKSPACES)

    # 61st request should be blocked
    response = client.get(URLs.WORKSPACES)
    assert response.status_code == 429
    data = response.json()
    assert data["success"] is False
    assert data["error"] == "Too Many Requests"
    assert "retry_after" in data["data"]
    assert isinstance(data["data"]["retry_after"], int)


def test_rate_limit_allows_under_limit(client):
    """Test requests under limit succeed."""
    # Make 10 requests (well under the 60 limit)
    for _ in range(10):
        response = client.get(URLs.WORKSPACES)
        # Should NOT be rate limited (will be 401 because no auth, but not 429)
        assert response.status_code != 429


def test_rate_limit_works_with_all_endpoints(client):
    """Test rate limiting applies to all endpoints."""
    # Exhaust limit on workspaces endpoint
    for _ in range(60):
        client.get(URLs.WORKSPACES)

    # Should be rate limited on different endpoint too
    response = client.get(URLs.FCS_PARAMETERS)
    assert response.status_code == 429


def test_rate_limit_error_format(client):
    """Test rate limit error matches specification."""
    # Exhaust limit
    for _ in range(60):
        client.get(URLs.WORKSPACES)

    response = client.get(URLs.WORKSPACES)
    data = response.json()

    # Verify error format matches spec
    assert data["success"] is False
    assert data["error"] == "Too Many Requests"
    assert "data" in data
    assert "retry_after" in data["data"]
    assert isinstance(data["data"]["retry_after"], int)
