"""
Conftest for storage tests - minimal setup without database.
"""
import pytest


# Don't use the parent conftest.py which requires database
# Override the autouse fixtures
@pytest.fixture(scope="session")
def setup_database():
    """Skip database setup for storage tests."""
    pass


@pytest.fixture
def db():
    """Skip database fixture for storage tests."""
    yield None


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Skip rate limiter reset for storage tests."""
    yield
