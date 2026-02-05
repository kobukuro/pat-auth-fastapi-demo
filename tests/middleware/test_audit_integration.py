"""
Integration tests for PAT audit logging middleware.

These tests use real database commits (not transaction rollback) to verify
that the audit middleware correctly logs all PAT usage, including successful
and unauthorized requests.

This prevents regression of the datetime comparison bug where naive datetimes
from the database couldn't be compared with aware datetimes.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import Base, SessionLocal, engine
from app.models.audit_log import PersonalAccessTokenAuditLog
from app.models.pat import PersonalAccessToken
from app.models.scope import Scope
from app.models.user import User
from tests.constants import URLs


@pytest.fixture(scope="function")
def db_with_cleanup():
    """
    Create a database session that commits changes (no rollback).

    This allows the audit middleware's separate session to see the data
    and persist audit logs that we can verify.
    """
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)

    # Seed scopes if needed
    db = SessionLocal()
    try:
        if db.query(Scope).count() == 0:
            scopes = [
                Scope(resource='workspaces', action='read', name='workspaces:read', level=1),
                Scope(resource='workspaces', action='write', name='workspaces:write', level=2),
                Scope(resource='workspaces', action='delete', name='workspaces:delete', level=3),
                Scope(resource='workspaces', action='admin', name='workspaces:admin', level=4),
            ]
            db.add_all(scopes)
            db.commit()
    finally:
        db.close()

    # Create a new session for the test
    db = SessionLocal()

    yield db

    # Cleanup: delete all test data
    try:
        db.execute(select(PersonalAccessTokenAuditLog))
        db.query(PersonalAccessTokenAuditLog).delete()
        db.query(PersonalAccessToken).delete()
        db.query(User).filter(User.email.like("%@audit-test.com")).delete()
        db.commit()
    finally:
        db.close()


@pytest.fixture(scope="function")
def client_with_real_db():
    """Test client that doesn't use transaction rollback."""
    from app.dependencies.storage import get_storage
    from app.main import app

    def override_get_storage():
        from tests.conftest import TestStorageBackend
        return TestStorageBackend()

    app.dependency_overrides[get_storage] = override_get_storage

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def _create_test_user(db, email_suffix: str = "audit-test") -> str:
    """Helper to create a user and return JWT token."""
    user = User(
        email=f"{email_suffix}@audit-test.com",
        hashed_password="fake_hash",  # Simplified for test
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create a fake JWT (simplified - in real scenario would use auth service)
    # For this test, we'll create PAT manually
    return user.id


def _create_pat(db, user_id: int, scopes: list, name: str = "Test Token") -> str:
    """Helper to create a PAT token directly in the database."""
    # Get scopes
    scope_objs = db.execute(
        select(Scope).where(Scope.name.in_(scopes))
    ).scalars().all()

    # Generate token
    token_str = f"pat_{hashlib.sha256(bytes(user_id)).hexdigest()[:32]}"

    # Create PAT record
    pat = PersonalAccessToken(
        user_id=user_id,
        name=name,
        token_prefix=token_str[:8],
        token_hash=hashlib.sha256(token_str.encode()).hexdigest(),
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    pat.scopes = scope_objs
    db.add(pat)
    db.commit()
    db.refresh(pat)

    return token_str


class TestAuditLoggingMiddleware:
    """Test audit logging middleware with real database commits."""

    def test_successful_request_creates_audit_log(self, db_with_cleanup, client_with_real_db):
        """Test that successful API requests create audit log entries."""
        # Setup: Create user and PAT
        user_id = _create_test_user(db_with_cleanup, "successful")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:read"], "Success Token")

        # Get token_id from DB
        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()

        # Verify no logs exist initially
        initial_logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()
        assert len(initial_logs) == 0, "Should start with no audit logs"

        # Act: Make API request with PAT
        response = client_with_real_db.get(
            URLs.WORKSPACES,
            headers={"Authorization": f"Bearer {pat}"},
        )

        # Assert: API request succeeded
        assert response.status_code == 200
        assert response.json()["success"] is True

        # Assert: Audit log was created
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 1, "Should have exactly one audit log entry"

        log = logs[0]
        assert log.token_id == pat_record.id
        assert log.method == "GET"
        assert log.endpoint == "/api/v1/workspaces"
        assert log.status_code == 200
        assert log.authorized is True
        assert log.reason is None
        assert log.ip_address == "testclient"  # FastAPI TestClient default

        # Assert: last_used_at was updated
        db_with_cleanup.refresh(pat_record)
        assert pat_record.last_used_at is not None

    def test_unauthorized_request_creates_audit_log(self, db_with_cleanup, client_with_real_db):
        """Test that unauthorized requests create audit log entries with reason."""
        # Setup: Create user and expired PAT
        user_id = _create_test_user(db_with_cleanup, "unauthorized")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:read"], "Expired Token")

        # Manually set expiration to past
        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()
        pat_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db_with_cleanup.commit()

        # Act: Make API request with expired PAT
        response = client_with_real_db.get(
            URLs.WORKSPACES,
            headers={"Authorization": f"Bearer {pat}"},
        )

        # Assert: API request was unauthorized
        assert response.status_code == 401

        # Assert: Audit log was created
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 1, "Should have exactly one audit log entry"

        log = logs[0]
        assert log.token_id == pat_record.id
        assert log.method == "GET"
        assert log.endpoint == "/api/v1/workspaces"
        assert log.status_code == 401
        assert log.authorized is False
        assert log.reason == "Token has expired"

    def test_revoked_token_creates_audit_log(self, db_with_cleanup, client_with_real_db):
        """Test that revoked token requests create audit log entries."""
        # Setup: Create user and revoke PAT
        user_id = _create_test_user(db_with_cleanup, "revoked")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:read"], "Revoked Token")

        # Revoke the token
        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()
        pat_record.is_revoked = True
        db_with_cleanup.commit()

        # Act: Make API request with revoked PAT
        response = client_with_real_db.get(
            URLs.WORKSPACES,
            headers={"Authorization": f"Bearer {pat}"},
        )

        # Assert: API request was unauthorized
        assert response.status_code == 401

        # Assert: Audit log was created
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 1
        log = logs[0]
        assert log.authorized is False
        assert log.reason == "Token has been revoked"

    def test_multiple_requests_create_multiple_logs(self, db_with_cleanup, client_with_real_db):
        """Test that multiple requests create separate audit log entries."""
        # Setup
        user_id = _create_test_user(db_with_cleanup, "multiple")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:read"], "Multi Token")

        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()

        # Act: Make multiple requests
        for i in range(3):
            response = client_with_real_db.get(
                URLs.WORKSPACES,
                headers={"Authorization": f"Bearer {pat}"},
            )
            assert response.status_code == 200

        # Assert: Three separate log entries
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 3, "Should have three audit log entries"

        # Verify they're in chronological order
        timestamps = [log.timestamp for log in logs]
        assert timestamps == sorted(timestamps), "Logs should be in chronological order"

    def test_invalid_token_no_log_created(self, db_with_cleanup, client_with_real_db):
        """Test that completely invalid tokens don't create logs (can't identify token)."""
        # Act: Make request with invalid token
        response = client_with_real_db.get(
            URLs.WORKSPACES,
            headers={"Authorization": "Bearer pat_invalid_token_xyz"},
        )

        # Assert: Request was unauthorized
        assert response.status_code == 401

        # Assert: No audit logs were created (token doesn't exist)
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog)
        ).scalars().all()

        assert len(logs) == 0, "Invalid tokens should not create audit logs"

    def test_post_request_creates_audit_log(self, db_with_cleanup, client_with_real_db):
        """Test that POST requests are logged correctly."""
        # Setup
        user_id = _create_test_user(db_with_cleanup, "post")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:write"], "POST Token")

        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()

        # Act: Make POST request
        response = client_with_real_db.post(
            URLs.WORKSPACES,
            headers={"Authorization": f"Bearer {pat}"},
        )

        # Assert: API request succeeded
        assert response.status_code == 200

        # Assert: Audit log was created with POST method
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 1
        log = logs[0]
        assert log.method == "POST"
        assert log.authorized is True

    def test_forbidden_request_creates_audit_log(self, db_with_cleanup, client_with_real_db):
        """Test that 403 forbidden requests create audit logs."""
        # Setup: Create PAT with insufficient scopes
        user_id = _create_test_user(db_with_cleanup, "forbidden")
        pat = _create_pat(db_with_cleanup, user_id, ["workspaces:read"], "Read Only Token")

        token_hash = hashlib.sha256(pat.encode()).hexdigest()
        pat_record = db_with_cleanup.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == token_hash)
        ).scalar_one()

        # Act: Try to access POST endpoint with read-only scope
        response = client_with_real_db.post(
            URLs.WORKSPACES,
            headers={"Authorization": f"Bearer {pat}"},
        )

        # Assert: Request was forbidden (not unauthorized)
        assert response.status_code == 403

        # Assert: Audit log was created showing authorized=False with reason
        logs = db_with_cleanup.execute(
            select(PersonalAccessTokenAuditLog).where(
                PersonalAccessTokenAuditLog.token_id == pat_record.id
            )
        ).scalars().all()

        assert len(logs) == 1
        log = logs[0]
        assert log.method == "POST"
        assert log.status_code == 403
        assert log.authorized is False, "Forbidden requests should have authorized=False"
        assert log.reason == "Insufficient permissions"
