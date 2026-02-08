"""
Unit tests for PAT service functions.

Tests the get_pat_by_token() function which uses token_prefix
lookup with hash verification for optimized PAT validation.
"""
import pytest
from datetime import datetime, timedelta, timezone

from app.models.pat import PersonalAccessToken
from app.models.user import User
from app.services.pat import generate_pat, get_pat_by_token


@pytest.fixture
def test_user(db):
    """Create a test user for PAT testing."""
    user = User(
        email="test@example.com",
        hashed_password="hashed_password_here"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestGetPatByToken:
    """Test suite for get_pat_by_token() function."""

    def test_get_pat_by_token_valid_token(self, db, test_user):
        """Verify correct token is found using prefix+hash lookup."""
        # Generate a token
        full_token, prefix, hash = generate_pat()

        # Create PAT record
        pat = PersonalAccessToken(
            user_id=test_user.id,
            name="Test Token",
            token_prefix=prefix,
            token_hash=hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        db.add(pat)
        db.commit()

        # Lookup should find the token
        result = get_pat_by_token(db, full_token)

        assert result is not None
        assert result.id == pat.id
        assert result.token_hash == hash
        assert result.token_prefix == prefix
        assert result.name == "Test Token"

    def test_get_pat_by_token_invalid_hash(self, db, test_user):
        """Verify wrong hash returns None even with same prefix."""
        # Generate two different tokens
        full_token1, prefix1, hash1 = generate_pat()
        _, _, hash2 = generate_pat()  # Different hash

        # Create PAT with mismatched hash
        pat = PersonalAccessToken(
            user_id=test_user.id,
            name="Test Token",
            token_prefix=prefix1,
            token_hash=hash2,  # Wrong hash!
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        db.add(pat)
        db.commit()

        # Lookup should not find match (hash doesn't match)
        result = get_pat_by_token(db, full_token1)

        assert result is None

    def test_get_pat_by_token_prefix_collision(self, db, test_user):
        """Verify correct token selected when multiple share prefix."""
        # Generate two tokens
        full_token1, _, hash1 = generate_pat()
        full_token2, _, hash2 = generate_pat()

        # Force same prefix (artificial collision scenario)
        common_prefix = "pat_test"

        # Create two PATs with same prefix but different hashes
        pat1 = PersonalAccessToken(
            user_id=test_user.id,
            name="Token 1",
            token_prefix=common_prefix,
            token_hash=hash1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        pat2 = PersonalAccessToken(
            user_id=test_user.id,
            name="Token 2",
            token_prefix=common_prefix,
            token_hash=hash2,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        db.add_all([pat1, pat2])
        db.commit()

        # Manually create test tokens with the common prefix
        # Note: This is artificial since we're forcing the prefix
        test_token1 = common_prefix + full_token1[8:]
        test_token2 = common_prefix + full_token2[8:]

        # Recalculate hashes for the modified tokens
        import hashlib
        hash1_for_common_prefix = hashlib.sha256(test_token1.encode()).hexdigest()
        hash2_for_common_prefix = hashlib.sha256(test_token2.encode()).hexdigest()

        # Update the PAT records with the correct hashes
        pat1.token_hash = hash1_for_common_prefix
        pat2.token_hash = hash2_for_common_prefix
        db.commit()

        # Should find exact match via hash verification
        result1 = get_pat_by_token(db, test_token1)
        assert result1 is not None
        assert result1.id == pat1.id
        assert result1.name == "Token 1"

        result2 = get_pat_by_token(db, test_token2)
        assert result2 is not None
        assert result2.id == pat2.id
        assert result2.name == "Token 2"

    def test_get_pat_by_token_no_candidates(self, db):
        """Verify None returned when prefix doesn't exist."""
        # Try to lookup a token that doesn't exist
        result = get_pat_by_token(db, "pat_invalid")

        assert result is None

    def test_get_pat_by_token_empty_string(self, db):
        """Verify None returned for empty token."""
        result = get_pat_by_token(db, "")

        assert result is None

    def test_get_pat_by_token_short_token(self, db):
        """Verify None returned for token shorter than 8 chars."""
        # Token shorter than prefix length
        result = get_pat_by_token(db, "pat_")

        assert result is None
