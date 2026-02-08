import pytest

from app.utils.validators import PasswordValidationError, validate_password_complexity


class TestPasswordComplexity:
    """Password complexity validation tests"""

    def test_valid_password(self):
        """Test password meeting all rules"""
        validate_password_complexity("Abc123!@#")

    def test_too_short(self):
        """Test password too short"""
        with pytest.raises(PasswordValidationError) as exc:
            validate_password_complexity("Ab1!a")
        assert "8 characters" in str(exc.value)

    def test_missing_uppercase(self):
        """Test password missing uppercase letter"""
        with pytest.raises(PasswordValidationError) as exc:
            validate_password_complexity("abc123!@#")
        assert "uppercase" in str(exc.value)

    def test_missing_lowercase(self):
        """Test password missing lowercase letter"""
        with pytest.raises(PasswordValidationError) as exc:
            validate_password_complexity("ABC123!@#")
        assert "lowercase" in str(exc.value)

    def test_missing_digit(self):
        """Test password missing digit"""
        with pytest.raises(PasswordValidationError) as exc:
            validate_password_complexity("Abcdef!@#")
        assert "digit" in str(exc.value)

    def test_missing_special(self):
        """Test password missing special character"""
        with pytest.raises(PasswordValidationError) as exc:
            validate_password_complexity("Abc123456")
        assert "special character" in str(exc.value)
