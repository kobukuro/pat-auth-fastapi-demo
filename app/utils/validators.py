import re
import string

# Define allowed special characters (excluding space)
SPECIAL_CHARS = string.punctuation.replace(' ', '')


class PasswordValidationError(Exception):
    """Password validation error exception"""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__('; '.join(errors))


def validate_password_complexity(password: str) -> None:
    """
    Validate password complexity requirements.

    Rules:
    - Minimum length of 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character

    Raises:
        PasswordValidationError: When password does not meet requirements
    """
    errors = []

    # Check length
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    # Check uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least 1 uppercase letter")

    # Check lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least 1 lowercase letter")

    # Check digit
    if not re.search(r'\d', password):
        errors.append("Password must contain at least 1 digit")

    # Check special character
    if not re.search(rf'[{re.escape(SPECIAL_CHARS)}]', password):
        errors.append(f"Password must contain at least 1 special character ({SPECIAL_CHARS})")

    if errors:
        raise PasswordValidationError(errors)
