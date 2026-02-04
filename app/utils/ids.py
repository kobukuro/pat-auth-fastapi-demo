"""
Utility functions for generating short, URL-safe identifiers.

This module provides functions for generating random IDs using base62 encoding,
which produces shorter, more human-friendly identifiers than UUIDs.
"""
import random
import string
import uuid


# Base62 character set: [0-9a-zA-Z]
BASE62_CHARS = string.digits + string.ascii_letters


def b62encode(num: int) -> str:
    """
    Encode a number to base62 string.

    Args:
        num: Integer to encode

    Returns:
        Base62 encoded string

    Examples:
        >>> b62encode(12345)
        '3D7'
    """
    if num == 0:
        return BASE62_CHARS[0]

    base = len(BASE62_CHARS)
    encoded = []

    while num > 0:
        num, remainder = divmod(num, base)
        encoded.append(BASE62_CHARS[remainder])

    return "".join(reversed(encoded))


def generate_short_id(length: int = 12) -> str:
    """
    Generate a short, URL-safe ID using base62 encoding.

    Uses random bytes for entropy and encodes them in base62 format,
    producing a shorter and more compact identifier than standard UUIDs.

    Args:
        length: Length of the output string (default: 12 characters)

    Returns:
        Short, URL-safe identifier using [0-9a-zA-Z] characters

    Examples:
        >>> generate_short_id()
        'a3b8f2d4e1c9'
        >>> generate_short_id(8)
        'x7y9z2a1'

    Notes:
        - 12 characters provides ~72 bits of entropy (sufficient for uniqueness)
        - Uses base62 encoding [0-9a-zA-Z] for URL safety
        - Shorter than standard UUID (12 vs 36 characters)
    """
    # Generate random bytes using UUID v4
    random_bytes = uuid.uuid4().bytes

    # Convert bytes to integer
    num = int.from_bytes(random_bytes, byteorder='big')

    # Encode to base62
    encoded = b62encode(num)

    # Pad or truncate to desired length
    if len(encoded) < length:
        # Add random padding to reach desired length
        padding = ''.join(random.choices(BASE62_CHARS, k=length - len(encoded)))
        return encoded + padding

    return encoded[:length]
