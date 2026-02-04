"""
Storage abstraction layer for file operations.

This package provides an S3-compatible interface for file storage,
allowing easy migration between local filesystem and cloud storage.
"""

from app.storage.base import StorageBackend
from app.storage.local import LocalStorageBackend
from app.storage.exceptions import (
    FileSizeExceededError,
    FileNotFoundError,
    StorageError,
)

__all__ = [
    "StorageBackend",
    "LocalStorageBackend",
    "FileSizeExceededError",
    "StorageError",
    "FileNotFoundError",
]
