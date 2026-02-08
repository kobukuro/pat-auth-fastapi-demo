"""
Storage dependency injection for FastAPI.

This module provides FastAPI dependency functions for injecting
storage backends into endpoints.
"""
from app.config import settings
from app.storage.base import StorageBackend
from app.storage.local import LocalStorageBackend


def get_storage() -> StorageBackend:
    """
    Return storage backend based on configuration.

    This allows switching between local and cloud storage
    by changing the STORAGE_BACKEND environment variable.

    Returns:
        StorageBackend instance (local or S3)

    Raises:
        ValueError: If STORAGE_BACKEND is not supported
    """
    if settings.STORAGE_BACKEND == "local":
        return LocalStorageBackend(
            base_path=settings.STORAGE_BASE_PATH,
            max_size_mb=settings.MAX_UPLOAD_SIZE_MB,
        )

    # Future support for S3
    # elif settings.STORAGE_BACKEND == "s3":
    #     from app.storage.s3 import S3StorageBackend
    #     return S3StorageBackend(...)

    raise ValueError(f"Unknown storage backend: {settings.STORAGE_BACKEND}")
