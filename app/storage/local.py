"""
Local filesystem storage implementation.

This module provides a local filesystem implementation of the storage backend
with async file operations and S3-compatible directory structure.
"""
import os
from pathlib import Path
from typing import AsyncIterator

import aiofiles

from app.config import settings
from app.storage.base import StorageBackend
from app.storage.exceptions import FileSizeExceededError, FileNotFoundError


class LocalStorageBackend(StorageBackend):
    """
    Local filesystem storage with async operations.

    Uses sharded directory structure for efficient file organization:
    app/storage/data/fcs/<prefix>/<file_id>.fcs

    This structure maps directly to S3 buckets for easy migration.
    """

    def __init__(self, base_path: str | None = None, max_size_mb: int = 1000):
        """
        Initialize local storage backend.

        Args:
            base_path: Base directory for file storage (default from config)
            max_size_mb: Maximum file size in MB (default from config)
        """
        self.base_path = Path(base_path or settings.STORAGE_BASE_PATH)
        self.max_size_bytes = max_size_mb * 1024 * 1024

    async def save_file(
        self,
        file_id: str,
        file_stream: AsyncIterator[bytes],
        content_type: str,
    ) -> str:
        """
        Stream file to disk in chunks (async).

        Args:
            file_id: Unique identifier for the file
            file_stream: Async iterator yielding file chunks
            content_type: MIME type of the file

        Returns:
            Full file path where file was saved

        Raises:
            FileSizeExceededError: If file exceeds maximum size
            StorageError: If save operation fails
        """
        file_path = self._get_file_path(file_id)

        # Ensure directory exists
        self._ensure_directory_exists(file_path)

        # Stream file to disk in 64KB chunks
        chunk_size = 64 * 1024  # 64KB
        total_size = 0

        try:
            async with aiofiles.open(file_path, 'wb') as f:
                async for chunk in file_stream:
                    total_size += len(chunk)

                    # Check size limit
                    if total_size > self.max_size_bytes:
                        await f.close()
                        # Delete partial file
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        raise FileSizeExceededError(total_size, self.max_size_bytes)

                    await f.write(chunk)

        except Exception as e:
            # Clean up partial file on error
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
            raise type(e)(f"Failed to save file: {str(e)}") from e

        return str(file_path)

    def get_file_path(self, file_id: str) -> str:
        """
        Get the full path for reading a file.

        Args:
            file_id: Unique identifier for the file

        Returns:
            Full file path

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        file_path = self._get_file_path(file_id)

        if not os.path.exists(file_path):
            raise FileNotFoundError(file_id)

        return str(file_path)

    async def delete_file(self, file_id: str) -> None:
        """
        Delete a file from storage.

        Args:
            file_id: Unique identifier for the file

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        file_path = self._get_file_path(file_id)

        if not os.path.exists(file_path):
            raise FileNotFoundError(file_id)

        try:
            os.remove(file_path)
        except Exception as e:
            raise type(e)(f"Failed to delete file: {str(e)}") from e

    def file_exists(self, file_id: str) -> bool:
        """
        Check if a file exists in storage.

        Args:
            file_id: Unique identifier for the file

        Returns:
            True if file exists, False otherwise
        """
        file_path = self._get_file_path(file_id)
        return os.path.exists(file_path)

    def _get_file_path(self, file_id: str) -> Path:
        """
        Calculate file path using sharded structure.

        Structure: <base_path>/fcs/<prefix>/<file_id>.fcs
        Example: app/storage/data/fcs/a3/a3b8f2d4e1c9.fcs

        Args:
            file_id: Unique identifier for the file

        Returns:
            Full file path as Path object
        """
        # Use first 2 characters as prefix for sharding
        prefix = file_id[:2] if len(file_id) >= 2 else file_id
        return self.base_path / "fcs" / prefix / f"{file_id}.fcs"

    def _ensure_directory_exists(self, file_path: Path) -> None:
        """
        Ensure the parent directory exists.

        Args:
            file_path: File path that needs parent directory
        """
        directory = file_path.parent
        directory.mkdir(parents=True, exist_ok=True)
