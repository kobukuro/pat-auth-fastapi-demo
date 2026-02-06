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

    # Chunked upload methods

    def _get_temp_file_path(self, session_id: str, filename: str) -> Path:
        """
        Calculate temporary file path for chunk assembly.

        Structure: <base_path>/.tmp/uploads/<prefix>/<session_id>.tmp

        Args:
            session_id: Upload session identifier (task_id)
            filename: Original filename (for extension, not used in path)

        Returns:
            Full temporary file path as Path object
        """
        # Use first 2 characters as prefix for sharding
        prefix = str(session_id)[:2] if len(str(session_id)) >= 2 else str(session_id)
        return self.base_path / ".tmp" / "uploads" / prefix / f"{session_id}.tmp"

    async def init_chunked_upload(
        self,
        session_id: str,
        filename: str,
        file_size: int,
        chunk_size: int,
    ) -> str:
        """
        Initialize chunked upload session.

        Creates temporary directory and empty file for chunk assembly.

        Args:
            session_id: Upload session identifier (task_id)
            filename: Original filename (for logging)
            file_size: Total expected file size
            chunk_size: Size of each chunk

        Returns:
            Path to temporary file

        Raises:
            StorageError: If initialization fails
        """
        temp_path = self._get_temp_file_path(session_id, filename)

        try:
            # Ensure directory exists
            temp_path.parent.mkdir(parents=True, exist_ok=True)

            # Create empty file (pre-allocate space for performance)
            async with aiofiles.open(temp_path, 'wb') as f:
                # Pre-allocate file space (optional, for performance)
                # This creates a sparse file on supported filesystems
                await f.truncate(file_size)

            return str(temp_path)

        except Exception as e:
            # Clean up on error
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise type(e)(f"Failed to initialize chunked upload: {str(e)}") from e

    async def save_chunk(
        self,
        session_id: str,
        chunk_number: int,
        chunk_data: bytes,
        chunk_size: int,
    ) -> int:
        """
        Save chunk at specific offset in temporary file.

        Args:
            session_id: Upload session identifier (task_id)
            chunk_number: Chunk sequence number (0-based)
            chunk_data: Chunk bytes to write
            chunk_size: Expected chunk size for offset calculation

        Returns:
            Number of bytes written

        Raises:
            FileNotFoundError: If temporary file not found
            ValueError: If chunk size exceeds expected chunk_size
            StorageError: If write operation fails
        """
        # Validate chunk size - should not exceed chunk_size
        if len(chunk_data) > chunk_size:
            raise ValueError(
                f"Chunk {chunk_number} size {len(chunk_data)} exceeds chunk_size {chunk_size}"
            )

        # Calculate offset using the configured chunk_size (not len(chunk_data))
        offset = chunk_number * chunk_size

        temp_path = self._get_temp_file_path(session_id, "")

        if not temp_path.exists():
            raise FileNotFoundError(f"Temporary file not found for session {session_id}")

        try:
            # Write chunk at offset
            async with aiofiles.open(temp_path, 'r+b') as f:
                await f.seek(offset)
                bytes_written = await f.write(chunk_data)

            return bytes_written

        except Exception as e:
            raise type(e)(f"Failed to save chunk {chunk_number}: {str(e)}") from e

    async def finalize_chunked_upload(
        self,
        session_id: str,
        file_id: str,
    ) -> str:
        """
        Move temporary file to permanent location.

        Validates size, moves to sharded directory, cleans up temp file.

        Args:
            session_id: Upload session identifier (task_id)
            file_id: Final file ID for permanent storage

        Returns:
            Final file path

        Raises:
            FileNotFoundError: If temporary file not found
            StorageError: If finalization fails or size mismatch
        """
        temp_path = self._get_temp_file_path(session_id, "")

        if not temp_path.exists():
            raise FileNotFoundError(f"Temporary file not found for session {session_id}")

        try:
            # Get actual file size
            actual_size = temp_path.stat().st_size

            # Calculate final path
            final_path = self._get_file_path(file_id)

            # Ensure destination directory exists
            self._ensure_directory_exists(final_path)

            # Atomic move (rename)
            temp_path.rename(final_path)

            # Clean up empty temp directory
            try:
                temp_path.parent.rmdir()
            except OSError:
                # Directory not empty, ignore
                pass

            return str(final_path)

        except Exception as e:
            raise type(e)(f"Failed to finalize chunked upload: {str(e)}") from e

    async def abort_chunked_upload(
        self,
        session_id: str,
    ) -> None:
        """
        Clean up temporary file for aborted upload.

        Args:
            session_id: Upload session identifier (task_id)

        Raises:
            StorageError: If cleanup fails
        """
        temp_path = self._get_temp_file_path(session_id, "")

        if temp_path.exists():
            try:
                temp_path.unlink()

                # Clean up empty directory
                try:
                    temp_path.parent.rmdir()
                except OSError:
                    # Directory not empty, ignore
                    pass

            except Exception as e:
                raise type(e)(f"Failed to cleanup upload session {session_id}: {str(e)}") from e

    async def list_temp_upload_files(self) -> list[str]:
        """
        List all temporary upload files.

        Scans the .tmp/uploads/ directory and returns all session_ids.

        Returns:
            List of session_ids (task_ids) for temp files
        """
        temp_dir = self.base_path / ".tmp" / "uploads"

        if not temp_dir.exists():
            return []

        session_ids = []

        # Iterate through prefix directories
        for prefix_dir in temp_dir.iterdir():
            if prefix_dir.is_dir():
                # Find all .tmp files in this prefix directory
                for temp_file in prefix_dir.glob("*.tmp"):
                    # Extract session_id from filename (remove .tmp extension)
                    session_id = temp_file.stem
                    session_ids.append(session_id)

        return session_ids
