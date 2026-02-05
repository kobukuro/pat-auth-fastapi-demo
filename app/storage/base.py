"""
Abstract base class for storage backends.

This module defines the interface that all storage backends must implement,
providing an S3-compatible abstraction layer.
"""
from abc import ABC, abstractmethod
from typing import AsyncIterator


class StorageBackend(ABC):
    """
    Abstract base class for storage backends.

    All storage implementations (local filesystem, S3, etc.) must implement
    these methods to ensure compatibility and easy migration.
    """

    @abstractmethod
    async def save_file(
        self,
        file_id: str,
        file_stream: AsyncIterator[bytes],
        content_type: str,
    ) -> str:
        """
        Save file to storage.

        Args:
            file_id: Unique identifier for the file
            file_stream: Async iterator yielding file chunks
            content_type: MIME type of the file

        Returns:
            Full file path or key

        Raises:
            FileSizeExceededError: If file exceeds maximum size
            StorageError: If save operation fails
        """
        pass

    @abstractmethod
    def get_file_path(self, file_id: str) -> str:
        """
        Get the path/key for reading a file.

        Args:
            file_id: Unique identifier for the file

        Returns:
            File path or key

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        pass

    @abstractmethod
    async def delete_file(self, file_id: str) -> None:
        """
        Delete a file from storage.

        Args:
            file_id: Unique identifier for the file

        Raises:
            FileNotFoundError: If file doesn't exist
            StorageError: If delete operation fails
        """
        pass

    @abstractmethod
    def file_exists(self, file_id: str) -> bool:
        """
        Check if a file exists in storage.

        Args:
            file_id: Unique identifier for the file

        Returns:
            True if file exists, False otherwise
        """
        pass

    # Chunked upload methods

    @abstractmethod
    async def init_chunked_upload(
        self,
        session_id: str,
        filename: str,
        file_size: int,
        chunk_size: int,
    ) -> str:
        """
        Initialize a chunked upload session.

        Creates a temporary file for assembling chunks.

        Args:
            session_id: Unique session identifier (task_id)
            filename: Original filename (for extension)
            file_size: Total expected file size in bytes
            chunk_size: Size of each chunk in bytes

        Returns:
            Path to temporary file

        Raises:
            StorageError: If initialization fails
        """
        pass

    @abstractmethod
    async def save_chunk(
        self,
        session_id: str,
        chunk_number: int,
        chunk_data: bytes,
    ) -> int:
        """
        Save a single chunk to temporary file.

        Args:
            session_id: Upload session identifier (task_id)
            chunk_number: Chunk sequence number (0-based)
            chunk_data: Chunk bytes to write

        Returns:
            Number of bytes written

        Raises:
            StorageError: If chunk write fails
            FileNotFoundError: If session not initialized
        """
        pass

    @abstractmethod
    async def finalize_chunked_upload(
        self,
        session_id: str,
        file_id: str,
    ) -> str:
        """
        Finalize chunked upload and move to permanent location.

        Validates file integrity, moves temp file to final location,
        and cleans up temporary resources.

        Args:
            session_id: Upload session identifier (task_id)
            file_id: Final file ID for permanent storage

        Returns:
            Final file path

        Raises:
            StorageError: If finalization fails
            FileNotFoundError: If temp file missing
            FileSizeExceededError: If size mismatch
        """
        pass

    @abstractmethod
    async def abort_chunked_upload(
        self,
        session_id: str,
    ) -> None:
        """
        Abort chunked upload and clean up temporary files.

        Args:
            session_id: Upload session identifier (task_id)

        Raises:
            StorageError: If cleanup fails
        """
        pass

    @abstractmethod
    async def list_temp_upload_files(self) -> list[str]:
        """
        List all temporary upload files.

        Returns:
            List of session_ids (task_ids) for temp files in .tmp/uploads/

        Raises:
            StorageError: If listing fails
        """
        pass
