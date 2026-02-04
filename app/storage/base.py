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
