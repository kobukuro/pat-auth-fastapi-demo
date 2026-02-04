"""
Storage-specific exceptions.

These exceptions provide detailed error handling for storage operations.
"""


class StorageError(Exception):
    """Base exception for storage operations."""

    pass


class FileSizeExceededError(StorageError):
    """Raised when uploaded file exceeds maximum size limit."""

    def __init__(self, file_size: int, max_size: int):
        self.file_size = file_size
        self.max_size = max_size
        super().__init__(
            f"File size ({file_size} bytes) exceeds maximum allowed size ({max_size} bytes)"
        )


class FileNotFoundError(StorageError):
    """Raised when requested file is not found in storage."""

    def __init__(self, file_id: str):
        self.file_id = file_id
        super().__init__(f"File not found: {file_id}")
