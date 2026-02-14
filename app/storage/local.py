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
            """
            建立暫存檔案的父目錄
            .parent: Path物件的屬性，取得父目錄路徑
            parents=True: 如果父目錄不存在，會連同上層目錄一起建立（遞迴建立）
            exist_ok=True: 如果目錄已經存在，不會拋出錯誤
            """
            # Ensure directory exists
            temp_path.parent.mkdir(parents=True, exist_ok=True)

            # Create empty file (pre-allocate space for performance)
            """
            aiofiles.open()：使用非同步方式開啟檔案（避免程式阻塞）
            'wb'：寫入模式 + 二進位模式
                - w (write)：覆寫模式，若檔案存在會清空後重寫
                - b (binary)：以位元組形式處理資料（適合上傳檔案）
            async with：非同步上下文管理器，確保檔案正確關閉
            as f：將檔案物件存入變數 f
            """
            async with aiofiles.open(temp_path, 'wb') as f:
                # Pre-allocate file space (optional, for performance)
                # This creates a sparse file on supported filesystems
                """
                f.truncate(file_size)：調整檔案大小為指定的位元組數
                    - await：等待這個非同步操作完成
                    - file_size：最終檔案應有的完整大小
                這段程式碼是在分塊上傳初始化時預先配置磁碟空間：
                1. 避免磁碟空間不足的錯誤：一開始就確保有足夠空間
                2. 提升效能：避免每個區塊寫入時都需要調整檔案大小
                3. 減少磁碟碎片：連續配置空間比逐步擴充更有效率
                
                實際範例:
                假設上傳一個 100MB 的 FCS 檔案：
                # 初始化時就建立一個 100MB 的空殼檔案
                await f.truncate(100 * 1024 * 1024)  # 預留 100MB空間
                
                # 後續分塊寫入時，直接填入資料即可
                # 第 1 塊 (0-5MB) → 寫入位置 0
                # 第 2 塊 (5-10MB) → 寫入位置 5MB
                # ...
                
                這樣就不需要每寫入一個區塊就調整一次檔案大小，可以減少磁碟 I/O 的次數。
                """
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
            """
            aiofiles.open()：使用 aiofiles 函式庫以非同步方式開啟檔案（避免程式阻塞）
            r (read)：讀取模式，檔案必須已存在（否則會報錯）
            +：同時具備讀取和寫入權限（單純的 r 只能讀不能寫）
            b (binary)：以位元組形式處理資料（適合上傳檔案等非文字資料）
            async with：非同步上下文管理器，確保檔案正確關閉
            as f：將檔案物件存入變數 f，後續可以用來操作檔案
            
            為什麼用 'r+b' 而不是 'wb'？
                - 這個暫存檔案在 init_chunked_upload 階段就已經建立並預留空間了
                - 我們需要讀取現有檔案（將來可能需要驗證內容）+ 在指定位置寫入新資料
                - 'wb' 會清空檔案重新寫入，這不是我們要的
            """
            async with aiofiles.open(temp_path, 'r+b') as f:
                """
                移動檔案游標（讀寫位置指標）到指定的位元組位置
                await：等待這個非同步操作完成
                """
                await f.seek(offset)
                """
                將資料塊寫入檔案，並回傳實際寫入的位元組數
                詳細說明：
                    - chunk_data：要寫入的資料塊（bytes 型別）
                    - 寫入操作會從目前游標位置開始（剛剛用 seek 設定的位置）
                    - 回傳值 bytes_written：實際寫入的位元組數（通常等於len(chunk_data)）
                    - await：等待這個非同步寫入操作完成
                """
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
