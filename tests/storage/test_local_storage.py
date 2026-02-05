"""
Unit tests for LocalStorageBackend utility methods.
"""
import pytest

from app.storage.local import LocalStorageBackend


@pytest.mark.asyncio
async def test_list_temp_upload_files_empty(tmp_path):
    """Test listing temp files when none exist."""
    storage = LocalStorageBackend(base_path=str(tmp_path))

    session_ids = await storage.list_temp_upload_files()
    assert session_ids == []


@pytest.mark.asyncio
async def test_list_temp_upload_files_with_files(tmp_path):
    """Test listing temp files when they exist."""
    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Create some temp files manually
    temp_dir = tmp_path / ".tmp" / "uploads"
    temp_dir.mkdir(parents=True)

    # Create prefix directories and temp files
    (temp_dir / "12").mkdir()
    (temp_dir / "34").mkdir()

    # Create temp files (session_ids: 123, 124, 345)
    (temp_dir / "12" / "123.tmp").write_bytes(b"test data 1")
    (temp_dir / "12" / "124.tmp").write_bytes(b"test data 2")
    (temp_dir / "34" / "345.tmp").write_bytes(b"test data 3")

    # List temp files
    session_ids = await storage.list_temp_upload_files()

    # Verify results
    assert len(session_ids) == 3
    assert "123" in session_ids
    assert "124" in session_ids
    assert "345" in session_ids


@pytest.mark.asyncio
async def test_list_temp_upload_files_ignores_non_tmp_files(tmp_path):
    """Test that non-.tmp files are ignored."""
    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Create temp directory with mixed files
    temp_dir = tmp_path / ".tmp" / "uploads"
    temp_dir.mkdir(parents=True)
    (temp_dir / "12").mkdir()

    # Create .tmp files and other files
    (temp_dir / "12" / "123.tmp").write_bytes(b"test data")
    (temp_dir / "12" / "456.txt").write_bytes(b"should be ignored")
    (temp_dir / "12" / "readme").write_bytes(b"should be ignored")

    # List temp files
    session_ids = await storage.list_temp_upload_files()

    # Verify only .tmp files are returned
    assert len(session_ids) == 1
    assert "123" in session_ids


@pytest.mark.asyncio
async def test_list_temp_upload_files_no_temp_directory(tmp_path):
    """Test listing when .tmp/uploads directory doesn't exist."""
    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Don't create .tmp/uploads directory

    # Should return empty list, not raise error
    session_ids = await storage.list_temp_upload_files()
    assert session_ids == []
