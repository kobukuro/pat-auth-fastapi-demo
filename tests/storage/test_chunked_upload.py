"""
Unit tests for chunked upload storage operations.

Tests the LocalStorageBackend chunked upload methods including
initialization, chunk saving, finalization, and abortion.
"""
import os
import pytest
from pathlib import Path

from app.storage.local import LocalStorageBackend


@pytest.fixture
def storage(tmp_path):
    """Create a storage backend with temporary directory."""
    backend = LocalStorageBackend(base_path=str(tmp_path), max_size_mb=100)
    return backend


@pytest.mark.asyncio
async def test_init_chunked_upload(storage):
    """Test chunked upload initialization."""
    temp_path = await storage.init_chunked_upload(
        session_id="test_session",
        filename="sample.fcs",
        file_size=1024 * 1024,  # 1MB
        chunk_size=512 * 1024,   # 512KB
    )

    assert Path(temp_path).exists()
    assert Path(temp_path).stat().st_size == 1024 * 1024  # Pre-allocated size


@pytest.mark.asyncio
async def test_save_chunk(storage):
    """Test saving a single chunk."""
    # Initialize session
    await storage.init_chunked_upload("test_session", "sample.fcs", 1024, 512)

    # Save chunk 0
    chunk_data = b"x" * 512
    bytes_written = await storage.save_chunk("test_session", 0, chunk_data, chunk_size=512)
    assert bytes_written == 512

    # Verify file size
    temp_path = storage._get_temp_file_path("test_session", "")
    assert temp_path.stat().st_size == 1024


@pytest.mark.asyncio
async def test_save_multiple_chunks(storage):
    """Test saving multiple chunks."""
    # Initialize
    await storage.init_chunked_upload("test_session", "sample.fcs", 1024, 256)

    # Save chunks
    chunk_data = b"a" * 256
    await storage.save_chunk("test_session", 0, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 1, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 2, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 3, chunk_data, chunk_size=256)

    # Verify
    temp_path = storage._get_temp_file_path("test_session", "")
    assert temp_path.stat().st_size == 1024


@pytest.mark.asyncio
async def test_finalize_chunked_upload(storage):
    """Test finalizing chunked upload."""
    # Initialize and upload chunks
    await storage.init_chunked_upload("test_session", "sample.fcs", 1024, 256)

    chunk_data = b"y" * 256
    await storage.save_chunk("test_session", 0, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 1, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 2, chunk_data, chunk_size=256)
    await storage.save_chunk("test_session", 3, chunk_data, chunk_size=256)

    # Finalize
    final_path = await storage.finalize_chunked_upload("test_session", "test_file_id")
    assert Path(final_path).exists()
    assert Path(final_path).stat().st_size == 1024

    # Verify temp file is cleaned up
    temp_path = storage._get_temp_file_path("test_session", "")
    assert not temp_path.exists()


@pytest.mark.asyncio
async def test_abort_chunked_upload(storage):
    """Test aborting chunked upload."""
    # Initialize
    await storage.init_chunked_upload("test_session", "sample.fcs", 1024, 256)

    temp_path = storage._get_temp_file_path("test_session", "")
    assert temp_path.exists()

    # Abort
    await storage.abort_chunked_upload("test_session")

    # Verify temp file is deleted
    assert not temp_path.exists()


@pytest.mark.asyncio
async def test_chunk_write_at_correct_offset(storage):
    """Test that chunks are written at the correct offset."""
    # Initialize
    await storage.init_chunked_upload("test_session", "sample.fcs", 1024, 256)

    # Write chunks with different data (each exactly 256 bytes)
    chunk1 = b"AAAA" + b"\x00" * 252  # 256 bytes
    chunk2 = b"BBBB" + b"\x00" * 252  # 256 bytes
    chunk3 = b"CCCC" + b"\x00" * 252  # 256 bytes

    await storage.save_chunk("test_session", 0, chunk1, chunk_size=256)  # Offset 0
    await storage.save_chunk("test_session", 1, chunk2, chunk_size=256)  # Offset 256
    await storage.save_chunk("test_session", 2, chunk3, chunk_size=256)  # Offset 512

    # Read and verify content
    temp_path = storage._get_temp_file_path("test_session", "")
    with open(temp_path, "rb") as f:
        f.seek(0)
        assert f.read(4) == b"AAAA"

        f.seek(256)
        assert f.read(4) == b"BBBB"

        f.seek(512)
        assert f.read(4) == b"CCCC"


@pytest.mark.asyncio
async def test_multiple_chunks_same_file(storage):
    """Test that multiple chunks write to the same file correctly."""
    # Initialize
    await storage.init_chunked_upload("test_session", "sample.fcs", 768, 256)

    # Write all chunks (each 256 bytes)
    chunk1 = b"AAA" + b"\x00" * 253  # 256 bytes
    chunk2 = b"BBB" + b"\x00" * 253  # 256 bytes
    chunk3 = b"CCC" + b"\x00" * 253  # 256 bytes

    await storage.save_chunk("test_session", 0, chunk1, chunk_size=256)
    await storage.save_chunk("test_session", 1, chunk2, chunk_size=256)
    await storage.save_chunk("test_session", 2, chunk3, chunk_size=256)

    # Finalize and verify
    final_path = await storage.finalize_chunked_upload("test_session", "final_id")

    with open(final_path, "rb") as f:
        content = f.read()
        # Only check first 4 bytes of each chunk (since rest is padding)
        assert content[0:3] == b"AAA"
        assert content[256:259] == b"BBB"
        assert content[512:515] == b"CCC"
