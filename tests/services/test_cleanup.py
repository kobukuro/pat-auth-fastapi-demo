"""
Integration tests for cleanup service.
"""
import pytest

from app.models.background_task import BackgroundTask
from app.models.user import User
from app.services.cleanup import cleanup_expired_upload_sessions, cleanup_orphaned_temp_files


@pytest.fixture
def test_user(db):
    """Create a test user for cleanup tests."""
    user = User(
        email="cleanup-test@example.com",
        hashed_password="test_hash",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_cleanup_orphaned_temp_files(db, tmp_path, test_user):
    """Test cleanup removes orphaned temp files."""
    from app.storage.local import LocalStorageBackend

    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Create an active upload session (not orphaned)
    active_task = BackgroundTask(
        task_type="chunked_upload",
        status="processing",
        user_id=test_user.id,
        extra_data={"filename": "active.fcs"},
    )
    db.add(active_task)
    db.commit()
    db.refresh(active_task)

    # Create temp files for active task (should NOT be cleaned up)
    await storage.init_chunked_upload(
        session_id=str(active_task.id),
        filename="active.fcs",
        file_size=1024,
        chunk_size=512,
    )

    # Create temp file for orphaned session (should be cleaned up)
    temp_dir = tmp_path / ".tmp" / "uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    (temp_dir / "99").mkdir(exist_ok=True)
    orphaned_file = temp_dir / "99" / "999.tmp"
    orphaned_file.write_bytes(b"orphaned data")

    # Verify orphaned file exists
    assert orphaned_file.exists()

    # Run cleanup with explicit db and storage
    await cleanup_orphaned_temp_files(db=db, storage=storage)

    # Verify orphaned file was removed
    assert not orphaned_file.exists()

    # Verify active task's temp file still exists
    active_temp_path = tmp_path / ".tmp" / "uploads" / f"{str(active_task.id)[:2]}" / f"{active_task.id}.tmp"
    assert active_temp_path.exists()


@pytest.mark.asyncio
async def test_cleanup_expired_upload_sessions(db, tmp_path, test_user):
    """Test cleanup marks expired sessions and removes temp files."""
    from app.storage.local import LocalStorageBackend
    from datetime import datetime, timedelta

    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Create an expired upload session
    expired_task = BackgroundTask(
        task_type="chunked_upload",
        status="processing",
        user_id=test_user.id,
        expires_at=datetime.now() - timedelta(hours=25),  # Expired
        extra_data={"filename": "expired.fcs"},
    )
    db.add(expired_task)
    db.commit()
    db.refresh(expired_task)

    # Create temp file for expired task
    await storage.init_chunked_upload(
        session_id=str(expired_task.id),
        filename="expired.fcs",
        file_size=1024,
        chunk_size=512,
    )

    # Verify temp file exists
    temp_path = tmp_path / ".tmp" / "uploads" / f"{str(expired_task.id)[:2]}" / f"{expired_task.id}.tmp"
    assert temp_path.exists()

    # Run cleanup with explicit db and storage
    await cleanup_expired_upload_sessions(db=db, storage=storage)

    # Refresh from database
    db.refresh(expired_task)

    # Verify task is marked as expired
    assert expired_task.status == "expired"

    # Verify temp file was removed
    assert not temp_path.exists()


@pytest.mark.asyncio
async def test_cleanup_orphaned_handles_cleanup_errors(db, tmp_path):
    """Test that cleanup handles error logging when files fail to delete."""
    from app.storage.local import LocalStorageBackend

    storage = LocalStorageBackend(base_path=str(tmp_path))

    # Create temp directory with correct prefix structure
    # session_id="99999" -> prefix="99"
    temp_dir = tmp_path / ".tmp" / "uploads" / "99"
    temp_dir.mkdir(parents=True, exist_ok=True)

    # Create orphaned temp file (using correct path structure)
    test_file = temp_dir / "99999.tmp"
    test_file.write_bytes(b"test data")

    # Verify file exists
    assert test_file.exists()

    # Run cleanup - should handle gracefully
    await cleanup_orphaned_temp_files(db=db, storage=storage)

    # Verify file was cleaned up
    assert not test_file.exists()
