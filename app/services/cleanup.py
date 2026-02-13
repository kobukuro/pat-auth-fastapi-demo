"""
Background cleanup service for expired upload sessions.

This module provides periodic cleanup of expired BackgroundTasks and
temporary files.
"""
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select, or_

from app.database import SessionLocal
from app.logging_config import setup_logging
from app.models.background_task import BackgroundTask, TaskType, TaskStatus
from app.storage.base import StorageBackend
from app.dependencies.storage import get_storage

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = setup_logging()


async def cleanup_expired_upload_sessions(
    db: "Session | None" = None,
    storage: StorageBackend | None = None,
):
    """
    Clean up expired upload sessions.

    Should be run periodically (e.g., every hour via cron or celery).
    Marks expired sessions as 'expired' and deletes temporary files.

    This function cleans up:
    1. Expired pending/uploading/finalizing sessions (older than 24 hours)
    2. Failed sessions with temp files
    3. Associated temporary files from storage

    Args:
        db: Optional database session. If not provided, creates a new one.
        storage: Optional storage backend. If not provided, uses get_storage().
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    if storage is None:
        storage = get_storage()

    try:
        # Find expired pending/uploading/finalizing sessions
        expired_sessions = db.query(BackgroundTask).filter(
            BackgroundTask.task_type == TaskType.CHUNKED_UPLOAD,
            BackgroundTask.status.in_([TaskStatus.PENDING, TaskStatus.PROCESSING, TaskStatus.FINALIZING, TaskStatus.FAILED]),
            BackgroundTask.expires_at < datetime.now(),
        ).all()

        logger.info(f"Found {len(expired_sessions)} expired upload sessions")

        for session in expired_sessions:
            logger.info(
                f"Cleaning up expired upload session: id={session.id}, "
                f"status={session.status}, user_id={session.user_id}"
            )

            # Clean up temp file if exists
            try:
                await storage.abort_chunked_upload(str(session.id))
            except Exception as e:
                logger.error(
                    f"Failed to cleanup temp file for session {session.id}: {str(e)}"
                )

            # Mark as expired
            session.status = TaskStatus.EXPIRED

        db.commit()
        logger.info(f"Cleaned up {len(expired_sessions)} expired upload sessions")

    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}", exc_info=True)
        db.rollback()

    finally:
        if close_db:
            db.close()


async def cleanup_orphaned_temp_files(
    db: "Session | None" = None,
    storage: StorageBackend | None = None,
):
    """
    Clean up orphaned temporary files.

    This function scans the temporary upload directory for files
    that don't have corresponding BackgroundTask records and removes them.

    This is a safety net for cleanup in case tasks are deleted from
    the database but temp files remain.

    Args:
        db: Optional database session. If not provided, creates a new one.
        storage: Optional storage backend. If not provided, uses get_storage().
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    if storage is None:
        storage = get_storage()

    try:
        # Get all active upload session IDs
        active_task_ids = set(
            row.id
            for row in db.query(BackgroundTask)
            .filter(
                BackgroundTask.task_type == TaskType.CHUNKED_UPLOAD,
                BackgroundTask.status.in_([TaskStatus.PENDING, TaskStatus.PROCESSING, TaskStatus.FINALIZING]),
            )
            .all()
        )

        # List all temp files in storage
        temp_session_ids = await storage.list_temp_upload_files()

        # Find orphaned files (exist in storage but not in active tasks)
        orphaned_ids = [sid for sid in temp_session_ids if int(sid) not in active_task_ids]

        logger.info(
            f"Active upload sessions: {len(active_task_ids)}, "
            f"Total temp files: {len(temp_session_ids)}, "
            f"Orphaned files: {len(orphaned_ids)}"
        )

        # Clean up orphaned files
        cleaned_count = 0
        for session_id in orphaned_ids:
            try:
                logger.info(f"Cleaning up orphaned temp file for session_id={session_id}")
                await storage.abort_chunked_upload(session_id)
                cleaned_count += 1
            except Exception as e:
                logger.error(
                    f"Failed to cleanup orphaned temp file for session {session_id}: {str(e)}"
                )

        logger.info(f"Cleaned up {cleaned_count} orphaned temporary files")

    except Exception as e:
        logger.error(f"Orphaned temp file cleanup failed: {str(e)}", exc_info=True)

    finally:
        if close_db:
            db.close()
