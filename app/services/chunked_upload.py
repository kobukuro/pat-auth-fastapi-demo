"""
Chunked upload auto-complete service.

This module provides the background task logic for finalizing chunked uploads,
including file assembly, FCS metadata extraction, and database record creation.
"""
from datetime import datetime

from app.database import SessionLocal
from app.logging_config import setup_logging
from app.models.background_task import BackgroundTask
from app.models.fcs_file import FCSFile
from app.services.fcs import get_fcs_parameters
from app.storage.base import StorageBackend
from app.dependencies.storage import get_storage
from app.utils.ids import generate_short_id

logger = setup_logging()


async def finalize_chunked_upload(
    task_id: int,
    db_session_factory,
) -> dict:
    """
    Finalize chunked upload session.

    Validates all chunks are uploaded, assembles the file, extracts FCS metadata,
    creates FCSFile record, and updates BackgroundTask status.

    This function is designed to be idempotent and safe to call multiple times.

    Args:
        task_id: Upload session identifier (task_id)
        db_session_factory: Database session factory for creating new sessions

    Returns:
        dict with file_id, filename, total_events, total_parameters

    Raises:
        ValueError: If session not found, validation fails, or FCS parsing fails
    """
    db = db_session_factory()
    storage: StorageBackend = get_storage()

    try:
        # 1. Get task with防重入 check
        task = db.query(BackgroundTask).filter_by(id=task_id).first()

        if not task:
            raise ValueError(f"Upload session {task_id} not found")

        # 防重入: Skip if already completed
        if task.status == "completed":
            logger.info(f"Task {task_id} already completed, skipping")
            if task.result:
                return task.result
            elif task.fcs_file:
                return {
                    "file_id": task.fcs_file.file_id,
                    "filename": task.fcs_file.filename,
                    "total_events": task.fcs_file.total_events or 0,
                    "total_parameters": task.fcs_file.total_parameters or 0,
                }

        # 防重入: Check if already finalizing
        if task.status == "finalizing":
            logger.info(f"Task {task_id} is already finalizing")
            # Wait or return error (simplified: return error)
            raise ValueError("Upload is finalizing, please wait")

        # 2. Validate all chunks uploaded
        extra_data = task.extra_data or {}
        uploaded_chunks = extra_data.get("uploaded_chunks", 0)
        total_chunks = extra_data.get("total_chunks", 0)

        if uploaded_chunks != total_chunks:
            raise ValueError(
                f"Not all chunks uploaded: {uploaded_chunks}/{total_chunks}"
            )

        logger.info(f"Finalizing upload task_id={task_id}, chunks validated")

        # 3. Generate file_id
        file_id = generate_short_id()

        # 4. Finalize storage (move temp file to permanent location)
        try:
            file_path = await storage.finalize_chunked_upload(
                session_id=str(task_id),
                file_id=file_id,
            )
        except Exception as e:
            logger.error(f"Failed to finalize upload: {str(e)}", exc_info=True)
            task.status = "failed"
            task.result = {"error_message": f"Failed to finalize upload: {str(e)}"}
            task.completed_at = datetime.now()
            db.commit()
            raise

        # 5. Parse FCS metadata
        try:
            params_data = get_fcs_parameters(file_path)
        except Exception as e:
            logger.error(f"Failed to parse FCS file: {str(e)}", exc_info=True)
            # Clean up the finalized file
            await storage.delete_file(file_id)
            task.status = "failed"
            task.result = {"error_message": f"Invalid FCS file: {str(e)}"}
            task.completed_at = datetime.now()
            db.commit()
            raise ValueError(f"Invalid FCS file format: {str(e)}")

        # 6. Create FCSFile record
        try:
            fcs_file = FCSFile(
                file_id=file_id,
                filename=extra_data.get("filename", "unknown.fcs"),
                file_path=file_path,
                file_size=extra_data.get("file_size", 0),
                total_events=params_data.total_events,
                total_parameters=params_data.total_parameters,
                is_public=True,  # Default to public, can be stored in extra_data in future
                upload_duration_ms=None,  # Not tracked for chunked uploads
                user_id=task.user_id,
            )
            db.add(fcs_file)
            db.flush()  # Get fcs_file.id without committing

            # Update background task
            task.fcs_file_id = fcs_file.id
            task.status = "completed"
            task.result = {
                "file_id": fcs_file.file_id,
                "filename": fcs_file.filename,
                "total_events": fcs_file.total_events or 0,
                "total_parameters": fcs_file.total_parameters or 0,
            }
            task.completed_at = datetime.now()
            db.commit()
            db.refresh(fcs_file)

            logger.info(
                f"Chunked upload completed: task_id={task_id}, "
                f"file_id={file_id}, filename={fcs_file.filename}, "
                f"events={params_data.total_events}, "
                f"parameters={params_data.total_parameters}"
            )

            return task.result

        except Exception as e:
            logger.error(f"Failed to save FCS file metadata: {str(e)}", exc_info=True)
            # Clean up the finalized file
            await storage.delete_file(file_id)
            task.status = "failed"
            task.result = {"error_message": f"Failed to save file metadata: {str(e)}"}
            task.completed_at = datetime.now()
            db.commit()
            raise

    except Exception as e:
        logger.error(f"finalize_chunked_upload failed: {str(e)}", exc_info=True)
        raise

    finally:
        db.close()
