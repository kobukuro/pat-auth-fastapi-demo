"""
Background task execution service.

This module provides functions for running background tasks asynchronously,
primarily for FCS statistics calculation.
"""
from datetime import datetime, timezone

from app.database import SessionLocal
from app.logging_config import setup_logging
from app.models.fcs_statistics import FCSStatistics
from app.services.fcs_statistics import calculate_fcs_statistics

logger = setup_logging()


async def calculate_statistics_task(
    task_id: int,
    file_path: str,
    file_id_for_storage: str,
    fcs_file_id: int | None,
    db_session_factory,
) -> None:
    """
    Background task for FCS statistics calculation.

    This function runs asynchronously after the API response is sent.
    It calculates statistics for an FCS file and stores the results in the database.

    Args:
        task_id: Background task ID (auto-increment integer)
        file_path: Path to FCS file (sample or uploaded)
        file_id_for_storage: file_id for storing in FCSStatistics table
            ("sample" for sample file, or file_id for uploaded files)
        fcs_file_id: FCS file database ID (None for sample file)
        db_session_factory: Database session factory function

    Note:
        This function is called by FastAPI BackgroundTasks and runs after
        the HTTP response is sent to the client.
    """
    db = db_session_factory()

    try:
        # Update task status to processing
        task = db.query(BackgroundTask).filter_by(id=task_id).first()
        if not task:
            logger.error(f"Background task {task_id} not found")
            return

        task.status = TaskStatus.PROCESSING
        db.commit()

        logger.info(
            f"Task {task_id}: Starting statistics calculation for {file_path}"
        )

        # Calculate statistics using NumPy
        result = calculate_fcs_statistics(file_path)

        # Store results in database (both sample and uploaded files)
        stats_record = FCSStatistics(
            file_id=file_id_for_storage,
            fcs_file_id=fcs_file_id,
            statistics=result.statistics,
            total_events=result.total_events,
        )
        db.add(stats_record)

        # Mark task as completed
        task.status = TaskStatus.COMPLETED
        task.result = {
            "total_events": result.total_events,
            "statistics": result.statistics,
        }
        task.completed_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            f"Task {task_id}: Completed statistics calculation. "
            f"Events: {result.total_events}, Parameters: {len(result.statistics)}"
        )

    except Exception as e:
        # Mark task as failed
        if "task" in locals():
            task.status = TaskStatus.FAILED
            task.result = {"error": str(e)}
            task.completed_at = datetime.now(timezone.utc)
            db.commit()

        logger.error(f"Task {task_id}: Failed with error: {str(e)}", exc_info=True)
        raise

    finally:
        db.close()


# Import BackgroundTask at module level to avoid circular imports
# This is safe because the function is async and runs in a separate context
from app.models.background_task import BackgroundTask, TaskStatus
