"""
FCS API endpoints.

This module provides API endpoints for FCS (Flow Cytometry Standard) file operations,
including parameter retrieval, events query, file upload, and statistics calculation.
"""
import time

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Query, UploadFile, status

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.dependencies.pat import AuthContext, require_scope
from app.dependencies.storage import get_storage
from app.logging_config import setup_logging
from app.models.fcs_file import FCSFile
from app.models.fcs_statistics import FCSStatistics
from app.schemas.common import APIResponse
from app.schemas.fcs import (
    FCSEventsResponseData,
    FCSFileResponse,
    FCSParametersResponseData,
    FCSStatisticsResponseData,
    StatisticsCalculateRequest,
    TaskResponseData,
)
from app.services.fcs import (
    get_fcs_events,
    get_fcs_file_path,
    get_fcs_parameters,
    get_sample_fcs_path,
)
from app.storage.base import StorageBackend
from app.utils.ids import generate_short_id

router = APIRouter(prefix="/fcs", tags=["fcs"])

# Setup logger for error tracking
logger = setup_logging()


@router.get(
    "/parameters",
    response_model=APIResponse[FCSParametersResponseData],
    status_code=status.HTTP_200_OK,
)
def get_fcs_parameters_endpoint(
    file_id: str | None = Query(
        None,
        description="Optional file ID to query specific uploaded file. "
        "If not provided, returns sample file parameters.",
    ),
    auth: AuthContext = Depends(require_scope("fcs:read")),
    db: Session = Depends(get_db),
):
    """
    Get FCS file parameters.

    This endpoint returns parameter metadata from FCS files.
    By default, it returns parameters from the built-in sample file.
    Optionally, you can specify a file_id to query a specific uploaded file.

    **Scope required:** `fcs:read`

    **Permissions:**
    - Sample file: Requires `fcs:read` scope
    - Public uploaded files: Requires `fcs:read` scope
    - Private uploaded files: Requires `fcs:read` scope + file ownership

    Args:
        file_id: Optional file ID to query specific uploaded file.
        auth: AuthContext containing PAT, scopes, and permission info.
        db: Database session.

    Returns:
        APIResponse with FCSParametersResponseData containing:
        - total_events: Total number of events in the FCS file
        - total_parameters: Total number of parameters
        - parameters: List of FCS parameters with index, pnn, pns, range, display

    Raises:
        HTTPException 403: If file_id is provided for a private file and user
            is not the owner.
        HTTPException 404: If file_id is provided but file is not found.
        HTTPException 500: If the FCS file cannot be parsed.
    """
    # 1. Determine which file to read
    if file_id is None:
        # Use built-in sample file
        file_path = get_sample_fcs_path()
    else:
        # Query uploaded file from database
        try:
            file_path, fcs_file = get_fcs_file_path(file_id, db)
        except ValueError as e:
            # Log detailed error for debugging
            logger.warning(f"FCS file lookup failed: {str(e)}")
            # Return safe, static message to client
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": "Not Found",
                    "message": "FCS file not found",
                },
            )

        # Permission check for private files
        if fcs_file and not fcs_file.is_public:
            # Get user_id from the PAT
            # The PAT is associated with a user through the tokens
            from sqlalchemy import select

            # Check if the authenticated token belongs to the file owner
            pat_user_id = None
            if auth.pat:
                # The PAT has a user_id attribute
                pat_user_id = auth.pat.user_id

            if fcs_file.user_id != pat_user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "success": False,
                        "error": "Forbidden",
                        "message": "Private file - access denied",
                    },
                )

    # 2. Parse FCS file
    try:
        params_data = get_fcs_parameters(file_path)
    except FileNotFoundError as e:
        # Log detailed error (includes full file path) for debugging
        logger.error(f"FCS file not found at path: {str(e)}")
        # Return safe, static message to client (no path exposed)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "FCS file not found",
            },
        )
    except Exception as e:
        # Log detailed error with stack trace for debugging
        logger.error(f"Failed to parse FCS file: {str(e)}", exc_info=True)
        # Return safe, static message to client (no internal details exposed)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to parse FCS file",
            },
        )

    # 3. Return result
    return APIResponse(success=True, data=params_data)


@router.get(
    "/events",
    response_model=APIResponse[FCSEventsResponseData],
    status_code=status.HTTP_200_OK,
)
def get_fcs_events_endpoint(
    file_id: str | None = Query(
        None,
        description="Optional file ID to query specific uploaded file. "
        "If not provided, returns sample file events.",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=10000,
        description="Maximum number of events to return (default: 100, max: 10000).",
    ),
    offset: int = Query(
        0,
        ge=0,
        description="Number of events to skip from the beginning (default: 0).",
    ),
    auth: AuthContext = Depends(require_scope("fcs:read")),
    db: Session = Depends(get_db),
):
    """
    Get FCS file events with pagination.

    This endpoint returns event data from FCS files in paginated format.
    By default, it returns events from the built-in sample file.
    Optionally, you can specify a file_id to query a specific uploaded file.

    **Scope required:** `fcs:read`

    **Permissions:**
    - Sample file: Requires `fcs:read` scope
    - Public uploaded files: Requires `fcs:read` scope
    - Private uploaded files: Requires `fcs:read` scope + file ownership

    Args:
        file_id: Optional file ID to query specific uploaded file.
        limit: Maximum number of events to return (default: 100, max: 10000).
        offset: Number of events to skip from the beginning (default: 0).
        auth: AuthContext containing PAT, scopes, and permission info.
        db: Database session.

    Returns:
        APIResponse with FCSEventsResponseData containing:
        - total_events: Total number of events in the FCS file
        - limit: Number of events returned per page
        - offset: Starting position
        - events: List of event dictionaries with parameter names as keys

    Raises:
        HTTPException 403: If file_id is provided for a private file and user
            is not the owner.
        HTTPException 404: If file_id is provided but file is not found.
        HTTPException 500: If the FCS file cannot be parsed.
    """
    # 1. Determine which file to read
    if file_id is None:
        file_path = get_sample_fcs_path()
    else:
        try:
            file_path, fcs_file = get_fcs_file_path(file_id, db)
        except ValueError as e:
            logger.warning(f"FCS file lookup failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": "Not Found",
                    "message": "FCS file not found",
                },
            )

        # Permission check for private files
        if fcs_file and not fcs_file.is_public:
            from sqlalchemy import select

            pat_user_id = auth.pat.user_id if auth.pat else None
            if fcs_file.user_id != pat_user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "success": False,
                        "error": "Forbidden",
                        "message": "Private file - access denied",
                    },
                )

    # 2. Parse FCS file and extract events
    try:
        events_data = get_fcs_events(file_path, limit=limit, offset=offset)
    except FileNotFoundError as e:
        logger.error(f"FCS file not found at path: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "FCS file not found",
            },
        )
    except Exception as e:
        logger.error(f"Failed to parse FCS file: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to parse FCS file",
            },
        )

    # 3. Return result
    return APIResponse(success=True, data=events_data)


@router.post(
    "/upload",
    response_model=APIResponse[FCSFileResponse],
    status_code=status.HTTP_201_CREATED,
)
async def upload_fcs_file(
    file: UploadFile,
    is_public: bool = Form(True),
    auth: AuthContext = Depends(require_scope("fcs:write")),
    db: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
):
    """
    Upload FCS file with streaming and background metadata extraction.

    Uploads an FCS file to local storage with streaming I/O for efficiency,
    extracts metadata using flowio, and stores file information in the database.

    **Scope required:** `fcs:write`

    **Features:**
    - Streaming upload (64KB chunks) for low memory usage
    - File validation (extension, content-type, FCS format)
    - Automatic metadata extraction (events count, parameters)
    - Short ID generation for file links

    Args:
        file: FCS file to upload (multipart/form-data)
        is_public: Whether file should be publicly accessible
        auth: AuthContext containing PAT and user info
        db: Database session
        storage: Storage backend for file operations

    Returns:
        APIResponse with FCSFileResponse containing:
        - file_id: Short identifier for the file
        - filename: Original filename
        - file_size: Size in bytes
        - total_events: Number of events in the file
        - total_parameters: Number of parameters

    Raises:
        HTTPException 400: Invalid file type or size
        HTTPException 500: Upload or parsing failure
    """
    # 1. Validate file extension
    if not file.filename.lower().endswith(tuple(settings.ALLOWED_FCS_EXTENSIONS)):
        logger.warning(
            f"Invalid file extension: {file.filename}. Allowed: {settings.ALLOWED_FCS_EXTENSIONS}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Invalid file type. Only {', '.join(settings.ALLOWED_FCS_EXTENSIONS)} files allowed",
            },
        )

    # 2. Validate Content-Type if provided
    if file.content_type and file.content_type not in settings.ALLOWED_FCS_CONTENT_TYPES:
        logger.warning(f"Invalid content-type: {file.content_type}")
        # Don't reject, just log - Content-Type can be unreliable

    # 3. Generate short ID
    file_id = generate_short_id()

    # 4. Start timer for upload duration tracking
    upload_start = time.time()

    # 5. Stream file to storage (async, low memory)
    try:
        file_path = await storage.save_file(
            file_id=file_id,
            file_stream=file.file,
            content_type=file.content_type or "application/octet-stream",
        )
    except Exception as e:
        logger.error(f"File upload failed for {file.filename}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to upload file",
            },
        )

    # 6. Stop timer
    upload_duration_ms = int((time.time() - upload_start) * 1000)

    # 7. Parse FCS metadata with flowio
    try:
        params_data = get_fcs_parameters(file_path)
    except FileNotFoundError:
        # File was not saved correctly
        logger.error(f"Uploaded file not found at path: {file_path}")
        # Clean up the uploaded file
        await storage.delete_file(file_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "File upload failed",
            },
        )
    except Exception as e:
        # Invalid FCS format - delete uploaded file
        logger.warning(f"Invalid FCS file {file.filename}: {str(e)}")
        await storage.delete_file(file_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": "Invalid FCS file format",
            },
        )

    # 8. Get file size
    file_size = file.size or 0

    # 9. Save to database
    try:
        fcs_file = FCSFile(
            file_id=file_id,
            filename=file.filename,
            file_path=file_path,
            file_size=file_size,
            total_events=params_data.total_events,
            total_parameters=params_data.total_parameters,
            is_public=is_public,
            upload_duration_ms=upload_duration_ms,
            user_id=auth.pat.user_id,
        )
        db.add(fcs_file)
        db.commit()
        db.refresh(fcs_file)
    except Exception as e:
        logger.error(f"Failed to save FCS file metadata: {str(e)}", exc_info=True)
        # Clean up uploaded file
        await storage.delete_file(file_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to save file metadata",
            },
        )

    # 10. Log successful upload
    logger.info(
        f"FCS file uploaded successfully: file_id={file_id}, "
        f"filename={file.filename}, size={file_size}, "
        f"events={params_data.total_events}, parameters={params_data.total_parameters}, "
        f"duration_ms={upload_duration_ms}, user_id={auth.pat.user_id}"
    )

    # 11. Return result
    return APIResponse(
        success=True,
        data={
            "file_id": fcs_file.file_id,
            "filename": fcs_file.filename,
            "file_size": fcs_file.file_size,
            "total_events": fcs_file.total_events,
            "total_parameters": fcs_file.total_parameters,
        },
    )


@router.get(
    "/statistics",
    response_model=APIResponse[FCSStatisticsResponseData],
    status_code=status.HTTP_200_OK,
)
async def get_fcs_statistics_endpoint(
    file_id: str | None = Query(
        None, description="File ID or null for sample file"
    ),
    auth: AuthContext = Depends(require_scope("fcs:analyze")),
    db: Session = Depends(get_db),
):
    """
    Get FCS file statistics from cache.

    Returns cached statistics only. If statistics haven't been calculated yet,
    returns 404 with a message to call POST /statistics/calculate first.

    **Scope required:** `fcs:analyze`

    **Permissions:**
    - Sample file: Requires `fcs:analyze` scope
    - Public uploaded files: Requires `fcs:analyze` scope
    - Private uploaded files: Requires `fcs:analyze` scope + file ownership

    Args:
        file_id: Optional file ID (null for sample file)
        auth: AuthContext containing PAT and user info
        db: Database session

    Returns:
        APIResponse with FCSStatisticsResponseData containing:
        - total_events: Total number of events
        - statistics: List of statistics for each parameter

    Raises:
        HTTPException 403: If private file and user is not owner
        HTTPException 404: If statistics not calculated yet
    """
    # 1. Determine which file to read
    if file_id is None:
        # Sample file: use "sample" as the file_id
        file_id_for_storage = "sample"
        fcs_file = None
    else:
        # Uploaded file: look up from database
        try:
            file_path, fcs_file = get_fcs_file_path(file_id, db)
        except ValueError as e:
            logger.warning(f"FCS file lookup failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": "Not Found",
                    "message": "FCS file not found",
                },
            )

        file_id_for_storage = file_id

    # 2. Permission check for private files
    if fcs_file and not fcs_file.is_public:
        pat_user_id = auth.pat.user_id if auth.pat else None
        if fcs_file.user_id != pat_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": "Forbidden",
                    "message": "Private file - access denied",
                },
            )

    # 3. Read from cache
    cached = db.query(FCSStatistics).filter_by(file_id=file_id_for_storage).first()

    if not cached:
        logger.info(f"Statistics not found for file_id: {file_id_for_storage}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Please call POST /api/v1/fcs/statistics/calculate first",
            },
        )

    # 4. Return cached result
    logger.info(f"Returning cached statistics for file_id: {file_id_for_storage}")
    return APIResponse(
        success=True,
        data={
            "total_events": cached.total_events,
            "statistics": cached.statistics,
        },
    )


@router.post(
    "/statistics/calculate",
    response_model=APIResponse[dict],
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_statistics_calculation(
    request: StatisticsCalculateRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_scope("fcs:analyze")),
    db: Session = Depends(get_db),
):
    """
    Trigger background statistics calculation.

    Initiates an asynchronous background task to calculate statistics for
    an FCS file. Returns immediately with a task_id for tracking.

    **Scope required:** `fcs:analyze`

    **Permissions:**
    - Sample file: Requires `fcs:analyze` scope
    - Public uploaded files: Requires `fcs:analyze` scope
    - Private uploaded files: Requires `fcs:analyze` scope + file ownership

    Args:
        request: Request body with optional file_id
        auth: AuthContext containing PAT and user info
        db: Database session
        background_tasks: FastAPI BackgroundTasks for async execution

    Returns:
        APIResponse with task_id and status, or cached results if already calculated

    Raises:
        HTTPException 403: If private file and user is not owner
        HTTPException 404: If file_id not found
    """
    from app.models.background_task import BackgroundTask

    # 1. Determine file source
    if request.file_id is None:
        # Sample file
        file_id_for_storage = "sample"
        file_path = get_sample_fcs_path()
        fcs_file = None
    else:
        # Uploaded file
        try:
            file_path, fcs_file = get_fcs_file_path(request.file_id, db)
        except ValueError as e:
            logger.warning(f"FCS file lookup failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": "Not Found",
                    "message": "FCS file not found",
                },
            )

        file_id_for_storage = request.file_id

    # 2. Permission check for private files
    if fcs_file and not fcs_file.is_public:
        pat_user_id = auth.pat.user_id if auth.pat else None
        if fcs_file.user_id != pat_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": "Forbidden",
                    "message": "Private file - access denied",
                },
            )

    # 3. Check cache (already calculated?)
    cached = db.query(FCSStatistics).filter_by(file_id=file_id_for_storage).first()

    if cached:
        logger.info(f"Statistics already calculated for file_id: {file_id_for_storage}")
        return APIResponse(
            success=True,
            data={
                "task_id": None,
                "status": "completed",
                "message": "Statistics already calculated",
                "result": {
                    "total_events": cached.total_events,
                    "statistics": cached.statistics,
                },
            },
        )

    # 4. Check for existing in-progress task
    from sqlalchemy import select, or_

    existing_task = db.query(BackgroundTask).filter(
        BackgroundTask.fcs_file_id == (fcs_file.id if fcs_file else None),
        BackgroundTask.task_type == "statistics",
        or_(
            BackgroundTask.status == "pending",
            BackgroundTask.status == "processing",
        ),
    ).first()

    if existing_task:
        logger.info(f"Task already in progress for file_id: {file_id_for_storage}, task_id: {existing_task.id}")
        return APIResponse(
            success=True,
            data={
                "task_id": existing_task.id,
                "status": existing_task.status,
                "message": "Statistics calculation already in progress",
            },
        )

    # 5. Create background task (using auto-increment id as task_id)
    task = BackgroundTask(
        task_type="statistics",
        fcs_file_id=fcs_file.id if fcs_file else None,
        status="pending",
        user_id=auth.pat.user_id,
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    task_id = task.id  # Use auto-increment id

    # 6. Start background task
    from app.services.background_tasks import calculate_statistics_task

    background_tasks.add_task(
        calculate_statistics_task,
        task_id=task_id,
        file_path=file_path,
        file_id_for_storage=file_id_for_storage,
        fcs_file_id=fcs_file.id if fcs_file else None,
        db_session_factory=lambda: SessionLocal(),
    )

    logger.info(
        f"Background task created: task_id={task_id}, file_id={file_id_for_storage}, user_id={auth.pat.user_id}"
    )

    # 7. Return task_id immediately
    return APIResponse(
        success=True,
        data={
            "task_id": task_id,
            "status": "pending",
            "message": "Statistics calculation started",
        },
    )


@router.get(
    "/tasks/{task_id}",
    response_model=APIResponse[TaskResponseData],
    status_code=status.HTTP_200_OK,
)
async def get_task_status_endpoint(
    task_id: int,
    auth: AuthContext = Depends(require_scope("fcs:analyze")),
    db: Session = Depends(get_db),
):
    """
    Get background task status and result.

    Returns the current status of a background statistics calculation task,
    along with the result if completed.

    **Scope required:** `fcs:analyze`

    Args:
        task_id: Task ID (auto-increment integer)
        auth: AuthContext containing PAT and user info
        db: Database session

    Returns:
        APIResponse with TaskResponseData containing:
        - task_id: Task ID
        - status: Current status (pending, processing, completed, failed)
        - created_at: Creation timestamp
        - completed_at: Completion timestamp (if completed)
        - result: Statistics result or error (if completed/failed)

    Raises:
        HTTPException 404: If task not found
        HTTPException 403: If user doesn't own the task
    """
    from app.models.background_task import BackgroundTask

    # 1. Get task
    task = db.query(BackgroundTask).filter_by(id=task_id).first()

    if not task:
        logger.warning(f"Task not found: task_id={task_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Task not found",
            },
        )

    # 2. Permission check: only task owner can view
    if task.user_id != auth.pat.user_id:
        logger.warning(
            f"Unauthorized access to task {task_id} by user {auth.pat.user_id}, owner: {task.user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "Forbidden",
                "message": "You can only view your own tasks",
            },
        )

    # 3. Build response data
    response_data = {
        "task_id": task.id,
        "status": task.status,
        "created_at": task.created_at.isoformat(),
    }

    if task.status == "completed" and task.result:
        response_data["completed_at"] = task.completed_at.isoformat()
        response_data["result"] = task.result
    elif task.status == "failed" and task.result:
        response_data["completed_at"] = task.completed_at.isoformat()
        response_data["result"] = task.result

    logger.info(f"Task status requested: task_id={task_id}, status={task.status}")

    return APIResponse(success=True, data=response_data)
