"""
FCS API endpoints.

This module provides API endpoints for FCS (Flow Cytometry Standard) file operations,
including parameter retrieval, events query, file upload, and statistics calculation.
"""
import time
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.dependencies.pat import AuthContext, get_pat_with_scopes, require_scope
from app.dependencies.storage import get_storage
from app.logging_config import setup_logging
from app.models.background_task import BackgroundTask
from app.models.fcs_statistics import FCSStatistics
from app.models.pat import PersonalAccessToken
from app.models.scope import Scope
from app.schemas.common import APIResponse
from app.schemas.fcs import (
    ChunkedUploadChunkResponse,
    ChunkedUploadInitResponse,
    FCSEventsResponseData,
    FCSParametersResponseData,
    FCSStatisticsResponseData,
    StatisticsCalculateRequest,
    TaskResponseData,
)
from app.services.fcs import (
    get_fcs_events,
    get_fcs_file_for_download,
    get_fcs_file_path,
    get_fcs_parameters,
    get_sample_fcs_path,
)
from app.storage.base import StorageBackend
from app.utils.authorization import check_permission_and_get_context

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
    response_model=APIResponse[ChunkedUploadInitResponse],
    status_code=status.HTTP_201_CREATED,
)
async def init_chunked_upload(
    filename: str = Form(...),
    file_size: int = Form(..., gt=0, le=1000*1024*1024),  # Max 1GB
    chunk_size: int = Form(5*1024*1024, ge=1*1024*1024, le=10*1024*1024),  # 1-10MB, default 5MB
    is_public: bool = Form(True),
    auth: AuthContext = Depends(require_scope("fcs:write")),
    db: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
):
    """
    Initialize chunked upload session for FCS file.

    Creates an upload session and returns a task_id for tracking progress.
    Client should then upload chunks using POST /upload/chunk.

    **Scope required:** `fcs:write`

    **Request (multipart/form-data):**
    - filename: Original filename (must end with .fcs)
    - file_size: Total file size in bytes (max 1GB)
    - chunk_size: Size of each chunk in bytes (1-10MB, default 5MB)
    - is_public: Whether file should be publicly accessible

    **Returns:**
    - task_id: Upload session ID for tracking
    - chunk_size: Actual chunk size used
    - total_chunks: Total number of chunks to upload
    - status: Current session status

    **Example:**
    ```bash
    curl -X POST http://localhost:8000/api/v1/fcs/upload \\
      -H "Authorization: Bearer pat_abc123..." \\
      -F "filename=sample.fcs" \\
      -F "file_size=157286400" \\
      -F "chunk_size=5242880" \\
      -F "is_public=true"
    ```
    """
    from datetime import datetime, timedelta
    from app.models.background_task import BackgroundTask

    # 1. Validate filename
    if not filename.lower().endswith(tuple(settings.ALLOWED_FCS_EXTENSIONS)):
        logger.warning(
            f"Invalid file extension: {filename}. Allowed: {settings.ALLOWED_FCS_EXTENSIONS}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Invalid file type. Only {', '.join(settings.ALLOWED_FCS_EXTENSIONS)} files allowed",
            },
        )

    # 2. Calculate total chunks
    total_chunks = (file_size + chunk_size - 1) // chunk_size  # Ceiling division

    # 3. Create BackgroundTask for upload session
    task = BackgroundTask(
        task_type="chunked_upload",
        status="pending",
        user_id=auth.pat.user_id,
        expires_at=datetime.now() + timedelta(hours=24),
        extra_data={
            "filename": filename,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "chunk_size": chunk_size,
            "uploaded_chunks": 0,
            "uploaded_bytes": 0,
            "uploaded_chunk_numbers": [],  # Track which chunks have been uploaded
            "is_public": is_public,
        },
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    task_id = task.id

    # 4. Initialize storage (create temp file)
    try:
        temp_path = await storage.init_chunked_upload(
            session_id=str(task_id),
            filename=filename,
            file_size=file_size,
            chunk_size=chunk_size,
        )

        # Update task with temp path and status
        task.extra_data["temp_file_path"] = temp_path
        task.status = "processing"
        db.commit()

    except Exception as e:
        logger.error(f"Failed to init chunked upload: {str(e)}", exc_info=True)
        task.status = "failed"
        task.result = {"error_message": "Failed to initialize upload"}
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to initialize upload session",
            },
        )

    # 5. Log successful initialization
    logger.info(
        f"Chunked upload initialized: task_id={task_id}, "
        f"filename={filename}, size={file_size}, chunks={total_chunks}, "
        f"user_id={auth.pat.user_id}"
    )

    # 6. Return session info
    return APIResponse(
        success=True,
        data={
            "task_id": task_id,
            "filename": filename,
            "file_size": file_size,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "status": "processing",
            "expires_at": task.expires_at.isoformat() if task.expires_at else None,
        },
    )


@router.post(
    "/upload/chunk",
    response_model=APIResponse[ChunkedUploadChunkResponse],
    status_code=status.HTTP_202_ACCEPTED,
)
async def upload_chunk(
    background_tasks: BackgroundTasks,
    task_id: int = Form(...),
    chunk_number: int = Form(..., ge=0),
    chunk: UploadFile = File(...),
    auth: AuthContext = Depends(require_scope("fcs:write")),
    db: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
):
    """
    Upload a single chunk for a chunked upload session.

    **Scope required:** `fcs:write`

    **Request (multipart/form-data):**
    - task_id: Upload session ID
    - chunk_number: Chunk sequence number (0-based)
    - chunk: Chunk file data

    **Returns:**
    - task_id: Upload session ID
    - chunk_number: Uploaded chunk number
    - uploaded_chunks: Number of chunks uploaded so far
    - total_chunks: Total number of chunks
    - progress_percentage: Upload progress percentage

    **Example:**
    ```bash
    # Upload chunk 0
    dd if=sample.fcs bs=5M count=1 skip=0 | curl -X POST \\
      http://localhost:8000/api/v1/fcs/upload/chunk \\
      -H "Authorization: Bearer pat_abc123..." \\
      -F "task_id=123" \\
      -F "chunk_number=0" \\
      -F "chunk=@-"
    ```
    """
    from app.models.background_task import BackgroundTask

    # 1. Get upload session
    task = db.query(BackgroundTask).filter_by(id=task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Upload session not found",
            },
        )

    # 1.5. Validate task type
    if task.task_type != "chunked_upload":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Task {task_id} is not an upload session",
            },
        )

    # 2. Permission check
    if task.user_id != auth.pat.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "Forbidden",
                "message": "Not your upload session",
            },
        )

    # 3. Validate session status
    if task.status not in ["pending", "processing"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Cannot upload to session with status: {task.status}",
            },
        )

    # 4. Validate chunk_number
    if chunk_number >= (task.extra_data or {}).get("total_chunks", 0):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Invalid chunk_number. Max is {(task.extra_data or {}).get('total_chunks', 0) - 1}",
            },
        )

    # 5. Read chunk data
    chunk_data = await chunk.read()

    # 5.5. Validate chunk size
    chunk_size = task.extra_data.get("chunk_size", 0)
    total_chunks = task.extra_data.get("total_chunks", 0)

    # Calculate expected size for this chunk
    # Last chunk may be smaller than chunk_size
    if chunk_number < total_chunks - 1:
        expected_size = chunk_size
    else:
        # Last chunk
        file_size = task.extra_data.get("file_size", 0)
        remaining = file_size % chunk_size
        expected_size = remaining if remaining != 0 else chunk_size

    if len(chunk_data) != expected_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": f"Chunk {chunk_number} size mismatch. Expected {expected_size} bytes, got {len(chunk_data)} bytes",
            },
        )

    # 5.6. Validate FCS format on first chunk
    if chunk_number == 0:
        from app.services.fcs import validate_fcs_header
        try:
            validate_fcs_header(chunk_data)
        except ValueError as e:
            # Log detailed error with stack trace for debugging
            logger.error(f"Invalid FCS file uploaded: {str(e)}", exc_info=True)
            # Return safe, static message to client (no internal details exposed)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "error": "Bad Request",
                    "message": "Invalid FCS file format",
                },
            )

    # 6. Save chunk (with timing)
    start_time = time.time()
    try:
        bytes_written = await storage.save_chunk(
            session_id=str(task_id),
            chunk_number=chunk_number,
            chunk_data=chunk_data,
            chunk_size=chunk_size,
        )
        chunk_upload_time_ms = int((time.time() - start_time) * 1000)

        # Update progress (Prevent double counting)
        from sqlalchemy.orm.attributes import flag_modified

        extra_data = task.extra_data or {}
        if chunk_number not in extra_data.get("uploaded_chunk_numbers", []):
            extra_data["uploaded_chunk_numbers"].append(chunk_number)
            extra_data["uploaded_chunks"] = extra_data.get("uploaded_chunks", 0) + 1
        extra_data["uploaded_bytes"] = extra_data.get("uploaded_bytes", 0) + bytes_written
        # Accumulate upload time (only count successful uploads)
        extra_data["accumulated_upload_ms"] = extra_data.get("accumulated_upload_ms", 0) + chunk_upload_time_ms
        task.extra_data = extra_data
        flag_modified(task, "extra_data")  # Explicitly mark JSON column as modified
        db.commit()

    except Exception as e:
        logger.error(f"Failed to save chunk {chunk_number}: {str(e)}", exc_info=True)
        task.status = "failed"
        task.result = {"error_message": "Failed to save chunk"}
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Internal Server Error",
                "message": "Failed to save chunk",
            },
        )

    # 7. Auto-trigger completion on last chunk
    is_last_chunk = (task.extra_data["uploaded_chunks"] == task.extra_data["total_chunks"])

    if is_last_chunk and task.status not in ["finalizing", "completed"]:
        # Trigger background completion task (don't set status here, let the background task handle it)
        from app.services.chunked_upload import finalize_chunked_upload
        background_tasks.add_task(
            finalize_chunked_upload,
            task_id=task_id,
            db_session_factory=lambda: db,  # Use current db session to avoid transaction issues in tests
        )

        logger.info(f"Auto-triggered finalization for task_id={task_id}")

    # 8. Calculate progress
    total_chunks = task.extra_data["total_chunks"]
    uploaded_chunks = task.extra_data["uploaded_chunks"]
    uploaded_bytes = task.extra_data["uploaded_bytes"]
    total_bytes = task.extra_data["file_size"]
    progress_percentage = round((uploaded_bytes / total_bytes) * 100, 2) if total_bytes > 0 else 0.0

    # 9. Return progress
    return APIResponse(
        success=True,
        data={
            "task_id": task_id,
            "chunk_number": chunk_number,
            "uploaded_chunks": uploaded_chunks,
            "total_chunks": total_chunks,
            "uploaded_bytes": uploaded_bytes,
            "total_bytes": total_bytes,
            "progress_percentage": progress_percentage,
            "status": task.status,
        },
    )


@router.post(
    "/upload/abort",
    response_model=APIResponse[dict],
    status_code=status.HTTP_200_OK,
)
async def abort_chunked_upload(
    task_id: int = Form(...),
    auth: AuthContext = Depends(require_scope("fcs:write")),
    db: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
):
    """
    Abort a chunked upload session and clean up resources.

    **Scope required:** `fcs:write`

    **Request (multipart/form-data):**
    - task_id: Upload session ID

    **Returns:**
    - task_id: Aborted session ID
    - status: "aborted"
    - message: Confirmation message

    **Example:**
    ```bash
    curl -X POST http://localhost:8000/api/v1/fcs/upload/abort \\
      -H "Authorization: Bearer pat_abc123..." \\
      -F "task_id=123"
    ```
    """
    from app.models.background_task import BackgroundTask

    # 1. Get upload session
    task = db.query(BackgroundTask).filter_by(id=task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Upload session not found",
            },
        )

    # 2. Permission check
    if task.user_id != auth.pat.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "Forbidden",
                "message": "Not your upload session",
            },
        )

    # 3. Cannot abort completed sessions
    if task.status == "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": "Cannot abort completed upload",
            },
        )

    # 4. Clean up storage
    try:
        await storage.abort_chunked_upload(str(task_id))
    except Exception as e:
        logger.error(f"Failed to cleanup upload session {task_id}: {str(e)}", exc_info=True)

    # 5. Update session
    task.status = "failed"
    task.result = {"error_message": "Upload aborted by user"}
    db.commit()

    # 6. Log
    logger.info(f"Upload session aborted: task_id={task_id}")

    return APIResponse(
        success=True,
        data={
            "task_id": task_id,
            "status": "failed",
            "message": "Upload session aborted successfully",
        },
    )


@router.get(
    "/statistics",
    response_model=APIResponse[FCSStatisticsResponseData | dict],
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

    Returns cached statistics if available. If a calculation is in progress,
    returns 202 with task information. If statistics haven't been calculated
    and no task is in progress, returns 404 with a message to call
    POST /statistics/calculate first.

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
        - 200: APIResponse with FCSStatisticsResponseData containing:
            - total_events: Total number of events
            - statistics: List of statistics for each parameter
        - 202: APIResponse with task info (task_id, status, message) if calculation in progress

    Raises:
        HTTPException 403: If private file and user is not owner
        HTTPException 404: If statistics not calculated yet and no task in progress
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

    # 3. Check for in-progress calculation task
    # For sample files, fcs_file_id is NULL; for uploaded files, it's the file's ID
    fcs_file_id_for_task = fcs_file.id if fcs_file else None

    in_progress_task = db.query(BackgroundTask).filter(
        BackgroundTask.fcs_file_id == fcs_file_id_for_task,
        BackgroundTask.task_type == "statistics",
        or_(
            BackgroundTask.status == "pending",
            BackgroundTask.status == "processing",
        ),
    ).first()

    if in_progress_task:
        logger.info(f"Statistics calculation in progress for file_id: {file_id_for_storage}, task_id: {in_progress_task.id}")
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "success": True,
                "data": {
                    "task_id": in_progress_task.id,
                    "status": in_progress_task.status,
                    "message": "Statistics calculation in progress",
                },
            },
        )

    # 4. Read from cache
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

    # 5. Return cached result
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
    from sqlalchemy import or_

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


def _is_task_public(db: Session, task: BackgroundTask) -> bool:
    """
    Determine if a task is publicly accessible.

    A task is public if:
    - Chunked upload: extra_data["is_public"] is True (before file creation)
                    OR fcs_file.is_public is True (after file creation)
    - Statistics: fcs_file_id is NULL (sample file)
                OR fcs_file.is_public is True

    Args:
        db: Database session
        task: BackgroundTask to check

    Returns:
        True if task is public, False if private
    """
    if task.task_type == "chunked_upload":
        # Check extra_data first (handles in-progress uploads)
        if task.extra_data and "is_public" in task.extra_data:
            return task.extra_data["is_public"]

        # Fall back to checking the created file
        if task.fcs_file:
            return task.fcs_file.is_public

        # Default to private if we can't determine (fail-safe)
        logger.warning(f"Chunked upload task {task.id} has no is_public info, defaulting to private")
        return False

    elif task.task_type == "statistics":
        # NULL fcs_file_id means sample file (public)
        if task.fcs_file_id is None:
            return True

        # Check the associated file's visibility
        if task.fcs_file:
            return task.fcs_file.is_public

        # File ID exists but file not found - treat as private for safety
        logger.warning(f"Statistics task {task.id} has fcs_file_id but no file loaded, treating as private")
        return False

    else:
        # Unknown task type - default to private for safety
        logger.warning(f"Unknown task_type '{task.task_type}' for task {task.id}, treating as private")
        return False


@router.get(
    "/tasks/{task_id}",
    response_model=APIResponse[TaskResponseData],
    status_code=status.HTTP_200_OK,
)
async def get_task_status_endpoint(
    task_id: int,
    request: Request,
    pat_data: tuple[PersonalAccessToken, list[Scope]] = Depends(get_pat_with_scopes),
    db: Session = Depends(get_db),
):
    """
    Get background task status and result.

    Returns the current status of a background task (statistics or chunked upload),
    along with the result if completed.

    **Dynamic Scope required:**
    - "chunked_upload" tasks: `fcs:write` scope
    - "statistics" tasks: `fcs:analyze` scope

    Args:
        task_id: Task ID (auto-increment integer)
        request: FastAPI Request object (for dynamic endpoint/method detection)
        pat_data: Tuple of (PAT, scopes) from authentication
        db: Database session

    Returns:
        APIResponse with TaskResponseData containing:
        - task_id: Task ID
        - status: Current status (pending, processing, finalizing, completed, failed)
        - created_at: Creation timestamp
        - completed_at: Completion timestamp (if completed/failed)
        - result: Task result based on task_type:
          - "statistics": Statistics data
          - "chunked_upload": Upload progress or FCSFile info

    Raises:
        HTTPException 404: If task not found
        HTTPException 403: If user doesn't own the task or lacks required scope
    """
    from app.models.background_task import BackgroundTask

    pat, scopes = pat_data

    # 1. Get task first (need task_type to determine required scope)
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

    # 2. Determine required scope based on task_type
    # Dynamic permission: upload tasks need fcs:write, statistics need fcs:analyze
    if task.task_type == "chunked_upload":
        required_scope = "fcs:write"
    elif task.task_type == "statistics":
        required_scope = "fcs:analyze"
    else:
        # Unknown task type - use highest level for safety
        required_scope = "fcs:analyze"
        logger.warning(f"Unknown task_type '{task.task_type}' for task {task_id}, using fcs:analyze")

    # 3. Check if user has the required scope for this task type
    check_permission_and_get_context(
        db=db,
        pat=pat,
        scopes=scopes,
        required_scope=required_scope,
        endpoint=request.url.path,
        method=request.method,
    )

    # 4. Access control: public tasks visible to all, private tasks only to owner
    is_task_public = _is_task_public(db, task)

    if not is_task_public:
        # Private task - only owner can view
        if task.user_id != pat.user_id:
            logger.warning(
                f"Private task access denied: task_id={task_id}, "
                f"user_id={pat.user_id}, owner={task.user_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": "Forbidden",
                    "message": "Private task - access denied",
                },
            )
    # Public task: no ownership check needed (already passed scope check)

    # 3. Build response data based on task_type
    response_data = {
        "task_id": task.id,
        "task_type": task.task_type,
        "status": task.status,
        "created_at": task.created_at.isoformat(),
    }

    if task.task_type == "statistics":
        # Statistics task - return existing format
        if task.status == "completed" and task.result:
            response_data["completed_at"] = task.completed_at.isoformat()
            response_data["result"] = task.result
        elif task.status == "failed" and task.result:
            response_data["completed_at"] = task.completed_at.isoformat()
            response_data["result"] = task.result

    elif task.task_type == "chunked_upload":
        # Chunked upload task - return upload progress or result
        if task.status == "processing":
            # Upload in progress - return progress from extra_data
            extra_data = task.extra_data or {}
            total_bytes = extra_data.get("file_size", 0)
            uploaded_bytes = extra_data.get("uploaded_bytes", 0)
            progress_percentage = round((uploaded_bytes / total_bytes) * 100, 2) if total_bytes > 0 else 0.0

            response_data["result"] = {
                "filename": extra_data.get("filename", ""),
                "file_size": total_bytes,
                "uploaded_bytes": uploaded_bytes,
                "uploaded_chunks": extra_data.get("uploaded_chunks", 0),
                "total_chunks": extra_data.get("total_chunks", 0),
                "progress_percentage": progress_percentage,
            }

        elif task.status == "finalizing":
            # Parsing FCS file
            response_data["result"] = {
                "message": "Parsing FCS file...",
                "filename": task.extra_data.get("filename", "") if task.extra_data else "",
            }

        elif task.status == "completed":
            # Upload completed - return FCSFile info with download URL
            response_data["completed_at"] = task.completed_at.isoformat()
            if task.result:
                response_data["result"] = task.result  # {file_id, filename, total_events, total_parameters}
                # Add upload duration if available
                if task.fcs_file and task.fcs_file.upload_duration_ms is not None:
                    response_data["result"]["upload_duration_ms"] = task.fcs_file.upload_duration_ms
                # Add download_url if file_id exists
                if "file_id" in task.result:
                    response_data["result"]["download_url"] = (
                        f"/api/v1/fcs/files/{task.result['file_id']}/download"
                    )
            elif task.fcs_file:
                # Fallback: get from FCSFile relation
                response_data["result"] = {
                    "file_id": task.fcs_file.file_id,
                    "filename": task.fcs_file.filename,
                    "total_events": task.fcs_file.total_events,
                    "total_parameters": task.fcs_file.total_parameters,
                    "upload_duration_ms": task.fcs_file.upload_duration_ms,
                    "download_url": (
                        f"/api/v1/fcs/files/{task.fcs_file.file_id}/download"
                    ),
                }

        elif task.status == "failed":
            # Upload failed
            response_data["completed_at"] = task.completed_at.isoformat() if task.completed_at else None
            response_data["result"] = task.result or {"error_message": "Upload failed"}

    logger.info(f"Task status requested: task_id={task_id}, task_type={task.task_type}, status={task.status}")

    return APIResponse(success=True, data=response_data)


@router.get(
    "/files/{file_id}/download",
    status_code=status.HTTP_200_OK,
)
async def download_fcs_file(
    file_id: str,
    auth: AuthContext = Depends(require_scope("fcs:read")),
    db: Session = Depends(get_db),
):
    """
    Download FCS file by short ID.

    **Scope required:** `fcs:read`

    **Permissions:**
    - Public files: Any user with `fcs:read` scope
    - Private files: Only file owner

    **Streaming Response:**
    - Returns file stream for large files (up to 1GB)
    - Content-Disposition: attachment (triggers browser download)

    Args:
        file_id: Short file identifier (12-character base62)
        auth: AuthContext containing PAT and user info
        db: Database session

    Returns:
        FileResponse with streaming file download

    Raises:
        HTTPException 403: Private file access by non-owner
        HTTPException 404: File not found
    """
    # 1. Get file path and metadata
    try:
        file_path, filename, fcs_file = get_fcs_file_for_download(file_id, db)
    except ValueError as e:
        logger.warning(f"FCS file download failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "FCS file not found",
            },
        )

    # 2. Permission check for private files
    if not fcs_file.is_public:
        pat_user_id = auth.pat.user_id if auth.pat else None
        if fcs_file.user_id != pat_user_id:
            logger.warning(
                f"Private file access denied: file_id={file_id}, "
                f"user_id={pat_user_id}, owner={fcs_file.user_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": "Forbidden",
                    "message": "Private file - access denied",
                },
            )

    # 3. Verify file exists on disk
    if not Path(file_path).exists():
        logger.error(f"File not found on disk: {file_path}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "File not available",
            },
        )

    # 4. Return streaming file response
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream",
        content_disposition_type="attachment",
    )
