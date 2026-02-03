"""
FCS API endpoints.

This module provides API endpoints for FCS (Flow Cytometry Standard) file operations,
including parameter retrieval. Future endpoints will support file upload, events query,
and statistics calculation.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status

from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.pat import AuthContext, require_scope
from app.logging_config import setup_logging
from app.schemas.common import APIResponse
from app.schemas.fcs import FCSEventsResponseData, FCSParametersResponseData
from app.services.fcs import (
    get_fcs_events,
    get_fcs_file_path,
    get_fcs_parameters,
    get_sample_fcs_path,
)

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
