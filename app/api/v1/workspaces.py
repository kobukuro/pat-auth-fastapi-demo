"""
Workspaces stub endpoints.

This module provides stub implementations for workspaces-related endpoints.
These endpoints demonstrate PAT-based authorization without implementing
actual workspace functionality.
"""
from fastapi import APIRouter, Depends, status

from app.dependencies.pat import AuthContext, require_scope
from app.schemas.common import APIResponse
from app.schemas.workspaces import WorkspacesStubResponseData

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


@router.get(
    "",
    response_model=APIResponse[WorkspacesStubResponseData],
    status_code=status.HTTP_200_OK,
)
def list_workspaces(
    auth: AuthContext = Depends(require_scope("workspaces:read")),
):
    """
    Stub endpoint for testing PAT-based permissions.

    This endpoint returns metadata about the endpoint and permission check,
    rather than actual workspace data. It demonstrates the scope-based
    authorization system.

    Args:
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with WorkspacesStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=WorkspacesStubResponseData(
            endpoint=auth.endpoint,
            method=auth.method,
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=auth.scopes,
        ),
    )


@router.post(
    "",
    response_model=APIResponse[WorkspacesStubResponseData],
    status_code=status.HTTP_200_OK,
)
def create_workspace(
    auth: AuthContext = Depends(require_scope("workspaces:write")),
):
    """
    Stub endpoint for creating a workspace.

    This endpoint requires workspaces:write scope and returns metadata about
    the endpoint and permission check, rather than actual workspace data.
    It demonstrates the scope-based authorization system for write operations.

    Args:
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with WorkspacesStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=WorkspacesStubResponseData(
            endpoint=auth.endpoint,
            method=auth.method,
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=auth.scopes,
        ),
    )
