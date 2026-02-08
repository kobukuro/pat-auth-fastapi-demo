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
            your_scopes=[scope.name for scope in auth.scopes],
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
            your_scopes=[scope.name for scope in auth.scopes],
        ),
    )


@router.delete(
    "/{id}",
    response_model=APIResponse[WorkspacesStubResponseData],
    status_code=status.HTTP_200_OK,
)
def delete_workspace(
    id: str,
    auth: AuthContext = Depends(require_scope("workspaces:delete")),
):
    """
    Stub endpoint for deleting a workspace.

    This endpoint requires workspaces:delete scope and returns metadata about
    the endpoint and permission check, rather than actual workspace data.
    It demonstrates the scope-based authorization system for delete operations.

    Args:
        id: The workspace ID to delete
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with WorkspacesStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=WorkspacesStubResponseData(
            endpoint=f"/api/v1/workspaces/{id}",
            method="DELETE",
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=[scope.name for scope in auth.scopes],
        ),
    )


@router.put(
    "/{id}/settings",
    response_model=APIResponse[WorkspacesStubResponseData],
    status_code=status.HTTP_200_OK,
)
def update_workspace_settings(
    id: str,
    auth: AuthContext = Depends(require_scope("workspaces:admin")),
):
    """
    Stub endpoint for updating workspace settings.

    This endpoint requires workspaces:admin scope (the highest level) and returns
    metadata about the endpoint and permission check, rather than actual settings data.
    It demonstrates the scope-based authorization system for admin operations.

    Args:
        id: The workspace ID to update settings for
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with WorkspacesStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=WorkspacesStubResponseData(
            endpoint=f"/api/v1/workspaces/{id}/settings",
            method="PUT",
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=[scope.name for scope in auth.scopes],
        ),
    )
