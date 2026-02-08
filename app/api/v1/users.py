"""
Users stub endpoints.

This module provides stub implementations for users-related endpoints.
These endpoints demonstrate PAT-based authorization without implementing
actual user profile functionality.
"""
from fastapi import APIRouter, Depends, status

from app.dependencies.pat import AuthContext, require_scope
from app.schemas.common import APIResponse
from app.schemas.users import UsersStubResponseData

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=APIResponse[UsersStubResponseData],
    status_code=status.HTTP_200_OK,
)
def get_current_user(
    auth: AuthContext = Depends(require_scope("users:read")),
):
    """
    Stub endpoint for getting current user information.

    This endpoint returns metadata about the endpoint and permission check,
    rather than actual user data. It demonstrates the scope-based
    authorization system for user profile operations.

    Args:
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with UsersStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=UsersStubResponseData(
            endpoint=auth.endpoint,
            method=auth.method,
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=[scope.name for scope in auth.scopes],
        ),
    )


@router.put(
    "/me",
    response_model=APIResponse[UsersStubResponseData],
    status_code=status.HTTP_200_OK,
)
def update_current_user(
    auth: AuthContext = Depends(require_scope("users:write")),
):
    """
    Stub endpoint for updating current user information.

    This endpoint returns metadata about the endpoint and permission check,
    rather than actual user data. It demonstrates the scope-based
    authorization system for user profile update operations.

    Args:
        auth: AuthContext containing PAT, scopes, and permission info

    Returns:
        APIResponse with UsersStubResponseData containing endpoint metadata
    """
    return APIResponse(
        success=True,
        data=UsersStubResponseData(
            endpoint=auth.endpoint,
            method=auth.method,
            required_scope=auth.required_scope,
            granted_by=auth.granted_by,
            your_scopes=[scope.name for scope in auth.scopes],
        ),
    )
