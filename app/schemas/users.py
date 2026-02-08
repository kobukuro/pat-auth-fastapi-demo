"""
Schemas for users stub endpoints.

This module defines Pydantic schemas for the users stub API responses.
Since users is a stub implementation, these schemas return metadata
about the endpoint and permission checks rather than actual user data.
"""
from pydantic import BaseModel


class UsersStubResponseData(BaseModel):
    """Response data for successful users stub endpoint call."""

    endpoint: str
    """The endpoint path (e.g., "/api/v1/users/me")"""

    method: str
    """The HTTP method (e.g., "GET")"""

    required_scope: str
    """The scope required to access this endpoint (e.g., "users:read")"""

    granted_by: str | None
    """The scope from the user's token that granted access.
    None if the user doesn't have access."""

    your_scopes: list[str]
    """List of all scopes associated with the user's PAT"""


class UsersStubErrorData(BaseModel):
    """Error response data when access is forbidden (403)."""

    required_scope: str
    """The scope required to access this endpoint"""

    your_scopes: list[str]
    """List of scopes the user has (which don't satisfy the requirement)"""
