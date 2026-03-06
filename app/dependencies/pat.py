"""
PAT authentication dependencies for protected resource endpoints.

This module provides dependencies for validating Personal Access Tokens (PATs)
and extracting their associated scopes for authorization checks.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.pat import PersonalAccessToken
from app.models.scope import Scope
from app.services.pat import has_permission_with_granting_scope

security = HTTPBearer()


def get_pat_with_scopes(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> tuple[PersonalAccessToken, list[Scope]]:
    """
    Validate PAT token and return PAT record with scopes.

    This dependency validates a Personal Access Token from the Authorization
    header and returns both the PAT record and its associated scopes for
    use in protected resource endpoints.

    Args:
        credentials: HTTP Bearer credentials from the Authorization header
        db: Database session

    Returns:
        A tuple of (PAT record, list of Scope objects)

    Raises:
        HTTPException: 401 if token is invalid, expired, or revoked
    """
    token = credentials.credentials

    # Check token format (must start with "pat_")
    if not token.startswith("pat_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "Unauthorized",
                "message": "Invalid token",
            },
        )

    # Lookup token using indexed prefix with hash verification
    from app.services.pat import get_pat_by_token

    pat = get_pat_by_token(db, token)

    if not pat:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "Unauthorized",
                "message": "Invalid token",
            },
        )

    # Check if token is revoked
    if pat.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "Unauthorized",
                "message": "Token revoked",
            },
        )

    # Check if token is expired
    # Handle both timezone-aware and naive datetimes from database
    now = datetime.now(timezone.utc)
    expires_at = pat.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "Unauthorized",
                "message": "Token expired",
            },
        )

    # Use ORM relationship (lazy="selectin" preloads scopes)
    scopes = pat.scopes

    return pat, scopes


@dataclass
class AuthContext:
    """Context object containing authentication and authorization information."""

    pat: PersonalAccessToken
    """The validated Personal Access Token"""

    scopes: list[Scope]
    """List of Scope objects associated with the PAT"""

    required_scope: str
    """The scope required for the current endpoint"""

    granted_by: str | None
    """The scope from user's token that granted access (highest level)"""

    endpoint: str
    """The endpoint path (e.g., "/api/v1/workspaces")"""

    method: str
    """The HTTP method (e.g., "GET")"""


def require_scope(required_scope: str):
    """
    Factory that creates a dependency to check for a specific scope.

    Args:
        required_scope: The scope required for this endpoint (e.g., "workspaces:read")

    Returns:
        A dependency that validates PAT has the required scope and returns AuthContext
    """
    def dependency(
        request: Request,
        pat_data: tuple[PersonalAccessToken, list[Scope]] = Depends(get_pat_with_scopes),
        db: Session = Depends(get_db),
    ) -> AuthContext:
        pat, scopes = pat_data

        # Check if user has required scope (optimized: single DB query)
        has_perm, granted_by = has_permission_with_granting_scope(
            db, scopes, required_scope
        )

        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": "Forbidden",
                    "data": {
                        "required_scope": required_scope,
                        "your_scopes": [scope.name for scope in scopes],
                    },
                },
            )

        return AuthContext(
            pat=pat,
            scopes=scopes,
            required_scope=required_scope,
            granted_by=granted_by,
            endpoint=request.url.path,
            method=request.method,
        )

    return dependency
