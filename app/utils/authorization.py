"""
Authorization utilities for dynamic permission checking.

This module provides helper functions for checking permissions dynamically
based on resource attributes, rather than using fixed scope requirements.
"""
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.scope import Scope
from app.services.pat import has_permission


def check_permission_and_get_context(
    db: Session,
    scopes: list[Scope],
    required_scope: str,
) -> None:
    """
    Check if user has required scope and raise 403 if not.

    This is a manual version of require_scope() for use when permissions
    need to be checked dynamically after fetching resource data.

    Args:
        db: Database session
        scopes: List of Scope objects from user's PAT
        required_scope: The scope required for this operation

    Raises:
        HTTPException: 403 if user lacks required scope
    """
    if not has_permission(db, scopes, required_scope):
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
