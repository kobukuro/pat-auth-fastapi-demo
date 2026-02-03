from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user
from app.models.pat import PersonalAccessToken
from app.models.user import User


def get_token_by_id(
    token_id: int,
    db: Session = Depends(get_db)
) -> PersonalAccessToken:
    """Get PAT by ID and verify it exists.

    Raises 404 if token not found.
    """
    token = db.execute(
        select(PersonalAccessToken).where(PersonalAccessToken.id == token_id)
    ).scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Token not found",
            },
        )

    return token


def verify_token_ownership(
    token: PersonalAccessToken = Depends(get_token_by_id),
    current_user: User = Depends(get_current_user)
) -> PersonalAccessToken:
    """Verify PAT belongs to the current user.

    Raises 404 if token doesn't belong to user (security: hide existence).
    """
    if token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Not Found",
                "message": "Token not found",
            },
        )

    return token


# Convenience dependency that combines both checks
def get_validated_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> PersonalAccessToken:
    """Get PAT by ID and verify ownership.

    This is a single dependency that performs both checks.
    Use this as a drop-in replacement for the duplicated validation logic.
    """
    token = get_token_by_id(token_id, db)
    return verify_token_ownership(token, current_user)
