from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.auth import UserRegisterRequest, UserResponse
from app.schemas.common import APIResponse
from app.services.auth import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=APIResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
)
def register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    # Check if username already exists
    stmt = select(User).where(User.username == request.username)
    existing_user = db.execute(stmt).scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "error": "Bad Request", "message": "Username already exists"},
        )

    # Create new user
    user = User(
        username=request.username,
        hashed_password=hash_password(request.password),
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "error": "Bad Request", "message": "Username already exists"},
        )

    return APIResponse(success=True, data=UserResponse.model_validate(user))
