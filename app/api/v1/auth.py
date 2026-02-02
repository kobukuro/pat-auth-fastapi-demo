from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.auth import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse
from app.schemas.common import APIResponse
from app.services.auth import hash_password, verify_password
from app.services.jwt import create_access_token

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


@router.post("/login", response_model=APIResponse[TokenResponse])
def login(request: UserLoginRequest, db: Session = Depends(get_db)):
    # Find user
    stmt = select(User).where(User.username == request.username)
    user = db.execute(stmt).scalar_one_or_none()

    # Verify password
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": "Unauthorized",
                "message": "Invalid credentials",
            },
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "Forbidden",
                "message": "User is inactive",
            },
        )

    # Create JWT
    access_token = create_access_token(user.id)
    return APIResponse(success=True, data=TokenResponse(access_token=access_token))
