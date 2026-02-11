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

# tags為標籤，用於 API 文件分組，在 Swagger自動文件頁面會顯示為「auth」區塊
router = APIRouter(prefix="/auth", tags=["auth"])

# decorator中response_model為成功時的預設回傳格式，status_code為成功時的預設status code，
@router.post(
    "/register",
    response_model=APIResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
)
# Depends為FastAPI的依賴注入機制
def register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    # Normalize email to lowercase
    email = request.email.lower()

    # Check if email already exists
    stmt = select(User).where(User.email == email)
    existing_user = db.execute(stmt).scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "error": "Bad Request", "message": "Email already exists"},
        )

    # Create new user
    user = User(
        email=email,
        hashed_password=hash_password(request.password),
    )

    try:
        db.add(user)
        db.commit()
        # 從資料庫重新查詢這個user，更新Python物件的屬性(user.id和user.created_at等, 不然值還是None, 因為這些是DB自動生成的)
        # 否則會導致回傳的UserResponse缺少這些欄位
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "error": "Bad Request", "message": "Email already exists"},
        )
    # model_validate為將ORM物件轉換成Pydantic模型
    # 為什麼需要 model_validate()？
    #   - SQLAlchemy ORM物件可能有lazy loading的關聯、資料庫session等額外資訊
    #   - Pydantic模型只包含定義的欄位（id, email, created_at）
    #   - model_validate() 確保只返回UserResponse定義的欄位，不會洩漏敏感資訊
    return APIResponse(success=True, data=UserResponse.model_validate(user))


@router.post("/login", response_model=APIResponse[TokenResponse])
def login(request: UserLoginRequest, db: Session = Depends(get_db)):
    # Normalize email to lowercase
    email = request.email.lower()

    # Find user
    stmt = select(User).where(User.email == email)
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
