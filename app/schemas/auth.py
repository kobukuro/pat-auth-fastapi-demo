from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.utils.validators import PasswordValidationError, validate_password_complexity


# 當一個類別繼承了Pydantic的BaseModel，它會自動獲得以下功能：
# 自動型別驗證:確保輸入的資料符合定義的型別（如 email 必須是合法的 Email 格式
# 資料轉換:自動將字串轉成對應型別（如 "123" 轉成 int）
# 序列化/反序列化:支援將物件轉成JSON字典，或從字典建立物件
# 欄位驗證:支援自訂驗證器
# 自動產生文件:FastAPI會自動根據Schema產生API文件（Swagger UI）
# 另外，如果驗證失敗，Pydantic會拋出ValidationError例外
class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

    # field_validator是Pydantic的裝飾器，
    # 用來對特定欄位進行自定義驗證。
    # 這裡表示要對password欄位執行額外的驗證邏輯。
    @field_validator('password')
    # @classmethod是Python的「類別方法」裝飾器
    # 將這個方法綁定到類別本身，而不是instance
    # 在Pydantic驗證器中必須使用@classmethod，
    # 因為Pydantic會直接透過類別來呼叫這個方法，而不需要先建立物件實例
    @classmethod
    # 參數v代表要驗證的密碼字串
    def validate_password(cls, v: str) -> str:
        """Validate password complexity"""
        try:
            validate_password_complexity(v)
        except PasswordValidationError as e:
            # 這裡轉換成ValueError，
            # 因為Pydantic的欄位驗證器只會攔截ValueError、TypeError等標準例外類型
            raise ValueError('; '.join(e.errors))
        # 如果密碼驗證通過，回傳原始的密碼值v
        # Pydantic會將這個回傳值存入模型的欄位中
        return v


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: datetime

    # 這行是Pydantic v2的模型配置設定，用來告訴這個UserResponse類別可以「從物件屬性」建立實例
    # 為什麼需要這個設定？
    #   沒有這個設定的情況：
    #   # 假設 user 是從資料庫查詢出來的SQLAlchemy ORM物件
    #   user = db.query(User).first()
    #   ❌ 這樣會報錯
    #   response = UserResponse(
    #       id=user.id,
    #       email=user.email,
    #       created_at=user.created_at
    #   )
    #
    #   有這個設定後：
    #   ✅ 可以直接傳入ORM物件，Pydantic會自動從屬性讀取資料
    #   response = UserResponse.from_orm(user)  # Pydantic v1 語法
    #   或
    #   response = UserResponse.model_validate(user)  # Pydantic v2 語法
    #
    #   在 FastAPI 中更方便，可以直接回傳ORM物件
    #   @router.get("/users/{user_id}")
    #   def get_user(user_id: int, db: Session = Depends(get_db)):
    #       user = db.query(User).get(user_id)
    #       return user  # FastAPI 會自動用UserResponse轉換
    #
    #   實際應用場景
    #   在這個專案中，當API端點需要回傳使用者資料時：
    #
    #   這個user物件是SQLAlchemy ORM模型
    #   user = db.query(User).filter(User.email == email).first()
    #
    #   因為有 from_attributes=True，
    #   FastAPI可以自動把這個ORM物件轉換成JSON回應
    #   return UserResponse(
    #       id=user.id,
    #       email=user.email,
    #       created_at=user.created_at
    #   )
    model_config = ConfigDict(from_attributes=True)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
