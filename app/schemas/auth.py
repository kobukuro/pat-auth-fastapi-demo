from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.utils.validators import PasswordValidationError, validate_password_complexity


# 當一個類別繼承了Pydantic的BaseModel，它會自動獲得以下功能：
# 自動型別驗證:確保輸入的資料符合定義的型別（如 email 必須是合法的 Email 格式
# 資料轉換:自動將字串轉成對應型別（如 "123" 轉成 int）
# 序列化/反序列化:支援將物件轉成JSON字典，或從字典建立物件
# 欄位驗證:支援自訂驗證器
# 自動產生文件:FastAPI會自動根據Schema產生API文件（Swagger UI）
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

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
