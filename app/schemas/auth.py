from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.utils.validators import PasswordValidationError, validate_password_complexity


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password complexity"""
        try:
            validate_password_complexity(v)
        except PasswordValidationError as e:
            raise ValueError('; '.join(e.errors))
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
