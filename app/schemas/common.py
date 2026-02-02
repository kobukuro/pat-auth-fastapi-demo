from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    message: str
