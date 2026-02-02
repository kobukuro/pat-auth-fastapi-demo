from datetime import datetime

from pydantic import BaseModel, Field


class PATCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1)
    expires_in_days: int = Field(ge=1, le=365, default=30)


class PATCreateResponse(BaseModel):
    id: int
    name: str
    token: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime
