from datetime import datetime

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """Single audit log entry for a PAT usage."""

    timestamp: datetime
    ip: str = Field(alias="ip_address")
    method: str
    endpoint: str
    status_code: int
    authorized: bool
    reason: str | None = None
    model_config = {"populate_by_name": True}


class TokenAuditLogsResponse(BaseModel):
    """Response schema for token audit logs."""

    token_id: str = Field(alias="token_id")
    token_name: str
    total_logs: int
    logs: list[AuditLogEntry]
    model_config = {"populate_by_name": True}
