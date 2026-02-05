from datetime import datetime

from pydantic import BaseModel, Field, model_serializer


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

    @model_serializer
    def serialize_model(self):
        """Custom serializer to exclude reason field for authorized requests."""
        data = {
            "timestamp": self.timestamp,
            "ip_address": self.ip,
            "method": self.method,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "authorized": self.authorized,
        }
        # Only include reason for unauthorized requests
        if not self.authorized and self.reason is not None:
            data["reason"] = self.reason
        return data


class TokenAuditLogsResponse(BaseModel):
    """Response schema for token audit logs."""

    token_id: str = Field(alias="token_id")
    token_name: str
    total_logs: int
    logs: list[AuditLogEntry]
    model_config = {"populate_by_name": True}
