from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PersonalAccessTokenAuditLog(Base):
    """Audit log for Personal Access Token usage."""

    __tablename__ = "personal_access_token_audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token_id: Mapped[int] = mapped_column(ForeignKey("personal_access_tokens.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))  # IPv6 compatible
    method: Mapped[str] = mapped_column(String(10))  # GET, POST, etc.
    endpoint: Mapped[str] = mapped_column(String(500))
    status_code: Mapped[int] = mapped_column()
    authorized: Mapped[bool] = mapped_column()
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)  # For unauthorized requests
