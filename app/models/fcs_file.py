"""
FCS file database model.

This module defines the FCSFile model for storing uploaded FCS file metadata,
including file information, parsed metadata, and access control settings.
"""
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class FCSFile(Base):
    """
    FCS file model for storing uploaded FCS file metadata.

    Attributes:
        id: Primary key
        file_id: Unique identifier for short links (UUID or base62)
        filename: Original filename
        file_path: Storage path
        file_size: File size in bytes
        total_events: Total number of events (stored after parsing)
        total_parameters: Total number of parameters (stored after parsing)
        is_public: Whether the file is publicly accessible
        upload_duration_ms: Upload duration in milliseconds (US-MVP-001 requirement)
        uploaded_at: Upload timestamp
        user_id: ID of the user who uploaded the file
    """

    __tablename__ = "fcs_files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    file_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(500))
    file_size: Mapped[int] = mapped_column(BigInteger)
    total_events: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_parameters: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True)
    upload_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(server_default=func.now())
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    user: Mapped["User"] = relationship("User", back_populates="fcs_files")

    def __repr__(self) -> str:
        return f"<FCSFile(id={self.id}, file_id={self.file_id}, filename={self.filename})>"
