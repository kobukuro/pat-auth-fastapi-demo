"""
Background task database model (reserved for future use).

This module defines the BackgroundTask model for storing async task metadata,
primarily for US-MVP-003 statistics calculation feature.
"""
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.fcs_file import FCSFile
    from app.models.user import User


class BackgroundTask(Base):
    """
    Background task model for async job tracking.

    This model is reserved for US-MVP-003 statistics calculation feature.
    It tracks the status and results of background tasks.

    Attributes:
        id: Primary key
        task_id: Unique identifier for querying task status (UUID)
        task_type: Type of task (e.g., "statistics", "analysis")
        fcs_file_id: Associated FCS file
        status: Task status (pending, processing, completed, failed)
        result: Task result data (JSON)
        created_at: Task creation timestamp
        completed_at: Task completion timestamp
        user_id: ID of the user who initiated the task
    """

    __tablename__ = "background_tasks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    task_type: Mapped[str] = mapped_column(String(50))
    fcs_file_id: Mapped[int] = mapped_column(ForeignKey("fcs_files.id"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    fcs_file: Mapped["FCSFile"] = relationship("FCSFile")
    user: Mapped["User"] = relationship("User")

    def __repr__(self) -> str:
        return f"<BackgroundTask(id={self.id}, task_id={self.task_id}, status={self.status})>"
