"""
Background task database model.

This module defines the BackgroundTask model for storing async task metadata,
for US-MVP-003 statistics calculation feature.
"""
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Index, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.fcs_file import FCSFile
    from app.models.user import User


class BackgroundTask(Base):
    """
    Background task model for async job tracking.

    Tracks the status and results of background tasks for operations like
    statistics calculation.

    Attributes:
        id: Primary key (used as task_id for API)
        task_type: Type of task (e.g., "statistics")
        fcs_file_id: Associated FCS file (nullable for sample files)
        status: Task status (pending, processing, completed, failed)
        result: Task result data (JSON)
        created_at: Task creation timestamp
        completed_at: Task completion timestamp
        user_id: ID of the user who initiated the task
    """

    __tablename__ = "background_tasks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    task_type: Mapped[str] = mapped_column(String(50))  # "statistics"
    fcs_file_id: Mapped[int | None] = mapped_column(
        ForeignKey("fcs_files.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    user: Mapped["User"] = relationship("User")
    fcs_file: Mapped["FCSFile"] = relationship("FCSFile")

    @property
    def task_id(self) -> int:
        """Return id as task_id for API compatibility."""
        return self.id

    __table_args__ = (
        Index("idx_background_tasks_file_type_status", "fcs_file_id", "task_type", "status"),
    )

    def __repr__(self) -> str:
        return f"<BackgroundTask(id={self.id}, task_type={self.task_type}, status={self.status})>"
