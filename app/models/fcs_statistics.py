"""
FCS statistics storage database model.

This module defines the FCSStatistics model for storing calculated statistics
for FCS files, allowing fast retrieval without recalculating.
"""
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.fcs_file import FCSFile


class FCSStatistics(Base):
    """
    Stored FCS file statistics.

    Stores calculated statistics for FCS files to avoid recomputation.
    One record per file (identified by file_id).

    Attributes:
        id: Primary key
        file_id: Unique identifier ("sample" for sample file, or file_id for uploads)
        fcs_file_id: Foreign key to FCSFile (nullable for sample files)
        statistics: Statistics data as JSON
        total_events: Total number of events (stored)
        calculated_at: When statistics were calculated
    """

    __tablename__ = "fcs_statistics"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    fcs_file_id: Mapped[int | None] = mapped_column(
        ForeignKey("fcs_files.id"), nullable=True
    )
    statistics: Mapped[list[dict]] = mapped_column(JSON)
    total_events: Mapped[int] = mapped_column(index=True)
    calculated_at: Mapped[datetime] = mapped_column(server_default=func.now())

    fcs_file: Mapped["FCSFile"] = relationship("FCSFile")

    __table_args__ = (
        Index("idx_fcs_statistics_file_id", "file_id"),
        Index("idx_fcs_statistics_fcs_file_id", "fcs_file_id"),
    )

    def __repr__(self) -> str:
        return f"<FCSStatistics(id={self.id}, file_id={self.file_id}, total_events={self.total_events})>"
