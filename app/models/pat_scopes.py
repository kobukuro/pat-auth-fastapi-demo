from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PATScope(Base):
    """Junction table for PersonalAccessToken and Scope many-to-many relationship."""
    __tablename__ = "pat_scopes"

    pat_id: Mapped[int] = mapped_column(
        ForeignKey("personal_access_tokens.id", ondelete="CASCADE"),
        primary_key=True
    )
    scope_id: Mapped[int] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"),
        primary_key=True
    )
