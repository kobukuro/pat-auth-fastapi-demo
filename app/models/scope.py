from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.pat import PersonalAccessToken


class Scope(Base):
    __tablename__ = "scopes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    resource: Mapped[str] = mapped_column(String(50), index=True)
    action: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(100), unique=True)
    level: Mapped[int] = mapped_column()

    tokens: Mapped[list["PersonalAccessToken"]] = relationship(
        "PersonalAccessToken",
        secondary="pat_scopes",
        back_populates="scopes"
    )

    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_scope_resource_action"),
        CheckConstraint("name = resource || ':' || action", name="ck_scope_name_consistency"),
    )
