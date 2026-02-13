"""Convert task_type to Enum

Revision ID: 20260213130000
Revises: 599510ba07cc
Create Date: 2026-02-13 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20260213130000'
down_revision: Union[str, Sequence[str], None] = '599510ba07cc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Convert task_type from VARCHAR to ENUM."""

    # 1. Create ENUM type
    op.execute("CREATE TYPE tasktype AS ENUM ('statistics', 'chunked_upload')")

    # 2. Alter column to use ENUM (PostgreSQL handles string conversion)
    op.execute(
        "ALTER TABLE background_tasks "
        "ALTER COLUMN task_type TYPE tasktype "
        "USING task_type::text::tasktype"
    )


def downgrade() -> None:
    """Downgrade schema: Revert task_type from ENUM to VARCHAR(50)."""

    # 1. Revert column to VARCHAR(50)
    op.execute(
        "ALTER TABLE background_tasks "
        "ALTER COLUMN task_type TYPE VARCHAR(50)"
    )

    # 2. Drop ENUM type
    op.execute("DROP TYPE tasktype")
