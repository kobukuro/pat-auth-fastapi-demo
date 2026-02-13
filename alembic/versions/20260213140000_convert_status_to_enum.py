"""Convert status to Enum

Revision ID: 20260213140000
Revises: 20260213130000
Create Date: 2026-02-13 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260213140000'
down_revision: Union[str, Sequence[str], None] = '20260213130000'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Convert status from VARCHAR to ENUM."""

    # 1. Create ENUM type
    op.execute("CREATE TYPE taskstatus AS ENUM ('pending', 'processing', 'finalizing', 'completed', 'failed', 'expired')")

    # 2. Alter column to use ENUM (PostgreSQL handles string conversion)
    op.execute(
        "ALTER TABLE background_tasks "
        "ALTER COLUMN status TYPE taskstatus "
        "USING status::text::taskstatus"
    )


def downgrade() -> None:
    """Downgrade schema: Revert status from ENUM to VARCHAR(20)."""

    # 1. Revert column to VARCHAR(20) and restore original default
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status DROP DEFAULT,
        ALTER COLUMN status TYPE VARCHAR(20) USING status::text,
        ALTER COLUMN status SET DEFAULT 'pending'
    """)

    # 2. Drop ENUM type
    op.execute("DROP TYPE taskstatus")
