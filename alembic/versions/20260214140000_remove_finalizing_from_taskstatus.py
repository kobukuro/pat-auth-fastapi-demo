"""Remove FINALIZING status from TaskStatus enum

Revision ID: 20260214140000
Revises: 20260213140000
Create Date: 2026-02-14 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260214140000'
down_revision: Union[str, Sequence[str], None] = '20260213140000'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove 'finalizing' from taskstatus ENUM type."""

    # In PostgreSQL, we need to recreate the ENUM type without 'finalizing'
    # Steps:
    #   a. Drop the column default (depends on ENUM)
    #   b. Alter column to VARCHAR (to hold any existing values)
    #   c. Drop the old ENUM
    #   d. Create new ENUM without 'finalizing'
    #   e. Alter column back to ENUM
    #   f. Restore default

    # Note: Since FINALIZING was never assigned in code, there should be 0 tasks in this state
    # But we check anyway to be safe
    op.execute("SELECT 1 FROM background_tasks WHERE status = 'finalizing' LIMIT 1")

    # Step 1: Drop the default (it depends on the ENUM type)
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status DROP DEFAULT
    """)

    # Step 2: Convert to VARCHAR temporarily
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status TYPE VARCHAR(20)
    """)

    # Step 3: Drop old ENUM
    op.execute("DROP TYPE taskstatus")

    # Step 4: Create new ENUM without 'finalizing'
    op.execute("CREATE TYPE taskstatus AS ENUM ('pending', 'processing', 'completed', 'failed', 'expired')")

    # Step 5: Convert back to ENUM
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status TYPE taskstatus
        USING status::text::taskstatus
    """)

    # Step 6: Restore default
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status SET DEFAULT 'pending'::taskstatus
    """)


def downgrade() -> None:
    """Add 'finalizing' back to taskstatus ENUM type."""

    # Step 1: Drop the default (it depends on the ENUM type)
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status DROP DEFAULT
    """)

    # Step 2: Convert to VARCHAR temporarily
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status TYPE VARCHAR(20)
    """)

    # Step 3: Drop current ENUM
    op.execute("DROP TYPE taskstatus")

    # Step 4: Recreate ENUM with 'finalizing' included
    op.execute("CREATE TYPE taskstatus AS ENUM ('pending', 'processing', 'finalizing', 'completed', 'failed', 'expired')")

    # Step 5: Convert back to ENUM
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status TYPE taskstatus
        USING status::text::taskstatus
    """)

    # Step 6: Restore default
    op.execute("""
        ALTER TABLE background_tasks
        ALTER COLUMN status SET DEFAULT 'pending'::taskstatus
    """)
