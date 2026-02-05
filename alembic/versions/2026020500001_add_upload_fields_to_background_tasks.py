"""Add upload fields to background_tasks table

Revision ID: 2026020500001
Revises: 490426bdfc05
Create Date: 2026-02-05 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2026020500001'
down_revision: Union[str, Sequence[str], None] = '490426bdfc05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Add expires_at and extra_data columns to background_tasks table."""

    # Add extra_data column (JSON, nullable)
    op.add_column(
        'background_tasks',
        sa.Column('extra_data', sa.JSON(), nullable=True)
    )

    # Add expires_at column (DateTime, nullable)
    op.add_column(
        'background_tasks',
        sa.Column('expires_at', sa.DateTime(), nullable=True)
    )

    # Create index on expires_at for cleanup queries
    op.create_index(
        'idx_background_tasks_expires_at',
        'background_tasks',
        ['expires_at']
    )

    # Create composite index on user_id and status
    op.create_index(
        'idx_background_tasks_user_status',
        'background_tasks',
        ['user_id', 'status']
    )


def downgrade() -> None:
    """Downgrade schema: Remove added columns and indexes."""

    # Drop indexes
    op.drop_index('idx_background_tasks_user_status', table_name='background_tasks')
    op.drop_index('idx_background_tasks_expires_at', table_name='background_tasks')

    # Drop columns
    op.drop_column('background_tasks', 'expires_at')
    op.drop_column('background_tasks', 'extra_data')
