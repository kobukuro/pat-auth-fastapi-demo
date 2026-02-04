"""Add background tasks and FCS statistics tables

Revision ID: 490426bdfc05
Revises: 58cce66cb274
Create Date: 2026-02-04 16:36:42.294880

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '490426bdfc05'
down_revision: Union[str, Sequence[str], None] = 'e5f8a3c2d1b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create fcs_statistics table
    op.create_table(
        "fcs_statistics",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.String(50), nullable=False),
        sa.Column("fcs_file_id", sa.Integer(), nullable=True),
        sa.Column("statistics", sa.JSON(), nullable=False),
        sa.Column("total_events", sa.Integer(), nullable=False),
        sa.Column(
            "calculated_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["fcs_file_id"], ["fcs_files.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("file_id"),
    )
    op.create_index("idx_fcs_statistics_file_id", "fcs_statistics", ["file_id"])
    op.create_index("idx_fcs_statistics_fcs_file_id", "fcs_statistics", ["fcs_file_id"])
    op.create_index("ix_fcs_statistics_total_events", "fcs_statistics", ["total_events"])

    # Create background_tasks table
    op.create_table(
        "background_tasks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("task_type", sa.String(50), nullable=False),
        sa.Column("fcs_file_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["fcs_file_id"], ["fcs_files.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_background_tasks_file_type_status",
        "background_tasks",
        ["fcs_file_id", "task_type", "status"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("idx_background_tasks_file_type_status", table_name="background_tasks")
    op.drop_table("background_tasks")

    op.drop_index("ix_fcs_statistics_total_events", table_name="fcs_statistics")
    op.drop_index("idx_fcs_statistics_fcs_file_id", table_name="fcs_statistics")
    op.drop_index("idx_fcs_statistics_file_id", table_name="fcs_statistics")
    op.drop_table("fcs_statistics")
