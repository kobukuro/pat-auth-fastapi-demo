"""create fcs_files table

Revision ID: e5f8a3c2d1b0
Revises: 58cce66cb274
Create Date: 2026-02-04 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f8a3c2d1b0'
down_revision: Union[str, Sequence[str], None] = '58cce66cb274'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "fcs_files",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("file_id", sa.String(20), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("total_events", sa.Integer(), nullable=True),
        sa.Column("total_parameters", sa.Integer(), nullable=True),
        sa.Column("is_public", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("upload_duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "uploaded_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("file_id"),
    )
    op.create_index("ix_fcs_files_file_id", "fcs_files", ["file_id"], unique=True)
    op.create_index("idx_fcs_files_user_id", "fcs_files", ["user_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("idx_fcs_files_user_id", table_name="fcs_files")
    op.drop_index("ix_fcs_files_file_id", table_name="fcs_files")
    op.drop_table("fcs_files")
