"""create pat audit logs table

Revision ID: 9f4118467795
Revises: 078d72b4bec9
Create Date: 2026-02-02 23:06:52

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9f4118467795'
down_revision: Union[str, Sequence[str], None] = '078d72b4bec9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('personal_access_token_audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('token_id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('endpoint', sa.String(length=500), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('authorized', sa.Boolean(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['token_id'], ['personal_access_tokens.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_personal_access_token_audit_logs_token_id'),
                    'personal_access_token_audit_logs', ['token_id'], unique=False)
    op.create_index(op.f('ix_personal_access_token_audit_logs_timestamp'),
                    'personal_access_token_audit_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_personal_access_token_audit_logs_timestamp'),
                  table_name='personal_access_token_audit_logs')
    op.drop_index(op.f('ix_personal_access_token_audit_logs_token_id'),
                  table_name='personal_access_token_audit_logs')
    op.drop_table('personal_access_token_audit_logs')
