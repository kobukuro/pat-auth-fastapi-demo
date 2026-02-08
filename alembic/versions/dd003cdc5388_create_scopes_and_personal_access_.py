"""create scopes and personal_access_tokens tables

Revision ID: dd003cdc5388
Revises: 00a3b809aaac
Create Date: 2026-02-02 09:22:33.351753

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dd003cdc5388'
down_revision: Union[str, Sequence[str], None] = '00a3b809aaac'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create scopes table
    op.create_table('scopes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('resource', sa.String(length=50), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('level', sa.Integer(), nullable=False),
        sa.CheckConstraint("name = resource || ':' || action", name='ck_scope_name_consistency'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('resource', 'action', name='uq_scope_resource_action')
    )
    op.create_index(op.f('ix_scopes_resource'), 'scopes', ['resource'], unique=False)

    # Create personal_access_tokens table
    op.create_table('personal_access_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('token_prefix', sa.String(length=12), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('scopes', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_personal_access_tokens_token_prefix'), 'personal_access_tokens', ['token_prefix'], unique=False)
    op.create_index(op.f('ix_personal_access_tokens_user_id'), 'personal_access_tokens', ['user_id'], unique=False)

    # Seed scope data
    scopes_table = sa.table('scopes',
        sa.column('resource', sa.String),
        sa.column('action', sa.String),
        sa.column('name', sa.String),
        sa.column('level', sa.Integer),
    )
    op.bulk_insert(scopes_table, [
        {'resource': 'workspaces', 'action': 'read', 'name': 'workspaces:read', 'level': 1},
        {'resource': 'workspaces', 'action': 'write', 'name': 'workspaces:write', 'level': 2},
        {'resource': 'workspaces', 'action': 'delete', 'name': 'workspaces:delete', 'level': 3},
        {'resource': 'workspaces', 'action': 'admin', 'name': 'workspaces:admin', 'level': 4},
        {'resource': 'users', 'action': 'read', 'name': 'users:read', 'level': 1},
        {'resource': 'users', 'action': 'write', 'name': 'users:write', 'level': 2},
        {'resource': 'fcs', 'action': 'read', 'name': 'fcs:read', 'level': 1},
        {'resource': 'fcs', 'action': 'write', 'name': 'fcs:write', 'level': 2},
        {'resource': 'fcs', 'action': 'analyze', 'name': 'fcs:analyze', 'level': 3},
    ])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_personal_access_tokens_user_id'), table_name='personal_access_tokens')
    op.drop_index(op.f('ix_personal_access_tokens_token_prefix'), table_name='personal_access_tokens')
    op.drop_table('personal_access_tokens')
    op.drop_index(op.f('ix_scopes_resource'), table_name='scopes')
    op.drop_table('scopes')
