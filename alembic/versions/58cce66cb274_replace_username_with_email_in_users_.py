"""replace username with email in users table

Revision ID: 58cce66cb274
Revises: 9f4118467795
Create Date: 2026-02-03 12:09:26.393193

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '58cce66cb274'
down_revision: Union[str, Sequence[str], None] = '9f4118467795'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Step 1: Drop the unique index on username
    op.drop_index(op.f('ix_users_username'), table_name='users')

    # Step 2: Rename username column to email
    op.alter_column('users', 'username', new_column_name='email')

    # Step 3: Change column type from String(50) to String(255)
    op.alter_column('users', 'email',
                   existing_type=sa.String(length=50),
                   type_=sa.String(length=255))

    # Step 4: Recreate unique index on email
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    # Reverse the upgrade steps
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.alter_column('users', 'email',
                   existing_type=sa.String(length=255),
                   type_=sa.String(length=50))
    op.alter_column('users', 'email', new_column_name='username')
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
