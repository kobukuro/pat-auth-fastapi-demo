"""change token_prefix to 8 chars

Revision ID: 078d72b4bec9
Revises: dd003cdc5388
Create Date: 2026-02-02 17:49:10.728558

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '078d72b4bec9'
down_revision: Union[str, Sequence[str], None] = 'dd003cdc5388'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column('personal_access_tokens', 'token_prefix',
        type_=sa.String(length=8),
        existing_type=sa.String(length=12))


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column('personal_access_tokens', 'token_prefix',
        type_=sa.String(length=12),
        existing_type=sa.String(length=8))
