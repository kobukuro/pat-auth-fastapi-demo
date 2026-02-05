"""merge scopes and upload fields migrations

Revision ID: 599510ba07cc
Revises: 14783fd3f203, 2026020500001
Create Date: 2026-02-05 15:30:51.614501

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '599510ba07cc'
down_revision: Union[str, Sequence[str], None] = ('14783fd3f203', '2026020500001')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
