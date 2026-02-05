"""convert scopes from JSON to many-to-many

Revision ID: 14783fd3f203
Revises: 490426bdfc05
Create Date: 2026-02-05 12:36:25.260090

"""
from typing import Sequence, Union
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column


# revision identifiers, used by Alembic.
revision: str = '14783fd3f203'
down_revision: Union[str, Sequence[str], None] = '490426bdfc05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Step 1: Create junction table
    op.create_table(
        'pat_scopes',
        sa.Column('pat_id', sa.Integer(), nullable=False),
        sa.Column('scope_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['pat_id'], ['personal_access_tokens.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scope_id'], ['scopes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('pat_id', 'scope_id')
    )

    # Step 2: Migrate data from JSON to junction table
    conn = op.get_bind()

    # Query all PATs with their scopes
    result = conn.execute(
        sa.text("SELECT id, scopes FROM personal_access_tokens")
    )

    # Track successful migrations
    migrated_count = 0
    failed_count = 0

    for row in result:
        pat_id = row[0]
        scopes_json = row[1]

        try:
            # Parse JSON array of scope names
            scope_names = json.loads(scopes_json)

            if not isinstance(scope_names, list):
                print(f"WARNING: PAT {pat_id} has non-list scopes: {type(scope_names)}")
                failed_count += 1
                continue

            # For each scope name, find its ID and create relationship
            for scope_name in scope_names:
                # Query scope ID from scopes table
                scope_result = conn.execute(
                    sa.text("SELECT id FROM scopes WHERE name = :name"),
                    {"name": scope_name}
                )
                scope_row = scope_result.fetchone()

                if scope_row:
                    scope_id = scope_row[0]
                    # Insert into junction table
                    conn.execute(
                        sa.text("INSERT INTO pat_scopes (pat_id, scope_id) VALUES (:pat_id, :scope_id)"),
                        {"pat_id": pat_id, "scope_id": scope_id}
                    )
                    migrated_count += 1
                else:
                    print(f"WARNING: Scope '{scope_name}' not found in scopes table for PAT {pat_id}")
                    failed_count += 1

        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse scopes for PAT {pat_id}: {e}")
            failed_count += 1
            continue

    print(f"Migration complete: {migrated_count} scope associations migrated, {failed_count} failures")

    # Step 3: Drop the old scopes column
    op.drop_column('personal_access_tokens', 'scopes')


def downgrade() -> None:
    """Downgrade schema."""
    # Step 1: Add back the scopes column
    op.add_column('personal_access_tokens', sa.Column('scopes', sa.Text(), nullable=True))

    # Step 2: Migrate data back from junction table to JSON
    conn = op.get_bind()

    # Query all PATs
    pat_result = conn.execute(
        sa.text("SELECT id FROM personal_access_tokens")
    )

    for row in pat_result:
        pat_id = row[0]

        # Get all scope names for this PAT
        scope_result = conn.execute(
            sa.text("""
                SELECT s.name
                FROM scopes s
                JOIN pat_scopes ps ON s.id = ps.scope_id
                WHERE ps.pat_id = :pat_id
                ORDER BY s.name
            """),
            {"pat_id": pat_id}
        )

        scope_names = [r[0] for r in scope_result.fetchall()]
        scopes_json = json.dumps(scope_names)

        # Update the scopes column
        conn.execute(
            sa.text("UPDATE personal_access_tokens SET scopes = :scopes WHERE id = :pat_id"),
            {"scopes": scopes_json, "pat_id": pat_id}
        )

    # Step 3: Make scopes column non-nullable (all data should be migrated)
    op.alter_column('personal_access_tokens', 'scopes', nullable=False)

    # Step 4: Drop junction table
    op.drop_table('pat_scopes')
