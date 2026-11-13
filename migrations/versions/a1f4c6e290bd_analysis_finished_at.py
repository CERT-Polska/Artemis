"""add analysis.finished_at

Revision ID: a1f4c6e290bd
Revises: 07eb88fe697f
Create Date: 2026-11-06 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1f4c6e290bd"
down_revision = "07eb88fe697f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analysis", sa.Column("finished_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis", "finished_at")
