"""add started_at to report_generation_task

Revision ID: a1b2c3d4e5f6
Revises: 3d5b256854bb
Create Date: 2026-03-08 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "3d5b256854bb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report_generation_task", sa.Column("started_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("report_generation_task", "started_at")
