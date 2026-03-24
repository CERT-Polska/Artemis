"""remove scheduled_task.deduplication_data_original

Revision ID: 7243ed9d7f98
Revises: 3d5b256854bb
Create Date: 2026-03-11 13:07:16.054460

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "7243ed9d7f98"
down_revision = "3d5b256854bb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("scheduled_task", "deduplication_data_original")


def downgrade() -> None:
    op.add_column(
        "scheduled_task", sa.Column("deduplication_data_original", sa.VARCHAR(), autoincrement=False, nullable=True)
    )
