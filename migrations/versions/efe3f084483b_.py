"""empty message

Revision ID: efe3f084483b
Revises: 4596773754db
Create Date: 2024-11-13 12:38:38.060631

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "efe3f084483b"
down_revision = "4596773754db"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("report_generation_task", sa.Column("skip_suspicious_reports", sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("report_generation_task", "skip_suspicious_reports")
    # ### end Alembic commands ###
