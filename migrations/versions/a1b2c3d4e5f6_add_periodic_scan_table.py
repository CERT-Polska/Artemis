"""Add periodic_scan table

Revision ID: a1b2c3d4e5f6
Revises: 3d5b256854bb
Create Date: 2026-03-03 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "3d5b256854bb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "periodic_scan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("targets", sa.String(), nullable=False),
        sa.Column("tag", sa.String(), nullable=True),
        sa.Column("disabled_modules", sa.String(), nullable=True),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("priority", sa.String(), nullable=False, server_default="normal"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("NOW()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_periodic_scan_tag"), "periodic_scan", ["tag"], unique=False)
    op.create_index(op.f("ix_periodic_scan_enabled"), "periodic_scan", ["enabled"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_periodic_scan_enabled"), table_name="periodic_scan")
    op.drop_index(op.f("ix_periodic_scan_tag"), table_name="periodic_scan")
    op.drop_table("periodic_scan")
