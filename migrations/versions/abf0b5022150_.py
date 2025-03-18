"""empty message

Revision ID: abf0b5022150
Revises: ab44b9431ad1
Create Date: 2025-03-17 06:57:29.458296

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "abf0b5022150"
down_revision = "ab44b9431ad1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "tag_archive_request",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tag", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tag_archive_request_tag"), "tag_archive_request", ["tag"], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_tag_archive_request_tag"), table_name="tag_archive_request")
    op.drop_table("tag_archive_request")
    # ### end Alembic commands ###
