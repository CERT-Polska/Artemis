# type: ignore
"""Tag migration

Revision ID: 40355237ae7c
Revises: 99b5570a348e
Create Date: 2024-06-20 13:47:53.630547

"""
import sqlalchemy as sa
from alembic import op

from artemis.db import DB

# revision identifiers, used by Alembic.
revision = "40355237ae7c"
down_revision = "99b5570a348e"
branch_labels = None
depends_on = None

db = DB()
task_tags = db.get_task_result_tags()
db.save_tags(task_tags)


def upgrade():

    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "tag",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tag_name", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("NOW()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tag_tag_name"), "tag", ["tag_name"], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_tag_tag_name"), table_name="tag")
    op.drop_table("tag")
    # ### end Alembic commands ###
