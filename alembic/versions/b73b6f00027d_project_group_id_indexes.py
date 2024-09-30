"""project group_id indexes

Revision ID: b73b6f00027d
Revises: 6fec61d361a4
Create Date: 2024-09-30 05:58:07.023437

"""

from typing import Sequence, Union

import sqlalchemy as sa  # noqa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b73b6f00027d"
down_revision: Union[str, None] = "6fec61d361a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint("unique_admin_group_id", "project", type_="unique")
    op.drop_constraint("unique_member_group_id", "project", type_="unique")
    op.create_index(
        op.f("ix_project_admin_group_id"), "project", ["admin_group_id"], unique=True
    )
    op.create_index(
        op.f("ix_project_member_group_id"), "project", ["member_group_id"], unique=True
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_project_member_group_id"), table_name="project")
    op.drop_index(op.f("ix_project_admin_group_id"), table_name="project")
    op.create_unique_constraint(
        "unique_member_group_id", "project", ["member_group_id"]
    )
    op.create_unique_constraint("unique_admin_group_id", "project", ["admin_group_id"])
    # ### end Alembic commands ###