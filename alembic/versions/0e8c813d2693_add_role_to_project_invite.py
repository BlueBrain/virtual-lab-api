"""add role to project_invite

Revision ID: 0e8c813d2693
Revises: c3fc70d340af
Create Date: 2024-03-15 13:06:06.643619

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0e8c813d2693"
down_revision: Union[str, None] = "c3fc70d340af"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("project_invite", sa.Column("role", sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("project_invite", "role")
    # ### end Alembic commands ###
