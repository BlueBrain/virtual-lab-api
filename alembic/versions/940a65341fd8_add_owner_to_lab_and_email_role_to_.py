"""Add owner to lab and email role to invite

Revision ID: 940a65341fd8
Revises: a5230adcae73
Create Date: 2024-03-20 16:19:54.475431

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "940a65341fd8"
down_revision: Union[str, None] = "a5230adcae73"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("virtual_lab", sa.Column("owner_id", sa.UUID(), nullable=False))
    op.add_column("virtual_lab_invite", sa.Column("role", sa.String(), nullable=False))
    op.add_column(
        "virtual_lab_invite", sa.Column("user_email", sa.String(), nullable=False)
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("virtual_lab_invite", "user_email")
    op.drop_column("virtual_lab_invite", "role")
    op.drop_column("virtual_lab", "owner_id")
    # ### end Alembic commands ###