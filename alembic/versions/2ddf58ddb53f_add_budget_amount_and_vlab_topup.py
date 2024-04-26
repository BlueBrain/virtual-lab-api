"""add_budget_amount_and_vlab_topup

Revision ID: 2ddf58ddb53f
Revises: 6338b6ac5353
Create Date: 2024-05-10 13:30:59.036044

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2ddf58ddb53f"
down_revision: Union[str, None] = "6338b6ac5353"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "virtual_lab_topup",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("virtual_lab_id", sa.UUID(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("stripe_event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["virtual_lab_id"],
            ["virtual_lab.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column(
        "virtual_lab", sa.Column("budget_amount", sa.Integer(), nullable=False)
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("virtual_lab", "budget_amount")
    op.drop_table("virtual_lab_topup")
    # ### end Alembic commands ###
