"""add stripe customer to vlab table

Revision ID: f4fe29571ef5
Revises: 6338b6ac5353
Create Date: 2024-05-06 16:15:25.835704

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4fe29571ef5'
down_revision: Union[str, None] = '6338b6ac5353'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('payment_method', 'customerId')
    op.add_column('virtual_lab', sa.Column('stripe_customer_id', sa.String(), nullable=False))
    op.create_unique_constraint(None, 'virtual_lab', ['stripe_customer_id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'virtual_lab', type_='unique')
    op.drop_column('virtual_lab', 'stripe_customer_id')
    op.add_column('payment_method', sa.Column('customerId', sa.VARCHAR(), autoincrement=False, nullable=False))
    # ### end Alembic commands ###
