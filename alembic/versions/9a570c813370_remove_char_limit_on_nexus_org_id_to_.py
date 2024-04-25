"""Instead of storing just the `label` of nexus_org in the `nexus_organization_id` column, we should
store the whole `self`. Nexus `label` is simply a UUID in our case (equal to the id of the virtual lab), while the `self`
has format similar to `https://sbo-nexus-fusion.shapes-registry.org/delta/v1/org/<UUID of virtual lab>`. Since the length
of `self` is more than `label`, the character limit of 255 can be removed from the column.

Revision ID: 9a570c813370
Revises: ad2e27bf6c24
Create Date: 2024-04-25 15:39:04.920198

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a570c813370"
down_revision: Union[str, None] = "ad2e27bf6c24"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "virtual_lab",
        "nexus_organization_id",
        existing_type=sa.String(255),
        type_=sa.String(length=None),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "project_invite",
        "nexus_organization_id",
        existing_type=sa.String(length=None),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
