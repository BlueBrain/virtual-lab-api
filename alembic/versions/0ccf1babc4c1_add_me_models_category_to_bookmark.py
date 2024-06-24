"""Add me models category to bookmark

Revision ID: 0ccf1babc4c1
Revises: 5242355ed15d
Create Date: 2024-06-24 16:01:18.981731

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0ccf1babc4c1"
down_revision: Union[str, None] = "5242355ed15d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE bookmarkcategory ADD VALUE 'CircuitMEModel'")


def downgrade() -> None:
    op.execute("ALTER TYPE bookmarkcategory RENAME TO bookmarkcategory_old")
    op.execute(
        "CREATE TYPE bookmarkcategory AS ENUM('ExperimentalBoutonDensity', 'ExperimentalNeuronDensity', 'ExperimentalElectroPhysiology', 'ExperimentalSynapsePerConnection', 'ExperimentalNeuronMorphology', 'SimulationCampaigns', 'CircuitEModel')"
    )
    op.execute(
        (
            "ALTER TABLE bookmark ALTER COLUMN category TYPE bookmarkcategory USING "
            "bookmarkcategory::text::bookmarkcategory"
        )
    )
    op.execute("DROP TYPE bookmarkcategory_old")
