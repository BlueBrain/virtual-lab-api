"""add-synaptome-categories-to-bookmark

Revision ID: 981da98985c0
Revises: 48547fa7c736
Create Date: 2024-09-04 16:29:26.447784

"""
from typing import Sequence, Union

from alembic import op

revision: str = "981da98985c0"
down_revision: Union[str, None] = "48547fa7c736"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE bookmarkcategory ADD VALUE 'SingleNeuronSynaptome'")
    op.execute("ALTER TYPE bookmarkcategory ADD VALUE 'SingleNeuronSimulation'")
    op.execute("ALTER TYPE bookmarkcategory ADD VALUE 'SynaptomeSimulation'")


def downgrade() -> None:
    op.execute("ALTER TYPE bookmarkcategory RENAME TO bookmarkcategory_old")
    op.execute(
        "CREATE TYPE bookmarkcategory AS ENUM('ExperimentalBoutonDensity', 'ExperimentalNeuronDensity', 'ExperimentalElectroPhysiology', 'ExperimentalSynapsePerConnection', 'ExperimentalNeuronMorphology', 'SimulationCampaigns', 'CircuitEModel', 'CircuitMEModel')"
    )
    op.execute(
        (
            "ALTER TABLE bookmark ALTER COLUMN category TYPE bookmarkcategory USING "
            "bookmarkcategory::text::bookmarkcategory"
        )
    )
    op.execute("DROP TYPE bookmarkcategory_old")
