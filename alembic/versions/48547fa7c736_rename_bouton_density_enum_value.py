"""Rename bouton density enum value

Revision ID: 48547fa7c736
Revises: 0ccf1babc4c1
Create Date: 2024-07-01 19:11:32.140736

"""
from typing import Sequence, Union

from alembic import op

revision: str = "48547fa7c736"
down_revision: Union[str, None] = "0ccf1babc4c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Save copy of bookmarkcategory enum
    op.execute("ALTER TYPE bookmarkcategory RENAME TO bookmarkcategory_old")

    # Create enum with all types
    op.execute(
        "CREATE TYPE bookmarkcategory AS ENUM('ExperimentsBoutonDensity', 'ExperimentalNeuronDensity', 'ExperimentalElectroPhysiology', 'ExperimentalSynapsePerConnection', 'ExperimentalNeuronMorphology', 'SimulationCampaigns', 'CircuitEModel', 'CircuitMEModel')"
    )

    op.execute(
        (
            "ALTER TABLE bookmark ALTER COLUMN category TYPE bookmarkcategory USING "
            "category::text::bookmarkcategory"
        )
    )

    # Drop copy of enum
    op.execute("DROP TYPE bookmarkcategory_old")


def downgrade() -> None:
    op.execute("ALTER TYPE bookmarkcategory RENAME TO bookmarkcategory_old")
    op.execute(
        "CREATE TYPE bookmarkcategory AS ENUM('ExperimentalBoutonDensity', 'ExperimentalNeuronDensity', 'ExperimentalElectroPhysiology', 'ExperimentalSynapsePerConnection', 'ExperimentalNeuronMorphology', 'SimulationCampaigns', 'CircuitEModel', 'CircuitMEModel')"
    )
    op.execute(
        (
            "ALTER TABLE bookmark ALTER COLUMN category TYPE bookmarkcategory USING "
            "category::text::bookmarkcategory"
        )
    )
    op.execute("DROP TYPE bookmarkcategory_old")
