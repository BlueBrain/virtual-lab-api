from enum import Enum
from typing import Annotated, TypedDict

from pydantic import UUID4, BaseModel, Field


class BookmarkCategory(Enum):
    ExperimentsBoutonDensity = "ExperimentsBoutonDensity"
    ExperimentalNeuronDensity = "ExperimentalNeuronDensity"
    ExperimentalElectroPhysiology = "ExperimentalElectroPhysiology"
    ExperimentalSynapsePerConnection = "ExperimentalSynapsePerConnection"
    ExperimentalNeuronMorphology = "ExperimentalNeuronMorphology"
    SimulationCampaigns = "SimulationCampaign"
    CircuitEModel = "CircuitEModel"
    CircuitMEModel = "CircuitMEModel"


class BookmarkIn(BaseModel):
    resource_id: Annotated[str, Field(alias="resourceId")]
    category: BookmarkCategory

    class Config:
        from_attributes = True
        populate_by_name = True


class BookmarkOut(BaseModel):
    id: UUID4
    resource_id: Annotated[str, Field(alias="resourceId")]
    category: BookmarkCategory

    class Config:
        from_attributes = True
        populate_by_name = True


BulkDeleteBookmarks = TypedDict(
    "BulkDeleteBookmarks",
    {
        "successfully_deleted": list[BookmarkIn],
        "failed_to_delete": list[BookmarkIn],
    },
)
