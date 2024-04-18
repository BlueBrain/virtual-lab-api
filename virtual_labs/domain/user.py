from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    UUID4,
    AliasChoices,
    BaseModel,
    Field,
    computed_field,
    field_validator,
)


class ShortenedUser(BaseModel):
    id: UUID4 | None
    username: str
    createdTimestamp: Annotated[datetime, Field(alias="created_at", default="")]
    first_name: Annotated[
        str, Field(validation_alias=AliasChoices("firstName"), default="")
    ]
    last_name: Annotated[
        str, Field(validation_alias=AliasChoices("lastName"), default="")
    ]

    @field_validator("createdTimestamp", mode="before")
    @classmethod
    def convert_timestamp(cls, v: int) -> Any:
        if isinstance(v, int):
            return datetime.fromtimestamp(v / 1000)
        return v

    @computed_field  # type: ignore
    @property
    def name(self) -> str:
        return f"{self.last_name} {self.first_name}"

    class Config:
        from_attributes = True
        # populate_by_name = True
