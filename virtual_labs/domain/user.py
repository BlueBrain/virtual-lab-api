from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    UUID4,
    AliasChoices,
    BaseModel,
    EmailStr,
    Field,
    computed_field,
    field_validator,
)

from virtual_labs.core.types import UserRoleEnum


class ShortenedUser(BaseModel):
    id: UUID4 | None
    username: str
    email: EmailStr
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
        return f"{self.first_name} {self.last_name}"

    class Config:
        from_attributes = True
        # populate_by_name = True


class AllUsersCount(BaseModel):
    total: int = Field(
        description="Count of all users in BBP keycloak (including the ones that may not have not explicitly signed into OBP or have any virtual labs)"
    )


class UserWithInviteStatus(ShortenedUser):
    invite_accepted: bool
    role: UserRoleEnum


class UserAgentResponse(BaseModel):
    id: str
    given_name: str
    family_name: str
    name: str
    createdAt: datetime
    type: list[str]
