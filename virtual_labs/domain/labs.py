from datetime import datetime
from typing import Generic, Optional, TypeVar

from pydantic import UUID4, BaseModel, EmailStr, JsonValue, field_validator

from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.user import ShortenedUser
from virtual_labs.infrastructure.kc.models import UserRepresentation

T = TypeVar("T")


class LabResponse(BaseModel, Generic[T]):
    message: str
    data: T


class VirtualLabBase(BaseModel):
    name: str
    description: str
    reference_email: EmailStr
    budget: float

    @field_validator("budget")
    @classmethod
    def check_budget_greater_than_0(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Budget should be greater than 0")

        return v


class VirtualLabCreate(VirtualLabBase):
    plan_id: int


class AddUser(BaseModel):
    role: UserRoleEnum
    user_id: UUID4


class VirtualLabUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    reference_email: EmailStr | None = None
    budget: float | None = None
    plan_id: int | None = None

    @field_validator("budget")
    @classmethod
    def check_budget_greater_than_0(cls, v: float | None) -> float | None:
        if v is None:
            return v

        if v <= 0:
            raise ValueError("Budget should be greater than 0")
        return v


class PlanDomain(BaseModel):
    id: int
    name: str
    price: float
    features: JsonValue

    class Config:
        from_attributes = True


class VirtualLabProjectOut(BaseModel):
    id: UUID4
    name: str
    description: str | None
    starred: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VirtualLabDomain(VirtualLabBase):
    id: UUID4
    plan_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class VirtualLabWithProject(VirtualLabDomain):
    projects: list[VirtualLabProjectOut] | None = None

    class Config:
        from_attributes = True


class VirtualLabDomainVerbose(VirtualLabDomain):
    nexus_organization_id: str
    deleted: bool

    updated_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    projects: list[VirtualLabProjectOut] | None = None

    class Config:
        from_attributes = True


class SearchLabResponse(BaseModel):
    virtual_labs: list[VirtualLabDomain]


class UserWithInviteStatus(ShortenedUser):
    invite_accepted: bool
    role: str


class VirtualLabUsers(BaseModel):
    users: list[UserWithInviteStatus]


class VirtualLabUser(BaseModel):
    user: UserRepresentation


class Lab(BaseModel):
    virtual_lab: VirtualLabDomain


class LabVerbose(BaseModel):
    virtual_lab: VirtualLabDomainVerbose


class AllPlans(BaseModel):
    all_plans: list[PlanDomain]


class AddUserToVirtualLab(BaseModel):
    email: EmailStr
    role: UserRoleEnum


class InviteSent(BaseModel):
    invite_id: UUID4
