from datetime import datetime
from typing import List, Optional

from pydantic import UUID4, BaseModel, ConfigDict, EmailStr, Field, computed_field

from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.invite import AddUser
from virtual_labs.domain.user import UserWithInviteStatus
from virtual_labs.shared.utils.billing import amount_to_float


class VirtualLabModel(BaseModel):
    id: UUID4
    name: str
    description: str

    class Config:
        from_attributes = True


class ProjectBody(BaseModel):
    name: str = Field(max_length=250)
    description: Optional[str] = None


class ProjectUpdateBody(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ProjectCreationBody(ProjectBody):
    include_members: Optional[list[AddUser]] = None


class Project(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID4
    nexus_project_id: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime | None
    budget_amount: int = Field(exclude=True, default=0)

    @computed_field
    def budget(self) -> float:
        return amount_to_float(self.budget_amount)


class ProjectVlOut(Project):
    virtual_lab_id: UUID4


class ProjectExistenceOut(BaseModel):
    exist: bool


class ProjectWithVLOut(BaseModel):
    projects: List[ProjectVlOut]
    total: int


class FailedInvite(BaseModel):
    user_email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    exists: bool = True


class ProjectOut(BaseModel):
    project: ProjectVlOut
    failed_invites: List[FailedInvite]


class ProjectsOut(BaseModel):
    project: List[Project]
    total: int


class ProjectDeletionOut(BaseModel):
    project_id: UUID4
    deleted: bool
    deleted_at: datetime


class ProjectBudgetOut(BaseModel):
    project_id: UUID4
    budget_amount: int = Field(exclude=True, default=0)

    @computed_field
    def budget(self) -> float:
        return amount_to_float(self.budget_amount)


class ProjectCountOut(BaseModel):
    count: int


class ProjectWithStarredDateOut(ProjectVlOut):
    updated_at: datetime
    starred_at: bool


class ProjectUpdateBudgetOut(BaseModel):
    project_id: UUID4
    new_budget: float
    updated_at: datetime


class ProjectUpdateRoleOut(BaseModel):
    project_id: UUID4
    new_role: UserRoleEnum


class ProjectUserDetachOut(BaseModel):
    project_id: UUID4
    detached: bool
    detached_at: datetime


class ProjectStarStatusUpdateOut(BaseModel):
    project_id: UUID4
    starred_at: datetime | None


class ProjectStar(BaseModel):
    id: UUID4
    user_id: UUID4

    class Config:
        from_attributes = True


class ProjectUsersOut(BaseModel):
    users: List[UserWithInviteStatus]
    total: int


class ProjectUsersCountOut(BaseModel):
    project_id: UUID4
    total: int


class ProjectPerVLCountOut(BaseModel):
    virtual_lab_id: UUID4
    total: int


class ProjectInviteIn(BaseModel):
    email: EmailStr
    role: UserRoleEnum


class ProjectInviteOut(BaseModel):
    origin: str = "Project"
    invite_id: UUID4
