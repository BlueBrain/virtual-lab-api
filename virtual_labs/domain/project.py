from datetime import datetime
from typing import List, Optional

from pydantic import UUID4, BaseModel, EmailStr, Field

from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.invite import AddUser
from virtual_labs.domain.user import ShortenedUser


class VirtualLabModel(BaseModel):
    id: UUID4
    name: str
    description: str

    class Config:
        from_attributes = True


class ProjectBody(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectCreationBody(ProjectBody):
    include_members: Optional[list[AddUser]] = None


class Project(BaseModel):
    id: UUID4
    nexus_project_id: str
    name: str
    description: str | None
    budget: float | None
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True


class ProjectVlOut(Project):
    virtual_lab_id: UUID4
    admin: ShortenedUser = Field(
        description="Alphabetically first admin of the project"
    )


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
    budget: float


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
    users: List[ShortenedUser]
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
