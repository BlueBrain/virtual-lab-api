from datetime import datetime
from typing import Annotated, Any, List, Optional, TypedDict

from pydantic import UUID4, BaseModel, Field


class NexusBase(BaseModel):
    context: Annotated[str | List[Any], Field(alias="@context")] = []
    id: Annotated[str, Field(alias="@id")]
    type: Annotated[str | List[str] | None, Field(alias="@type")] = None
    createdAt: Annotated[datetime, Field(alias="_createdAt")]
    createdBy: Annotated[str, Field(alias="_createdBy")]
    deprecated: Annotated[bool, Field(alias="_deprecated")]
    self: Annotated[str, Field(alias="_self")]
    rev: Annotated[int, Field(alias="_rev")]


class NexusOrganization(NexusBase):
    label: Annotated[str, Field(alias="_label")]
    uuid: Annotated[UUID4, Field(alias="_uuid")]


class NexusProject(NexusBase):
    label: Annotated[str, Field(alias="_label")]
    uuid: Annotated[UUID4, Field(alias="_uuid")]


class NexusApiMapping(TypedDict):
    namespace: str
    prefix: str


class NexusIdentity(BaseModel):
    realm: str
    subject: Optional[str] = None
    type: Annotated[str | None, Field(serialization_alias="@type")] = None


class NexusResource(NexusBase):
    apiMappings: Annotated[List[NexusApiMapping], Field(default=List)] = []


class NexusAcls(NexusBase):
    type: Annotated[str | List[str], Field(alias="@type")] = "AccessControlList"


class NexusCrossResolver(NexusBase):
    type: Annotated[str | List[str], Field(alias="@type")] = [
        "Resolver",
        "CrossProject",
    ]


class NexusAclResult(NexusBase):
    id: Annotated[str, Field(alias="@id")] = ""
    type: Annotated[str | List[str], Field(alias="@type")] = "AccessControlList"


class NexusAclIdentity(BaseModel):
    id: Annotated[str, Field(alias="@id", default=None)]
    type: Annotated[str, Field(alias="@type", default=None)]
    realm: Optional[str] = None
    # group: Optional[str] = Field(None)


class NexusAcl(TypedDict):
    identity: NexusAclIdentity
    permissions: List[str]


class NexusAclList(BaseModel):
    acl: List[NexusAcl]
    rev: Annotated[int, Field(alias="_rev")]


class NexusResultAcl(BaseModel):
    context: Annotated[List[str], Field(alias="@context")] = []
    results: Annotated[List[NexusAclList], Field(alias="_results")]
    total: Annotated[int, Field(alias="_total")]


class NexusESViewMappingPropertyType(BaseModel):
    type: str


class NexusESViewMappingProperty(TypedDict):
    dynamic: bool
    properties: dict[str, NexusESViewMappingPropertyType]


class NexusElasticSearchViewMapping(BaseModel):
    type: Annotated[str | List[str], Field(alias="@type")] = [
        "View",
        "ElasticSearchView",
    ]
    mapping: NexusESViewMappingProperty
    pipeline: Annotated[List[Any], Field(default=List)] = []


class NexusPermissions(NexusBase):
    permissions: List[str]


class NexusSuiteProjects(BaseModel):
    context: Annotated[str | list[str], Field(alias="@context")] = []
    name: str
    projects: str | list[str]


class ProjectView(TypedDict):
    project: str
    viewId: str


class NexusS3Storage(NexusBase):
    type: Annotated[str | List[str], Field(alias="@type")] = ["Storage", "S3Storage"]


class NexusUserAgent(NexusBase):
    family_name: Annotated[str, Field(alias="familyName")]
    given_name: Annotated[str, Field(alias="givenName")]
    name: str
