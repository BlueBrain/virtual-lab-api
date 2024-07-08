from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus as url_encode

from httpx import AsyncClient
from loguru import logger
from pydantic import UUID4

from virtual_labs.core.exceptions.nexus_error import NexusError, NexusErrorValue
from virtual_labs.domain.project import ProjectUpdateBody
from virtual_labs.external.nexus.defaults import (
    AG_ES_VIEW_ID,
    AG_SP_VIEW_ID,
    AGGREGATE_ELASTIC_SEARCH_VIEW,
    AGGREGATE_SPARQL_VIEW,
    CROSS_RESOLVER,
    DEFAULT_RESOLVER_PRIORITY,
    ELASTIC_SEARCH_VIEW,
    ES_VIEW_ID,
    ES_VIEWS,
    SP_VIEW_ID,
    SP_VIEWS,
    prep_project_base,
)
from virtual_labs.external.nexus.models import (
    NexusAcls,
    NexusApiMapping,
    NexusCrossResolver,
    NexusIdentity,
    NexusPermissions,
    NexusProject,
    NexusResource,
    NexusResultAcl,
    NexusSuiteProjects,
    ProjectView,
)
from virtual_labs.infrastructure.settings import settings


def create_context(vocab: str) -> Dict[str, Any]:
    return {
        "@context": ["https://neuroshapes.org", {"@vocab": vocab}],
        "@id": "https://bbp.neuroshapes.org",
    }


class NexusProjectInterface:
    httpx_clt: AsyncClient

    def __init__(self, httpx_clt: AsyncClient, client_token: str) -> None:
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {client_token}",
        }
        self.httpx_clt = httpx_clt
        pass

    async def retrieve_project(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
    ) -> NexusProject:
        nexus_project_url = f"{settings.NEXUS_DELTA_URI}/projects/{str(virtual_lab_id)}/{str(project_id)}"
        try:
            response = await self.httpx_clt.get(
                nexus_project_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusProject(**data)
        except Exception as ex:
            logger.error(
                f"Error during fetching nexus project {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during fetching nexus project",
                type=NexusErrorValue.FETCH_PROJECT_ERROR,
            )

    async def create_project(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        description: Optional[str],
        apiMapping: List[NexusApiMapping],
        vocab: str,
    ) -> NexusProject:
        nexus_project_url = (
            f"{settings.NEXUS_DELTA_URI}/projects/{virtual_lab_id}/{project_id}"
        )
        project_base = prep_project_base(
            virtual_lab_id=str(virtual_lab_id), project_id=str(project_id)
        )
        try:
            response = await self.httpx_clt.put(
                nexus_project_url,
                headers=self.headers,
                json={
                    "description": description,
                    "apiMappings": apiMapping,
                    "vocab": vocab,
                    "base": project_base,
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusProject(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus project {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus project",
                type=NexusErrorValue.CREATE_PROJECT_ERROR,
            )

    async def retrieve_project_latest_acls(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
    ) -> NexusResultAcl:
        nexus_acl_url = (
            f"{settings.NEXUS_DELTA_URI}/acls/{str(virtual_lab_id)}/{str(project_id)}"
        )
        try:
            response = await self.httpx_clt.get(
                nexus_acl_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusResultAcl(**data)
        except Exception as ex:
            logger.error(
                f"Error during fetching nexus project acls {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during fetching nexus project acls",
                type=NexusErrorValue.FETCH_PROJECT_ACL_ERROR,
            )

    async def append_project_acls(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        group_name: str,
        rev: int,
        permissions: List[str] | None = None,
    ) -> NexusAcls:
        nexus_acl_url = f"{settings.NEXUS_DELTA_URI}/acls/{str(virtual_lab_id)}/{str(project_id)}?rev={rev}"

        try:
            response = await self.httpx_clt.patch(
                nexus_acl_url,
                headers=self.headers,
                json={
                    "@type": "Append",
                    "acl": [
                        {
                            "permissions": permissions,
                            "identity": {
                                "@type": "Group",
                                "realm": settings.KC_REALM_NAME,
                                "group": f"/{group_name}",
                            },
                        },
                    ],
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusAcls(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus project acls {ex}. Response: {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus project acls",
                type=NexusErrorValue.APPEND_ACL_ERROR,
            )

    async def delete_project_acl_revision(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
    ) -> NexusAcls:
        nexus_acl_url = (
            f"{settings.NEXUS_DELTA_URI}/acls/{str(virtual_lab_id)}/{str(project_id)}"
        )

        try:
            response = await self.httpx_clt.delete(
                nexus_acl_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusAcls(**data)
        except Exception as ex:
            logger.error(
                f"Error during deleting nexus acl list {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during deleting nexus project acl list",
                type=NexusErrorValue.DELETE_PROJECT_ACL_ERROR,
            )

    async def deprecate_project(
        self, *, virtual_lab_id: UUID4, project_id: UUID4, revision: int
    ) -> NexusProject:
        nexus_acl_url = f"{settings.NEXUS_DELTA_URI}/projects/{str(virtual_lab_id)}/{str(project_id)}?rev={revision}"

        try:
            response = await self.httpx_clt.delete(
                nexus_acl_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusProject(**data)
        except Exception as ex:
            logger.error(
                f"Error during deprecation of nexus project {ex}. Response: {response.json()}"
            )
            raise NexusError(
                message="Error during deprecation of nexus project",
                type=NexusErrorValue.DEPRECATE_PROJECT_ERROR,
            )

    async def create_es_view(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        view_id: str = ES_VIEW_ID,
        mapping: Dict[str, Any],
        source_as_text: Optional[bool] = None,
        resource_types: Optional[List[str]] = None,
        include_metadata: bool = False,
        include_deprecated: bool = False,
    ) -> NexusResource:
        nexus_es_view_url = (
            f"{settings.NEXUS_DELTA_URI}/views/{str(virtual_lab_id)}/{str(project_id)}"
        )
        payload = {
            "@id": view_id,
            "@type": ELASTIC_SEARCH_VIEW,
            "mapping": mapping,
            "includeMetadata": include_metadata,
            "includeDeprecated": include_deprecated,
        }

        if resource_types:
            payload["resourceTypes"] = resource_types
        if source_as_text is not None:
            payload["sourceAsText"] = source_as_text

        try:
            response = await self.httpx_clt.post(
                nexus_es_view_url, headers=self.headers, json=payload
            )
            response.raise_for_status()

            data = response.json()
            return NexusResource(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus es view {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus es view",
                type=NexusErrorValue.CREATE_ES_VIEW_ERROR,
            )

    async def __get_sbo_suite_views(self) -> list[ProjectView]:
        try:
            sbo_projects_response = await self.httpx_clt.get(
                f"{settings.NEXUS_DELTA_URI}/search/suites/sbo", headers=self.headers
            )
            sbo_projects_response.raise_for_status()

            data = NexusSuiteProjects.model_validate(
                sbo_projects_response.json()
            ).projects
            sbo_projects = data if isinstance(data, list) else [data]

            views = [
                ProjectView(project=project, viewId=ES_VIEW_ID)
                for project in sbo_projects
            ]
            return views
        except Exception as ex:
            logger.error(
                f"Failed to retrieve projects within sbo suite. Response {sbo_projects_response.json()}. Error: {ex}"
            )
            raise NexusError(
                message="Failed to retrieve projects within sbo suite.",
                type=NexusErrorValue.FETCH_SUITE_ERROR,
            )

    async def create_nexus_es_aggregate_view(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        view_id: str = AG_ES_VIEW_ID,
    ) -> NexusResource:
        nexus_es_view_url = (
            f"{settings.NEXUS_DELTA_URI}/views/{str(virtual_lab_id)}/{str(project_id)}"
        )
        sbo_suite_views = await self.__get_sbo_suite_views()
        views = (
            [
                ProjectView(
                    project=f"{str(virtual_lab_id)}/{str(project_id)}",
                    viewId=ES_VIEW_ID,
                ),
            ]
            + ES_VIEWS
            + sbo_suite_views
        )
        try:
            response = await self.httpx_clt.post(
                nexus_es_view_url,
                headers=self.headers,
                json={
                    "@id": view_id,
                    "@type": AGGREGATE_ELASTIC_SEARCH_VIEW,
                    "views": views,
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusResource(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus es aggregate view {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus es aggregate view",
                type=NexusErrorValue.CREATE_ES_AGG_VIEW_ERROR,
            )

    async def create_nexus_sp_aggregate_view(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        view_id: str = AG_SP_VIEW_ID,
    ) -> NexusResource:
        nexus_es_view_url = (
            f"{settings.NEXUS_DELTA_URI}/views/{str(virtual_lab_id)}/{str(project_id)}"
        )
        views = [
            {"project": f"{virtual_lab_id}/{project_id}", "viewId": SP_VIEW_ID}
        ] + SP_VIEWS

        try:
            response = await self.httpx_clt.post(
                nexus_es_view_url,
                headers=self.headers,
                json={
                    "@id": view_id,
                    "@type": AGGREGATE_SPARQL_VIEW,
                    "views": views,
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusResource(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus sp aggregate view {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus sp aggregate view",
                type=NexusErrorValue.CREATE_SP_AGG_VIEW_ERROR,
            )

    async def retrieve_all_permissions(self) -> NexusPermissions:
        nexus_permissions_url = f"{settings.NEXUS_DELTA_URI}/permissions"
        try:
            response = await self.httpx_clt.get(
                nexus_permissions_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusPermissions(**data)
        except Exception as ex:
            logger.error(
                f"Error during fetching nexus permissions {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during fetching nexus permissions",
                type=NexusErrorValue.FETCH_NEXUS_PERMISSIONS_ERROR,
            )

    async def subtract_project_acls(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        permissions: List[str,],
        identity: NexusIdentity,
        revision: int,
    ) -> NexusAcls:
        nexus_acl_url = f"{settings.NEXUS_DELTA_URI}/acls/{str(virtual_lab_id)}/{str(project_id)}?rev={revision}"

        try:
            response = await self.httpx_clt.patch(
                nexus_acl_url,
                headers=self.headers,
                json={
                    "@type": "Subtract",
                    "acl": [
                        {
                            "permissions": permissions,
                            "identity": {
                                "realm": identity["realm"],
                                "subject": identity["subject"],
                            },
                        },
                    ],
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusAcls(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus project acls {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus project acls",
                type=NexusErrorValue.SUBTRACT_ACL_ERROR,
            )

    async def retrieve_resource(
        self,
        *,
        virtual_lab_id: UUID4 | str,
        project_id: UUID4 | str,
        resource_id: str,
        schema_id: str = "_",
        revision: int | None = None,
    ) -> NexusResource:
        nexus_resource_url = f"{settings.NEXUS_DELTA_URI}/resources/{str(virtual_lab_id)}/{str(project_id)}/{schema_id}/{url_encode(resource_id)}"

        if revision is not None:
            nexus_resource_url = nexus_resource_url + f"?rev={revision}"

        try:
            response = await self.httpx_clt.get(
                nexus_resource_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusResource(**data)
        except Exception as ex:
            logger.error(
                f"Error during fetching of nexus resource {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during fetching of nexus resource",
                type=NexusErrorValue.FETCH_RESOURCE_ERROR,
            )

    async def create_resolver(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        resolver_id: str | None = None,
        type: List[str] = CROSS_RESOLVER,
        projects: List[str],
        identities: List[NexusIdentity],
        priority: int = DEFAULT_RESOLVER_PRIORITY,
    ) -> NexusCrossResolver:
        nexus_resolver_url = f"{settings.NEXUS_DELTA_URI}/resolvers/{str(virtual_lab_id)}/{str(project_id)}"
        payload = {
            "@type": type,
            "projects": projects,
            "identities": identities,
            "priority": priority,
        }

        if resolver_id:
            payload["@id"] = resolver_id
        try:
            response = await self.httpx_clt.post(
                nexus_resolver_url, headers=self.headers, json=payload
            )

            response.raise_for_status()

            data = response.json()
            return NexusCrossResolver(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus resolver {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus resolver",
                type=NexusErrorValue.CREATE_RESOLVER_ERROR,
            )

    async def create_resource(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        payload: Dict[str, Any],
    ) -> NexusResource:
        nexus_resource_url = f"{settings.NEXUS_DELTA_URI}/resources/{str(virtual_lab_id)}/{str(project_id)}"
        try:
            response = await self.httpx_clt.post(
                nexus_resource_url, headers=self.headers, json=payload
            )
            response.raise_for_status()

            data = response.json()
            return NexusResource(**data)
        except Exception as ex:
            logger.error(
                f"Error during creating nexus resource {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during creating nexus resource",
                type=NexusErrorValue.CREATE_RESOURCE_ERROR,
            )

    async def update_project(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        payload: ProjectUpdateBody,
    ) -> NexusProject:
        project = await self.retrieve_project(
            virtual_lab_id=virtual_lab_id, project_id=project_id
        )

        nexus_project_url = f"{settings.NEXUS_DELTA_URI}/projects/{virtual_lab_id}/{project_id}?rev={project.rev}"
        try:
            response = await self.httpx_clt.put(
                nexus_project_url,
                headers=self.headers,
                json={
                    "description": payload.description,
                },
            )
            response.raise_for_status()

            data = response.json()
            return NexusProject(**data)
        except Exception as ex:
            logger.error(
                f"Error during update nexus project {ex}. Response {response.json()}"
            )
            raise NexusError(
                message="Error during update nexus project",
                type=NexusErrorValue.UPDATE_PROJECT_ERROR,
            )
