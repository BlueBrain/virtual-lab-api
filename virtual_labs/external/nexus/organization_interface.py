from httpx import AsyncClient
from loguru import logger
from pydantic import UUID4

from virtual_labs.core.exceptions.nexus_error import NexusError, NexusErrorValue
from virtual_labs.external.nexus.models import (
    NexusAcls,
    NexusOrganization,
    NexusResultAcl,
)
from virtual_labs.infrastructure.settings import settings


class NexusOrganizationInterface:
    httpx_client: AsyncClient

    def __init__(self, client: AsyncClient, client_token: str):
        self.httpx_client = client
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {client_token}",
        }

    async def create_organization(
        self, lab_id: UUID4, description: str | None
    ) -> NexusOrganization:
        nexus_org_url = f"{settings.NEXUS_DELTA_URI}/orgs/{str(lab_id)}"
        try:
            response = await self.httpx_client.put(
                nexus_org_url, headers=self.headers, json={"description": description}
            )
            response.raise_for_status()
            return NexusOrganization(**response.json())
        except Exception as error:
            logger.error(
                f"Error when creating nexus organization for virtual lab {lab_id}: {error}. Response {response.json()}"
            )
            raise NexusError(
                message=f"Error when creating nexus organization for virtual lab {lab_id}",
                type=NexusErrorValue.CREATE_ORGANIZATION_ERROR,
            ) from error

    async def retrieve_organization(
        self,
        lab_id: UUID4,
    ) -> NexusOrganization:
        nexus_org_url = f"{settings.NEXUS_DELTA_URI}/orgs/{str(lab_id)}"

        try:
            response = await self.httpx_client.get(nexus_org_url, headers=self.headers)
            response.raise_for_status()

            return NexusOrganization(**response.json())
        except Exception as ex:
            logger.error(
                f"Error when fetching organization {lab_id} {ex}. Response {response.json()}"
            )
            raise NexusError(
                message=f"Error when fetching organization {lab_id}",
                type=NexusErrorValue.FETCH_ORGANIZATION_ERROR,
            )

    async def deprecate_organziation(
        self, lab_id: UUID4, revision: int
    ) -> NexusOrganization:
        nexus_org_url = f"{settings.NEXUS_DELTA_URI}/orgs/{str(lab_id)}?rev={revision}"

        try:
            response = await self.httpx_client.delete(
                nexus_org_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusOrganization(**data)
        except Exception as ex:
            logger.error(
                f"Error when deprecation organization {lab_id}: {ex}. Response {response.json()}"
            )
            raise NexusError(
                message=f"Error when deprecation organization {lab_id}",
                type=NexusErrorValue.DEPRECATE_ORGANIZATION_ERROR,
            )

    async def retrieve_latest_org_acls(
        self,
        *,
        org_id: UUID4,
    ) -> NexusResultAcl:
        nexus_acl_url = f"{settings.NEXUS_DELTA_URI}/acls/{str(org_id)}"
        try:
            response = await self.httpx_client.get(
                nexus_acl_url,
                headers=self.headers,
            )
            response.raise_for_status()

            data = response.json()
            return NexusResultAcl(**data)
        except Exception as error:
            logger.error(
                f"Error during fetching acls for lab {org_id} {error}. Response {response.json()}"
            )
            raise NexusError(
                message=f"Error during fetching acls for lab {org_id}",
                type=NexusErrorValue.FETCH_PROJECT_ACL_ERROR,
            )

    async def append_org_acls(
        self,
        *,
        org_id: UUID4,
        group_name: str,
        rev: int,
        permissions: list[str] | None = None,
    ) -> NexusAcls:
        nexus_acl_url = f"{settings.NEXUS_DELTA_URI}/acls/{str(org_id)}?rev={rev}"

        try:
            response = await self.httpx_client.patch(
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
                f"Error when adding acls for lab {org_id}, group {group_name}: {ex}. Response {response.json()}"
            )
            raise NexusError(
                message=f"Error when adding acls for lab {org_id}",
                type=NexusErrorValue.APPEND_ACL_ERROR,
            )
