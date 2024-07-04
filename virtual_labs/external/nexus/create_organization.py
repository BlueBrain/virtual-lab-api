import httpx
from pydantic import UUID4

from virtual_labs.external.nexus.acl_list import (
    virtual_lab_admin_acls,
    virtual_lab_member_acls,
)
from virtual_labs.external.nexus.models import NexusOrganization
from virtual_labs.external.nexus.organization_interface import (
    NexusOrganizationInterface,
)
from virtual_labs.infrastructure.kc.auth import get_client_token


async def create_nexus_organization(
    nexus_org_id: UUID4,
    description: str | None,
    admin_group_name: str,
    member_group_name: str,
) -> NexusOrganization:
    transport = httpx.AsyncHTTPTransport(retries=3)
    async with httpx.AsyncClient(transport=transport) as httpx_client:
        client_token = get_client_token()
        nexus_org_interface = NexusOrganizationInterface(httpx_client, client_token)
        nexus_org = await nexus_org_interface.create_organization(
            nexus_org_id, description
        )

        # get the latest organization acl for revision
        acls = await nexus_org_interface.retrieve_latest_org_acls(org_id=nexus_org_id)
        latest_acl = acls.results[0].rev

        # Append acls to the admin group
        admin_acls = await nexus_org_interface.append_org_acls(
            org_id=nexus_org_id,
            group_name=admin_group_name,
            permissions=virtual_lab_admin_acls,
            rev=latest_acl,
        )

        # Append acls to the member group

        await nexus_org_interface.append_org_acls(
            org_id=nexus_org_id,
            group_name=member_group_name,
            permissions=virtual_lab_member_acls,
            rev=admin_acls.rev,
        )

        return nexus_org
