import asyncio
from typing import Tuple

import httpx
from pydantic import UUID4

from virtual_labs.external.nexus.acl_list import project_admin_acls, project_member_acls
from virtual_labs.external.nexus.default_mapping import DEFAULT_MAPPING
from virtual_labs.external.nexus.defaults import (
    CROSS_RESOLVER,
    DEFAULT_API_MAPPING_RESOURCE,
    DEFAULT_PROJECT_VOCAB,
    ES_RESOURCE_TYPE,
    ES_VIEW_ID,
    prep_default_local_context,
)
from virtual_labs.external.nexus.models import NexusIdentity
from virtual_labs.external.nexus.project_interface import NexusProjectInterface
from virtual_labs.infrastructure.kc.auth import get_client_token
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.infrastructure.settings import settings


# TODO: check for storage creation
async def instantiate_nexus_project(
    *,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    description: str | None,
    admin_group_name: str,
    member_group_name: str,
    auth: Tuple[AuthUser, str],
) -> str:
    transport = httpx.AsyncHTTPTransport(retries=3)

    async with httpx.AsyncClient(transport=transport) as httpx_clt:
        nexus_interface = NexusProjectInterface(
            httpx_clt,
            get_client_token(),
        )
        user, _ = auth

        sbo_suite_projects = await nexus_interface.get_sbo_suite_projects()

        # get the latest api mapping
        # TODO: to confirm if the api mapping has the full set
        api_mappings_datamodels = (
            await nexus_interface.retrieve_resource(
                virtual_lab_id="neurosciencegraph",
                project_id="datamodels",
                resource_id=DEFAULT_API_MAPPING_RESOURCE,
            )
        ).apiMappings
        # create the new project
        nexus_project = await nexus_interface.create_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            vocab=DEFAULT_PROJECT_VOCAB,
            apiMapping=api_mappings_datamodels,
            description=description,
        )
        # Add the CrossProject resolver pointing to projects with public data
        await nexus_interface.create_resolver(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            type=CROSS_RESOLVER,
            projects=sbo_suite_projects,
            identities=[
                NexusIdentity(realm=settings.KC_REALM_NAME, type="Authenticated"),
            ],
        )
        await asyncio.gather(
            *list(
                map(
                    asyncio.create_task,
                    [
                        # Add the local context resource to the project
                        nexus_interface.create_resource(
                            virtual_lab_id=virtual_lab_id,
                            project_id=project_id,
                            payload=prep_default_local_context(
                                vocab=DEFAULT_PROJECT_VOCAB,
                            ),
                        ),
                        # Create dataset elastic search view in the project
                        nexus_interface.create_es_view(
                            virtual_lab_id=virtual_lab_id,
                            project_id=project_id,
                            mapping=DEFAULT_MAPPING,
                            view_id=ES_VIEW_ID,
                            resource_types=ES_RESOURCE_TYPE,
                            source_as_text=False,
                            include_metadata=True,
                            include_deprecated=False,
                        ),
                    ],
                )
            )
        )

        # get the latest project acl for revision
        acls = await nexus_interface.retrieve_project_latest_acls(
            virtual_lab_id=virtual_lab_id, project_id=project_id
        )
        last_acl_rev = acls.results[0].rev

        # Append Acls to the admin group
        appended_admin_group_acls = await nexus_interface.append_project_acls(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            group_name=admin_group_name,
            permissions=project_admin_acls,
            rev=last_acl_rev,
        )

        nexus_tasks = [
            # Append Acls to the member group
            nexus_interface.append_project_acls(
                virtual_lab_id=virtual_lab_id,
                project_id=project_id,
                group_name=member_group_name,
                permissions=project_member_acls,
                rev=appended_admin_group_acls.rev,
            ),
            # Create aggregated elastic search view in the project
            nexus_interface.create_nexus_es_aggregate_view(
                virtual_lab_id=virtual_lab_id,
                project_id=project_id,
                extra_projects=sbo_suite_projects,
            ),
            # Create aggregated Sparql view in the project
            nexus_interface.create_nexus_sp_aggregate_view(
                virtual_lab_id=virtual_lab_id,
                project_id=project_id,
                extra_projects=sbo_suite_projects,
            ),
            # Create S3 storage
            nexus_interface.create_s3_storage(
                virtual_lab_id=virtual_lab_id, project_id=project_id
            ),
        ]

        await asyncio.gather(
            *list(
                map(
                    asyncio.create_task,
                    nexus_tasks,
                )
            )
        )

        return nexus_project.self
