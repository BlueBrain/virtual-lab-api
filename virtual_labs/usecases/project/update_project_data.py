from http import HTTPStatus as status
from typing import Tuple

from fastapi.responses import Response
from httpx import AsyncClient
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.generic_exceptions import EntityAlreadyExists
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.domain.project import ProjectUpdateBody, ProjectVlOut
from virtual_labs.external.nexus.project_interface import NexusProjectInterface
from virtual_labs.infrastructure.kc.auth import get_client_token
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import (
    ProjectMutationRepository,
    ProjectQueryRepository,
)


async def update_project_data(
    session: AsyncSession,
    httpx_client: AsyncClient,
    *,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    payload: ProjectUpdateBody,
    auth: Tuple[AuthUser, str],
) -> Response:
    pmr = ProjectMutationRepository(session)
    pqr = ProjectQueryRepository(session)
    nexus = NexusProjectInterface(
        httpx_clt=httpx_client, client_token=get_client_token()
    )
    try:
        (project, _) = await pqr.retrieve_one_project_by_id(project_id=project_id)

        newPayload = dict()
        if payload.name is not None and payload.name.strip():
            if bool(
                await pqr.check_project_exists_by_name_per_vlab(
                    vlab_id=virtual_lab_id,
                    query_term=payload.name,
                )
                and project.name != payload.name.strip()
            ):
                raise EntityAlreadyExists(
                    f"Project already exists with this name: '{payload.name}'"
                )

            newPayload.update(
                {
                    "name": payload.name.strip(),
                }
            )
        if payload.description is not None:
            newPayload.update(
                {
                    "description": payload.description.strip(),
                }
            )

        project = await pmr.update_project_data(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=ProjectUpdateBody(**newPayload),
        )
        await nexus.update_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=ProjectUpdateBody(**newPayload),
        )
    except EntityAlreadyExists as ex:
        raise VliError(
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=status.BAD_REQUEST,
            message=ex.message,
        )
    except SQLAlchemyError as ex:
        logger.exception(f"Updating project failed because of error {ex}")
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Updating project failed",
        )
    except NexusError as ex:
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Nexus Project update failed",
            details=ex.type,
        )
    except Exception as ex:
        logger.error(
            f"Error during updating project data: {virtual_lab_id}/{project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during updating project",
        )
    else:
        return VliResponse.new(
            message="Project data updated successfully",
            data={"project": ProjectVlOut.model_validate(project)},
        )
