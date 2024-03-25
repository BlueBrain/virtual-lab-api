from http import HTTPStatus as status
from json import loads
from typing import Tuple
from uuid import UUID

from fastapi.responses import Response
from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.generic_exceptions import (
    ProjectAlreadyDeleted,
)
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.external.nexus.project_deletion import delete_nexus_project
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import (
    ProjectMutationRepository,
    ProjectQueryRepository,
)


async def delete_project_use_case(
    session: Session,
    *,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    auth: Tuple[AuthUser, str],
) -> Response | VliError:
    pqr = ProjectQueryRepository(session)
    pmr = ProjectMutationRepository(session)
    user, _ = auth

    try:
        vl_project = pqr.retrieve_one_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
        )
        assert vl_project is not None
        if vl_project[0] and vl_project[0].deleted:
            raise ProjectAlreadyDeleted

    except AssertionError:
        raise VliError(
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=status.BAD_REQUEST,
            message="Project not found",
        )
    except ProjectAlreadyDeleted:
        raise VliError(
            error_code=VliErrorCode.ENTITY_ALREADY_DELETED,
            http_status_code=status.BAD_REQUEST,
            message="Project already marked as 'deleted'",
        )

    try:
        (
            deleted_project_id,
            deleted,
            deleted_at,
        ) = pmr.delete_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            user_id=UUID(user.sub),
        )

    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Project deletion failed",
        )
    except KeycloakError as ex:
        logger.warning(f"project deletion from KC: {loads(ex.error_message)["error"]}")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=ex.response_code,
            message="Group deletion failed",
            details=loads(ex.error_message)["error"],
        )
    except Exception as ex:
        logger.error(
            f"Error during deleting the project: {virtual_lab_id}/{project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during deleting the project",
        )

    try:
        await delete_nexus_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            auth=auth,
        )
    except NexusError as ex:
        pmr.un_delete_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
        )
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Project deprecation failed",
            details=ex.type,
        )
    else:
        return VliResponse.new(
            message="Project marked as deleted successfully",
            data={
                "project_id": deleted_project_id,
                "deleted": deleted,
                "deleted_at": deleted_at,
            },
        )
