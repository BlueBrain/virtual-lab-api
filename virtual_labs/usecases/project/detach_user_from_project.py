from datetime import datetime
from http import HTTPStatus as status
from json import loads
from typing import Tuple

from fastapi.responses import Response
from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.generic_exceptions import ForbiddenOperation
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.repositories.user_repo import UserMutationRepository
from virtual_labs.shared.utils.uniq_list import uniq_list


async def detach_user_from_project(
    session: AsyncSession,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    user_id: UUID4,
    auth: Tuple[AuthUser, str],
) -> Response:
    pqr = ProjectQueryRepository(session)
    umr = UserMutationRepository()
    gqr = GroupQueryRepository()

    try:
        project, vl = await pqr.retrieve_one_project_strict(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
        )
        users = gqr.retrieve_group_users(group_id=str(vl.admin_group_id))
        users_list = uniq_list([u.id for u in users])

        if (user_id == project.owner_id) or (user_id in users_list):
            raise ForbiddenOperation

        umr.detach_user_from_group(
            user_id=user_id, group_id=str(project.admin_group_id)
        )
        umr.detach_user_from_group(
            user_id=user_id, group_id=str(project.member_group_id)
        )

    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Retrieving project failed",
        )
    except KeycloakError as error:
        logger.warning(
            f"Detaching user from project: {loads(error.error_message)["error"]}"
        )
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=error.response_code or status.BAD_GATEWAY,
            message="Detaching user from project failed",
        )
    except ForbiddenOperation:
        raise VliError(
            error_code=VliErrorCode.NOT_ALLOWED_OP,
            http_status_code=status.FORBIDDEN,
            message="Can not detach the owner of the project",
        )
    except Exception as ex:
        logger.error(
            f"Error during detaching user from project: {virtual_lab_id}/{project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during detaching user from project",
        )
    else:
        return VliResponse.new(
            message="User Detached from project successfully",
            data={
                "project_id": project_id,
                "detached": True,
                "detached_at": datetime.now(),
            },
        )
