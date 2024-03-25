from http import HTTPStatus as status
from json import loads
from typing import Tuple

from fastapi.responses import Response
from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.generic_exceptions import UserNotInList
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import (
    ProjectQueryRepository,
)
from virtual_labs.repositories.user_repo import (
    UserMutationRepository,
    UserQueryRepository,
)
from virtual_labs.shared.utils.auth import get_user_id_from_auth


async def update_user_role_in_project(
    session: Session,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    user_id: UUID4,
    new_role: UserRoleEnum,
    auth: Tuple[AuthUser, str],
) -> Response | VliError:
    pqr = ProjectQueryRepository(session)
    uqr = UserQueryRepository()
    umr = UserMutationRepository()

    user_req_id = get_user_id_from_auth(auth)

    if user_req_id.int == user_id.int:
        raise VliError(
            error_code=VliErrorCode.NOT_ALLOWED_OP,
            http_status_code=status.FORBIDDEN,
            message="Update current user role is not allowed",
        )

    try:
        project, _ = pqr.retrieve_one_project_strict(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
        )

        if not uqr.is_user_in_group(
            user_id=user_id,
            group_id=str(project.admin_group_id),
        ) and not uqr.is_user_in_group(
            user_id=user_id,
            group_id=str(project.member_group_id),
        ):
            raise UserNotInList

        new_group_id = (
            project.admin_group_id
            if new_role.value == UserRoleEnum.admin.value
            else project.member_group_id
        )
        old_group_id = (
            project.member_group_id
            if new_role.value == UserRoleEnum.admin.value
            else project.admin_group_id
        )

        if uqr.is_user_in_group(user_id=user_id, group_id=str(new_group_id)):
            return VliResponse.new(
                http_status_code=status.OK,
                message="User already in this group",
            )

        umr.detach_user_from_group(user_id=user_id, group_id=str(old_group_id))
        umr.attach_user_to_group(user_id=user_id, group_id=str(new_group_id))

    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Retrieving project failed",
        )
    except KeycloakError as error:
        logger.warning(
            f"Updating user role/group failed: {loads(error.error_message)["error"]}"
        )
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_GATEWAY,
            message="Update user role in project failed",
        )
    except UserNotInList:
        raise VliError(
            error_code=VliErrorCode.NOT_ALLOWED_OP,
            http_status_code=status.FORBIDDEN,
            message="Update user role not allowed user not in this project members",
        )
    except Exception as ex:
        logger.error(
            f"Error during updating user role ({new_role.value}): {virtual_lab_id}/{project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during updating user role",
        )
    else:
        return VliResponse.new(
            message="Project new role updated successfully",
            data={
                "project_id": project_id,
                "new_role": new_role.value,
            },
        )
