from http import HTTPStatus
from json import loads

from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.repositories import labs as lab_repository
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.repositories.user_repo import UserMutationRepository
from virtual_labs.shared.utils.is_user_in_lab import is_user_admin_of_lab


async def remove_user_from_lab(lab_id: UUID4, user_id: UUID4, db: AsyncSession) -> None:
    try:
        lab = await lab_repository.get_undeleted_virtual_lab(db, lab_id)

        user_repository = UserMutationRepository()
        group_repository = GroupQueryRepository()

        admins = group_repository.retrieve_group_users(str(lab.admin_group_id))
        if len(admins) == 1 and is_user_admin_of_lab(user_id, lab):
            raise VliError(
                message=f"Last admin of lab {lab_id} cannot be removed",
                error_code=VliErrorCode.NOT_ALLOWED_OP,
                http_status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                details="Lab needs to have at least 1 admin.",
            )

        user_repository.detach_user_from_group(
            user_id=user_id, group_id=str(lab.admin_group_id)
        )
        user_repository.detach_user_from_group(
            user_id=user_id, group_id=str(lab.member_group_id)
        )

        return
    except SQLAlchemyError as error:
        logger.error(
            f"Db error when retrieving virtual lab {lab_id} for removing user {user_id}. {error}"
        )
        raise VliError(
            message="Virtual lab could not be retrieved",
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    except KeycloakError as error:
        logger.warning(
            f"Removing user {user_id} from lab {lab_id}, groups failed: {loads(error.error_message)["error"]}"
        )
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=error.response_code or HTTPStatus.BAD_GATEWAY,
            message="Removing user from virtual lab failed due to a keycloak error",
        )
    except VliError as error:
        raise error
    except Exception as error:
        logger.warning(
            f"Unknown error when removing user {user_id} to lab {lab_id}: {error}"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            message="Adding user to virtual lab failed due to an internal server error",
        )
