from functools import wraps
from http import HTTPStatus as status
from typing import Any, Callable

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.generic_exceptions import UserNotInList
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.repositories.labs import get_undeleted_virtual_lab
from virtual_labs.shared.utils.auth import get_user_id_from_auth
from virtual_labs.shared.utils.is_user_in_list import is_user_in_list
from virtual_labs.shared.utils.uniq_list import uniq_list


def verify_vlab_write(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    This decorator to check if the user is VL admin group
    to perform this action
    """

    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            virtual_lab_id = kwargs["virtual_lab_id"]
            session = kwargs["session"]
            auth = kwargs["auth"]
            user_id = get_user_id_from_auth(auth)

            gqr = GroupQueryRepository()

            vlab = await get_undeleted_virtual_lab(
                session,
                lab_id=virtual_lab_id,
            )
            users = gqr.retrieve_group_users(group_id=str(vlab.admin_group_id))
            uniq_users = uniq_list([u.id for u in users])

            is_user_in_list(list_=uniq_users, user_id=str(user_id))

        except SQLAlchemyError:
            raise VliError(
                error_code=VliErrorCode.DATABASE_ERROR,
                http_status_code=status.NOT_FOUND,
                message="No VL with this id found",
            )
        except UserNotInList:
            raise VliError(
                error_code=VliErrorCode.NOT_ALLOWED_OP,
                http_status_code=status.FORBIDDEN,
                message="The supplied authentication is not authorized for this action",
            )
        except Exception as error:
            logger.warning(f"Error while checking authorization {error}")
            raise VliError(
                error_code=VliErrorCode.INTERNAL_SERVER_ERROR,
                http_status_code=status.BAD_REQUEST,
                message="Checking for authorization failed",
            )

        else:
            return await f(*args, **kwargs)

    return wrapper
