from functools import wraps
from http import HTTPStatus as status
from typing import Any, Callable

from loguru import logger

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.repositories.user_repo import UserQueryRepository
from virtual_labs.shared.utils.auth import get_user_id_from_auth


def verify_user_authenticated(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    This decorator checks that the request contains auth headers with a bearer token that
    corresponds to a valid keycloak user (i.e. the user making the request is recognized by our identity provider)
    """

    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            auth = kwargs["auth"]

            user_repo = UserQueryRepository()
            user_id = get_user_id_from_auth(auth)
            user_repo.retrieve_user_from_kc(str(user_id))
        except Exception as error:
            logger.exception(
                f"Unknown error when checking for user_authentication: {error}"
            )
            raise VliError(
                error_code=VliErrorCode.AUTHORIZATION_ERROR,
                http_status_code=status.UNAUTHORIZED,
                message="Checking for authorization failed",
                details=str(error),
            )

        else:
            return await f(*args, **kwargs)

    return wrapper
