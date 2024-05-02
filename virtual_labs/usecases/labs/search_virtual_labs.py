from http import HTTPStatus

from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.domain.labs import SearchLabResponse, VirtualLabDetails
from virtual_labs.repositories import labs as respository
from virtual_labs.repositories.user_repo import UserQueryRepository


async def search_virtual_labs_by_name(
    term: str, db: AsyncSession, user_id: UUID4
) -> SearchLabResponse:
    try:
        user_repo = UserQueryRepository()
        group_ids = [group.id for group in user_repo.retrieve_user_groups(user_id)]

        matching_labs = [
            VirtualLabDetails.model_validate(lab)
            for lab in await respository.get_virtual_labs_with_matching_name(
                db, term, group_ids
            )
        ]
        return SearchLabResponse(virtual_labs=matching_labs)
    except IdentityError as error:
        logger.error(f"Identity error when retrieving user roles {error}")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=HTTPStatus.UNAUTHORIZED,
            message="Could not retrieve groups for user",
        )
    except SQLAlchemyError as error:
        logger.error(f"Db error when retrieving labs with matching name: {error}")
        raise VliError(
            message=f"Labs with matching name could not be retrieved from the db. {error}",
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        ) from error
    except VliError as error:
        raise error
    except Exception as error:
        logger.error(f"Unkown error when retrieving labs with matching name: {error}")
        raise VliError(
            message=f"Unkown error when retrieving labs with matching name. {error}",
            error_code=VliErrorCode.INTERNAL_SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        ) from error
