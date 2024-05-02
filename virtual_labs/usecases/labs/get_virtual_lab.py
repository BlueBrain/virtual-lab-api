from http import HTTPStatus

from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.domain.labs import VirtualLabDetails, VirtualLabOut
from virtual_labs.repositories import labs as repository


async def get_virtual_lab(
    db: AsyncSession, lab_id: UUID4, user_id: UUID4
) -> VirtualLabOut:
    try:
        db_lab = await repository.get_undeleted_virtual_lab(db, lab_id)
        return VirtualLabOut(virtual_lab=VirtualLabDetails.model_validate(db_lab))
    except SQLAlchemyError as error:
        raise VliError(
            message="Virtual lab not found",
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=HTTPStatus.NOT_FOUND,
        ) from error
    except VliError as error:
        raise error
