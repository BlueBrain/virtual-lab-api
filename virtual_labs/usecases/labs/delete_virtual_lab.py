from datetime import datetime
from http import HTTPStatus

from loguru import logger
from pydantic import UUID4, BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.domain.labs import VirtualLabDetails, VirtualLabOut
from virtual_labs.external.nexus.deprecate_organization import (
    deprecate_nexus_organization,
)
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories import labs as repository
from virtual_labs.shared.utils.auth import get_user_id_from_auth


class ProjectWithIds(BaseModel):
    id: UUID4
    deleted: bool
    admin_group_id: str
    member_group_id: str

    class Config:
        from_attributes = True


async def delete_virtual_lab(
    db: AsyncSession, lab_id: UUID4, auth: tuple[AuthUser, str]
) -> VirtualLabOut:
    try:
        db_lab = await repository.get_virtual_lab_async(db, lab_id)
        user_id = get_user_id_from_auth(auth)

        response = VirtualLabOut(virtual_lab=VirtualLabDetails.model_validate(db_lab))
        if db_lab.deleted is True:
            return response

        nexus_org = await deprecate_nexus_organization(lab_id)
        logger.debug(f"Deprecated nexus organization {nexus_org.label}")

        await repository.delete_virtual_lab(db, lab_id, user_id)

        response.virtual_lab.deleted = True
        response.virtual_lab.deleted_at = datetime.now()
        return response
    except SQLAlchemyError:
        raise VliError(
            message="Virtual lab not found",
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=HTTPStatus.NOT_FOUND,
        )
    except VliError as error:
        raise error
    except Exception as error:
        logger.warning(f"Deleting virtual lab failed  failed: {error}")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=HTTPStatus.BAD_GATEWAY,
            message=f"Virtual lab deletion could not be completed due to an unknown error: {error}",
        )
