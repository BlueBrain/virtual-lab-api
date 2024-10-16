from http import HTTPStatus

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from typing_extensions import TypedDict

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.repositories import labs as repository

LabExists = TypedDict("LabExists", {"exists": bool})


async def check_virtual_lab_name_exists(db: AsyncSession, name: str) -> LabExists:
    try:
        if name.strip() == "":
            return {"exists": True}
        return {
            "exists": await repository.count_virtual_labs_with_name(db, name.strip())
            > 0
        }
    except SQLAlchemyError as error:
        logger.error(f"Db error when checking if lab with name exists: {error}")
        raise VliError(
            message=f"Db error when checking if lab with name exists. {error}",
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        ) from error
    except VliError as error:
        raise error
    except Exception as error:
        logger.error(f"Unknown error when checking lab with name exists: {error}")
        raise VliError(
            message=f"Unknown error when checking lab with name exists. {error}",
            error_code=VliErrorCode.INTERNAL_SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        ) from error
