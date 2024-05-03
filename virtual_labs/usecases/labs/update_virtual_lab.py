from http import HTTPStatus

from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import IntegrityError, NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.domain import labs as domain
from virtual_labs.repositories import labs as repository
from virtual_labs.shared.utils.db_lab_to_domain_lab import db_lab_to_domain_lab
from virtual_labs.usecases.plans.verify_plan import verify_plan


async def update_virtual_lab(
    db: AsyncSession, lab_id: UUID4, lab: domain.VirtualLabUpdate, user_id: UUID4
) -> domain.VirtualLabOut:
    try:
        if lab.plan_id is not None:
            await verify_plan(db, lab.plan_id)
        db_lab = await repository.update_virtual_lab(db, lab_id, lab)
        return domain.VirtualLabOut(virtual_lab=db_lab_to_domain_lab(db_lab))
    except IntegrityError as error:
        logger.error(
            "Virtual lab {} update could not be processed because it violates db constraints {}".format(
                lab_id, error
            )
        )
        raise VliError(
            message="Another virtual lab with same name already exists",
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=HTTPStatus.CONFLICT,
        )
    except NoResultFound:
        raise VliError(
            message="Virtual lab not found",
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=HTTPStatus.NOT_FOUND,
        )
    except ValueError as error:
        raise VliError(
            message=str(error),
            error_code=VliErrorCode.INVALID_REQUEST,
            http_status_code=HTTPStatus.BAD_REQUEST,
        )
    except SQLAlchemyError as error:
        logger.error(
            "Virtual lab {} update could not be processed for unknown database error {}".format(
                lab_id, error
            )
        )

        raise VliError(
            message="Virtual lab could not be saved to the database",
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=HTTPStatus.BAD_REQUEST,
        )
    except VliError as error:
        raise error
    except Exception as error:
        logger.error(
            "Virtual lab could not be saved due to an unknown error {}".format(error)
        )

        raise VliError(
            message="Virtual lab could not be saved to the database",
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
