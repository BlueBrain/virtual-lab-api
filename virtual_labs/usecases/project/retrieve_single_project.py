from http import HTTPStatus as status
from typing import Optional, Tuple

from fastapi.responses import Response
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.domain.project import Project, ProjectVlOut
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.shared.utils.get_one_project_admin import get_one_project_admin


async def retrieve_single_project_use_case(
    session: AsyncSession,
    virtual_lab_id: UUID4,
    project_id: UUID4,
    auth: Optional[Tuple[AuthUser, str]],
) -> Response:
    pr = ProjectQueryRepository(session)
    try:
        project, _ = await pr.retrieve_one_project_strict(virtual_lab_id, project_id)

        _project = ProjectVlOut(
            **{
                **Project.model_validate(project).model_dump(),
                "virtual_lab_id": project.virtual_lab_id,
                "admin": get_one_project_admin(project),
            }
        )

    except NoResultFound:
        raise VliError(
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=status.BAD_REQUEST,
            message="No project found",
        )
    except MultipleResultsFound:
        raise VliError(
            error_code=VliErrorCode.MULTIPLE_ENTITIES_FOUND,
            http_status_code=status.BAD_REQUEST,
            message="Multiple projects found",
        )
    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Retrieving project failed",
        )
    except Exception as ex:
        logger.error(
            f"Error during retrieve project: {virtual_lab_id}/{project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during retrieving project",
        )
    else:
        return VliResponse.new(
            message="Project found successfully",
            data={"project": _project},
        )
