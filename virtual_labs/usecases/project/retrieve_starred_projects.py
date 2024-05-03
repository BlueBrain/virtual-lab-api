from http import HTTPStatus as status
from typing import Tuple

from fastapi.responses import Response
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.domain.common import PageParams
from virtual_labs.domain.project import Project
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.shared.utils.auth import get_user_id_from_auth
from virtual_labs.shared.utils.get_one_project_admin import get_one_project_admin


async def retrieve_starred_projects_use_case(
    session: AsyncSession, auth: Tuple[AuthUser, str], pagination: PageParams
) -> Response | VliError:
    pr = ProjectQueryRepository(session)

    try:
        user_id = get_user_id_from_auth(auth)
        results = await pr.retrieve_starred_projects_per_user(
            user_id,
            pagination=pagination,
        )

        projects = [
            {
                **Project(**project.__dict__).model_dump(),
                "starred_at": star_p.created_at,
                "virtual_lab_id": project.virtual_lab_id,
                "admin": get_one_project_admin(project),
            }
            for star_p, project in results.rows
        ]

    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Retrieving starred project failed",
        )
    except Exception as ex:
        logger.error(
            f"Error during retrieving starred projects for user: {user_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during retrieving starred projects",
        )
    else:
        return VliResponse.new(
            message="Starred projects found successfully",
            data={
                "results": projects,
                "page": pagination.page,
                "size": pagination.size,
                "page_size": len(projects),
                "total": results.count,
            },
        )
