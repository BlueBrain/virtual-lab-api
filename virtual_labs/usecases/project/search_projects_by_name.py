from http import HTTPStatus as status
from typing import Tuple

from fastapi.responses import Response
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.domain.project import Project, VirtualLabModel
from virtual_labs.domain.user import ShortenedUser
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.repositories.user_repo import UserQueryRepository
from virtual_labs.shared.utils.auth import get_user_id_from_auth


async def search_projects_by_name_use_case(
    session: AsyncSession, query_term: str | None, auth: Tuple[AuthUser, str]
) -> Response | VliError:
    pr = ProjectQueryRepository(session)
    gqr = GroupQueryRepository()
    uqr = UserQueryRepository()

    user_id = get_user_id_from_auth(auth)

    if not query_term:
        raise VliError(
            error_code=VliErrorCode.INVALID_PARAMETER,
            http_status_code=status.BAD_REQUEST,
            message="No search query provided",
        )
    try:
        groups = gqr.retrieve_user_groups(user_id=str(user_id))
        group_ids = [g.id for g in groups]
        projects_vl_tuple = await pr.search(
            query_term=query_term,
            groups_ids=group_ids,
        )

        projects = [
            {
                **Project(**p.__dict__).model_dump(),
                "virtual_lab": VirtualLabModel(**v.__dict__),
                "owner": ShortenedUser(
                    **uqr.retrieve_user_from_kc(user_id=str(p.owner_id)).__dict__
                ),
            }
            for p, v in projects_vl_tuple
        ]

    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Searching for projects failed",
        )
    except Exception as ex:
        logger.error(f"Error during searching for projects in ({ex})")
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during searching for project",
        )
    else:
        return VliResponse.new(
            message=f"Projects with '{query_term}' found successfully"
            if len(projects) > 0
            else "No projects was found",
            data={
                "projects": projects,
                "total": len(projects),
            },
        )
