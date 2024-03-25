from http import HTTPStatus as status
from typing import Tuple

from fastapi.responses import Response
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.domain.project import Project
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.shared.utils.auth import get_user_id_from_auth


async def retrieve_starred_projects_use_case(
    session: Session, auth: Tuple[AuthUser, str]
) -> Response | VliError:
    pr = ProjectQueryRepository(session)

    try:
        user_id = get_user_id_from_auth(auth)
        projects = pr.retrieve_starred_projects_per_user(user_id)
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
                "projects": [
                    {
                        **Project(**project.__dict__).model_dump(
                            exclude=[  # type: ignore[arg-type]
                                "admin_group_id",
                                "member_group_id",
                                "nexus_project_id",
                                "created_at",
                            ]
                        ),
                        "starred_at": star.created_at,
                    }
                    for star, project in projects
                ],
                "total": len(projects),
            },
        )
