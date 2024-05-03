from http import HTTPStatus as status

from fastapi.responses import Response
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.repositories.project_repo import ProjectQueryRepository
from virtual_labs.shared.utils.uniq_list import uniq_list


async def retrieve_users_per_project_count_use_case(
    session: AsyncSession, project_id: UUID4
) -> Response | VliError:
    pr = ProjectQueryRepository(session)
    gqr = GroupQueryRepository()

    try:
        project, _ = await pr.retrieve_one_project_by_id(project_id)
        admins = gqr.retrieve_group_users(group_id=str(project.admin_group_id))
        members = gqr.retrieve_group_users(group_id=str(project.member_group_id))

        users = uniq_list([u.id for u in admins + members])

    except SQLAlchemyError as ex:
        logger.error(
            f"DB error during retrieving users per project count: {project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Retrieving users per project failed",
        )
    except Exception as ex:
        logger.error(
            f"Error during retrieving users per project count: {project_id} ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during retrieving users per project",
        )
    else:
        return VliResponse.new(
            message="Count users per project fetched successfully",
            data={
                "project_id": project_id,
                "total": len(users),
            },
        )
