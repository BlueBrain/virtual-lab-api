from http import HTTPStatus

from pydantic import UUID4
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.domain.common import PageParams, PaginatedResultsResponse
from virtual_labs.domain.labs import VirtualLabDetails
from virtual_labs.repositories import labs as repository
from virtual_labs.repositories.user_repo import UserQueryRepository


async def paginated_labs_for_user(
    db: AsyncSession, page_params: PageParams, user_id: UUID4
) -> PaginatedResultsResponse[VirtualLabDetails]:
    try:
        user_repo = UserQueryRepository()
        group_ids = [group.id for group in user_repo.retrieve_user_groups(user_id)]
        paginated_results = await repository.get_paginated_virtual_labs(
            db, page_params, group_ids=group_ids
        )
        labs = [VirtualLabDetails.model_validate(lab) for lab in paginated_results.rows]
        return PaginatedResultsResponse(
            total=paginated_results.count,
            page=page_params.page,
            page_size=len(paginated_results.rows),
            results=labs,
        )
    except IdentityError:
        raise VliError(
            error_code=VliErrorCode.AUTHORIZATION_ERROR,
            http_status_code=HTTPStatus.UNAUTHORIZED,
            message="User is not authenticated to retrieve virtual labs",
        )
