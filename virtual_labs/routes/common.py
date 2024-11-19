from fastapi import APIRouter, Depends

from virtual_labs.domain.labs import LabResponse
from virtual_labs.domain.user import AllUsersCount, UserAgentResponse
from virtual_labs.infrastructure.kc.auth import verify_jwt
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.usecases.users.get_count_of_all_users import get_count_of_all_users
from virtual_labs.usecases.users.get_or_create_user_agent import (
    get_or_create_user_agent,
)

router = APIRouter()


@router.get("/users_count", response_model=LabResponse[AllUsersCount])
async def get_all_users_count(
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[AllUsersCount]:
    return await get_count_of_all_users()


@router.get("/agent", tags=["Agent"], response_model=LabResponse[UserAgentResponse])
async def get_or_create_agent(
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[UserAgentResponse]:
    """
    Gets the "Agent" entity for the user calling the api (derived from the "Authorization" header). If the agent does not exist, a new one is created and returned.
    """
    return await get_or_create_user_agent(user=auth[0])
