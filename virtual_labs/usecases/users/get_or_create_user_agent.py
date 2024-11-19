from http import HTTPStatus

from loguru import logger

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.domain.labs import LabResponse
from virtual_labs.domain.user import UserAgentResponse
from virtual_labs.external.nexus.create_agent import create_agent
from virtual_labs.external.nexus.get_agent import get_agent
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.shared.utils.name import extract_name_parts


async def get_or_create_user_agent(user: AuthUser) -> LabResponse[UserAgentResponse]:
    """
    Fetches the agent information from nexus for the user passed in the user token.
    If the nexus agent does not exist, one is created and returned.
    """
    try:
        nexus_agent = await get_agent(agent_username=user.username)
        return LabResponse(
            message="Agent successfully fetched",
            data=UserAgentResponse.model_validate(nexus_agent.model_dump()),
        )
    except NexusError as nexus_error:
        if nexus_error.http_status_code == HTTPStatus.NOT_FOUND:
            try:
                logger.debug("Agent for user not found. About to create one.")
                (firstname, lastname) = extract_name_parts(user.name)
                await create_agent(
                    username=user.username, first_name=firstname, last_name=lastname
                )
                created_agent = await get_agent(agent_username=user.username)
                return LabResponse(
                    message="Agent successfully created",
                    data=UserAgentResponse.model_validate(created_agent.model_dump()),
                )
            except NexusError as err:
                raise VliError(
                    message="Creating agent on nexus failed",
                    details=f"{err}",
                    error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
                    http_status_code=err.http_status_code
                    if err.http_status_code is not None
                    else HTTPStatus.BAD_GATEWAY,
                )
            except Exception as err:
                logger.exception(f"Unknown error occured when creating agent {err}")
                raise VliError(
                    message="Creating agent on nexus failed due to an unknown error",
                    details=f"{err}",
                    error_code=VliErrorCode.INTERNAL_SERVER_ERROR,
                    http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
        else:
            raise VliError(
                message="Unknown nexus error when retrieving agent",
                details=f"{nexus_error}",
                error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
                http_status_code=nexus_error.http_status_code
                if nexus_error.http_status_code is not None
                else HTTPStatus.BAD_GATEWAY,
            )
    except VliError as verr:
        raise verr
    except Exception as error:
        logger.exception(f"Unknown error when retrieving agent from nexus {error}")
        raise VliError(
            message="Unknown error when retrieving agent from nexus",
            details=f"{error}",
            error_code=VliErrorCode.INTERNAL_SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
