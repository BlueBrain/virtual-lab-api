from http import HTTPStatus
from urllib.parse import quote_plus

from httpx import AsyncClient
from httpx._exceptions import HTTPStatusError
from loguru import logger

from virtual_labs.core.exceptions.nexus_error import NexusError, NexusErrorValue
from virtual_labs.external.nexus.models import NexusBase, NexusUserAgent
from virtual_labs.infrastructure.settings import settings


class NexusAgentInterface:
    httpx_client: AsyncClient
    agent_org_project: str = "bbp/agents"
    person_schema: str = "https://neuroshapes.org/dash/person"

    def __init__(self, client: AsyncClient, client_token: str):
        self.httpx_client = client
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {client_token}",
        }

    @classmethod
    def get_agent_url(cls) -> str:
        return f"{settings.NEXUS_DELTA_URI}/resources/{cls.agent_org_project}"

    def __get_agent_id_from_username__(self, username: str) -> str:
        return f"{settings.NEXUS_DELTA_URI}/realms/{settings.KC_REALM_NAME}/users/{username}"

    async def retrieve_agent(
        self,
        agent_username: str,
    ) -> NexusUserAgent:
        agent_id = self.__get_agent_id_from_username__(username=agent_username)

        try:
            response = await self.httpx_client.get(
                f"{self.get_agent_url()}/_/{quote_plus(agent_id)}", headers=self.headers
            )
            response.raise_for_status()
            return NexusUserAgent.model_validate(response.json())
        except HTTPStatusError as error:
            logger.error(
                f"HTTP Error when retrieving agent from nexus. Error {error}. Nexus Response: {response.json()}"
            )
            raise NexusError(
                message=f"Could not retrieve agent from nexus. Nexus Response: {response.json()}",
                type=NexusErrorValue.GET_AGENT_ERROR,
                http_status_code=HTTPStatus(error.response.status_code),
            )
        except Exception as error:
            logger.error(f"Could not retrieve agent from nexus. Exception {error}")
            raise NexusError(
                message=f"Could not retrieve agent from nexus. Nexus Response: {error}",
                type=NexusErrorValue.GET_AGENT_ERROR,
            )

    async def create_agent(
        self, username: str, first_name: str, last_name: str
    ) -> NexusBase:
        nexus_url = f"{self.get_agent_url()}/{quote_plus(self.person_schema)}"
        try:
            response = await self.httpx_client.post(
                nexus_url,
                headers=self.headers,
                json={
                    "@id": self.__get_agent_id_from_username__(username=username),
                    "@type": ["Agent", "Person"],
                    "familyName": last_name,
                    "givenName": first_name,
                    "name": f"{first_name} {last_name}",
                    "@context": "https://bbp.neuroshapes.org",
                },
            )
            response.raise_for_status()
            return NexusBase.model_validate(response.json())
        except HTTPStatusError as error:
            logger.error(
                f"HTTP Error when creating agent in nexus. Error {error}. Nexus Response: {response.json()}"
            )
            raise NexusError(
                message=f"Could not create agent in nexus. Nexus Response: {response.json()}",
                type=NexusErrorValue.GET_AGENT_ERROR,
                http_status_code=HTTPStatus(error.response.status_code),
            )
        except Exception as error:
            logger.exception(
                f"Could not create agent. Error: {error}. Nexus Response: {response.json()}"
            )
            raise NexusError(
                message=f"Could not create agent in nexus. Error {error}",
                type=NexusErrorValue.CREATE_AGENT_ERROR,
            )
