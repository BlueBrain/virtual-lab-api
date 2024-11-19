import httpx

from virtual_labs.external.nexus.agent_interface import NexusAgentInterface
from virtual_labs.external.nexus.models import NexusBase
from virtual_labs.infrastructure.kc.auth import get_client_token


async def create_agent(username: str, first_name: str, last_name: str) -> NexusBase:
    transport = httpx.AsyncHTTPTransport(retries=3)

    async with httpx.AsyncClient(transport=transport, verify=False) as httpx_client:
        client_token = get_client_token()
        nexus_interface = NexusAgentInterface(httpx_client, client_token)
        return await nexus_interface.create_agent(
            username=username, first_name=first_name, last_name=last_name
        )
