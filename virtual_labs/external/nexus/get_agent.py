import httpx

from virtual_labs.external.nexus.agent_interface import NexusAgentInterface
from virtual_labs.external.nexus.models import NexusUserAgent
from virtual_labs.infrastructure.kc.auth import get_client_token


async def get_agent(agent_username: str) -> NexusUserAgent:
    transport = httpx.AsyncHTTPTransport(retries=3)

    async with httpx.AsyncClient(transport=transport, verify=False) as httpx_client:
        client_token = get_client_token()
        nexus_interface = NexusAgentInterface(httpx_client, client_token)
        return await nexus_interface.retrieve_agent(agent_username=agent_username)
