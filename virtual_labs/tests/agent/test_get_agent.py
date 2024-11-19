from http import HTTPStatus

import pytest
from httpx import AsyncClient
from loguru import logger

from virtual_labs.infrastructure.settings import settings
from virtual_labs.tests.utils import get_headers


@pytest.mark.asyncio
async def test_get_agent(async_test_client: AsyncClient) -> None:
    user = "test-2"
    headers = get_headers(user)
    response = await async_test_client.get("/agent", headers=headers)
    assert response.status_code == HTTPStatus.OK

    expected_agent_response = {
        "id": f"{settings.NEXUS_DELTA_URI}/realms/{settings.KC_REALM_NAME}/users/{user}",
        "given_name": user,
        "family_name": user,
        "name": f"{user} {user}",
    }

    gotten_agent_response = response.json()["data"]
    logger.debug(f"Agent message {response.json()["message"]}")

    assert gotten_agent_response["createdAt"] is not None
    gotten_agent_response.pop("createdAt")
    assert expected_agent_response == gotten_agent_response
