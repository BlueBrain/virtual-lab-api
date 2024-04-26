import asyncio
from typing import Any, AsyncGenerator
from uuid import uuid4

import pytest_asyncio
from httpx import AsyncClient, Response

from virtual_labs.api import app
from virtual_labs.tests.utils import cleanup_resources, get_headers

VL_COUNT = 2
PROJECTS_PER_VL_COUNT = 2


@pytest_asyncio.fixture()
async def async_test_client() -> AsyncGenerator[AsyncClient, None]:
    # default header used in this test client are for the user=test
    # if you need another test user please override the headers in the test
    headers = get_headers()
    async with AsyncClient(
        app=app,
        base_url="http://localhost:8000",
        headers=headers,
    ) as ac:
        yield ac


@pytest_asyncio.fixture(scope="session", autouse=True)
def event_loop(request: Any) -> Any:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[Response, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10000,
        "plan_id": 1,
    }
    headers = get_headers()
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )

    yield response, headers

    lab_id = response.json()["data"]["virtual_lab"]["id"]
    await cleanup_resources(client, lab_id)
