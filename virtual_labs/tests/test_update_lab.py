from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import cleanup_resources, get_headers


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, str, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
    }
    headers = get_headers()
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )
    assert response.status_code == 200
    lab_id = response.json()["data"]["virtual_lab"]["id"]
    yield client, lab_id, headers

    await cleanup_resources(client=client, lab_id=lab_id)


@pytest.mark.asyncio
async def test_update_lab(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, headers = mock_lab_create

    update_body = {"name": "New Name", "plan_id": 2, "budget": 200}
    response = await client.patch(
        f"/virtual-labs/{lab_id}", headers=headers, json=update_body
    )
    assert response.status_code == 200
    data = response.json()["data"]["virtual_lab"]
    assert data["name"] == update_body["name"]
    assert data["plan_id"] == update_body["plan_id"]
    assert data["budget"] == update_body["budget"]
