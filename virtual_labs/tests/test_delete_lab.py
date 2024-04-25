from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response

from virtual_labs.tests.utils import cleanup_resources, get_headers


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, Response, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 3,
    }
    headers = get_headers()
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )
    assert response.status_code == 200
    lab_id = response.json()["data"]["virtual_lab"]["id"]

    # Able to retrive virtual lab before deletion
    newly_created_lab = await client.get(f"/virtual-labs/{lab_id}", headers=headers)
    assert newly_created_lab.status_code == 200
    yield client, response, headers

    await cleanup_resources(client=async_test_client, lab_id=lab_id)


@pytest.mark.asyncio
async def test_delete_lab(
    mock_lab_create: tuple[AsyncClient, Response, dict[str, str]],
) -> None:
    client, response, headers = mock_lab_create

    lab_id = response.json()["data"]["virtual_lab"]["id"]
    response = await client.delete(f"/virtual-labs/{lab_id}", headers=headers)
    assert response.status_code == 200

    # Not able to retrieve virtual lab after deletion
    deleted_lab = await client.get(f"/virtual-labs/{lab_id}", headers=headers)
    assert deleted_lab.status_code == 404
