from typing import AsyncGenerator, cast
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import get_headers


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, str, str, dict[str, str]], None]:
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

    project_body = {
        "name": f"Test Project {uuid4()}",
        "description": "Test",
    }
    project_response = await client.post(
        f"/virtual-labs/{lab_id}/projects",
        json=project_body,
        headers=headers,
    )
    project_id = cast("str", project_response.json()["data"]["project"]["id"])

    yield client, lab_id, project_id, headers

    lab_id = response.json()["data"]["virtual_lab"]["id"]
    response = await client.delete(f"/virtual-labs/{lab_id}", headers=get_headers())
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_get_lab_by_id(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_id, project_id, headers = mock_lab_create

    response = await client.get(f"/virtual-labs/{lab_id}", headers=headers)
    assert response.status_code == 200
    lab = response.json()["data"]["virtual_lab"]
    assert len(lab["projects"]) == 1
    assert lab["projects"][0]["id"] == project_id
    assert lab["projects"][0]["starred"] is False
    assert len(lab["users"]) == 1
    assert lab["users"][0]["username"] == "test"
    assert lab["users"][0]["invite_accepted"] is True


@pytest.mark.asyncio
async def test_update_lab_has_same_response_as_get_lab_by_id(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_id, project_id, headers = mock_lab_create
    update_response = await client.patch(
        f"/virtual-labs/{lab_id}", headers=headers, json={"plan_id": 2}
    )
    get_response = await client.get(f"/virtual-labs/{lab_id}", headers=headers)

    assert update_response.status_code == get_response.status_code == 200
    assert update_response.json()["data"] == get_response.json()["data"]
