import copy
from typing import Any, AsyncGenerator, cast
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response

from virtual_labs.tests.utils import cleanup_resources, get_headers


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
    lab_delete_response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )

    assert lab_delete_response.status_code == 200
    lab_id = lab_delete_response.json()["data"]["virtual_lab"]["id"]

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
    await cleanup_resources(client=client, lab_id=lab_id, project_ids=[project_id])


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


def assert_get_and_delete_body_are_same(
    get_response: Response, delete_response: Response
) -> None:
    """Checks that virtual lab in the response of get and delete endpoints are the same (except the `deleted` and `deleted_at` values, which will be different)."""
    delete_body = copy.deepcopy(
        cast(dict[str, Any], delete_response.json()["data"]["virtual_lab"])
    )
    assert delete_body["deleted"] is True
    assert delete_body["deleted_at"] is not None
    del delete_body["deleted"]
    del delete_body["deleted_at"]

    get_body = copy.deepcopy(
        cast(dict[str, Any], get_response.json()["data"]["virtual_lab"])
    )
    assert get_body["deleted"] is False
    assert get_body["deleted_at"] is None
    del get_body["deleted"]
    del get_body["deleted_at"]

    assert delete_body == get_body


@pytest.mark.asyncio
async def test_get_udpate_delete_response_are_same(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_id, project_id, headers = mock_lab_create
    update_response = await client.patch(
        f"/virtual-labs/{lab_id}", headers=headers, json={"plan_id": 2}
    )
    get_response = await client.get(f"/virtual-labs/{lab_id}", headers=headers)

    assert update_response.status_code == get_response.status_code == 200
    assert update_response.json()["data"] == get_response.json()["data"]

    delete_response = await client.delete(f"/virtual-labs/{lab_id}", headers=headers)
    assert delete_response.status_code == get_response.status_code == 200
    assert_get_and_delete_body_are_same(get_response, delete_response)
