from http import HTTPStatus
from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response

from virtual_labs.tests.utils import (
    cleanup_resources,
    create_mock_lab_with_project,
    get_headers,
)


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
        "entity": "EPFL, Switzerland",
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


@pytest.mark.asyncio
async def test_deleting_labs_deletes_all_projects_only_in_that_lab(
    async_test_client: AsyncClient,
) -> None:
    lab_to_delete, project_1_id = await create_mock_lab_with_project(async_test_client)
    lab_to_keep, project_2_id = await create_mock_lab_with_project(async_test_client)

    user_projects = await async_test_client.get("/virtual-labs/projects")
    count_before_deleting = user_projects.json()["data"]["total"]
    assert count_before_deleting >= 2

    delete_response = await async_test_client.delete(
        f"/virtual-labs/{lab_to_delete["id"]}", headers=get_headers()
    )
    assert delete_response.status_code == HTTPStatus.OK

    user_projects_after = await async_test_client.get("/virtual-labs/projects")
    count_after_deleting = user_projects_after.json()["data"]["total"]
    assert count_after_deleting < count_before_deleting

    project_ids = [
        project["id"] for project in user_projects_after.json()["data"]["results"]
    ]
    assert project_1_id not in project_ids
    assert project_2_id in project_ids
