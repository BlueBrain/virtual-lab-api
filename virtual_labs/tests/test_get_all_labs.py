import asyncio
from typing import AsyncGenerator, cast
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import cleanup_resources, get_headers

headers_for_test_user = get_headers()


async def create_mock_lab(
    client: AsyncClient, with_project: bool = False
) -> tuple[str, str | None]:
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
    }
    headers = headers_for_test_user
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )
    lab_id = cast("str", response.json()["data"]["virtual_lab"]["id"])
    if with_project is False:
        return (lab_id, None)

    project_body = {
        "name": f"Test Project {uuid4()}",
        "description": "Test",
    }
    project_response = await client.post(
        f"/virtual-labs/{lab_id}/projects",
        json=project_body,
        headers=headers,
    )
    assert project_response.status_code == 200
    project_id = cast("str", project_response.json()["data"]["project"]["id"])
    return (lab_id, project_id)


async def delete_lab(client: AsyncClient, lab_id: str) -> None:
    response = await client.delete(
        f"/virtual-labs/{lab_id}", headers=headers_for_test_user
    )
    assert response.status_code == 200


@pytest_asyncio.fixture
async def multiple_mock_labs(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, list[tuple[str, str | None]]], None]:
    ids = await asyncio.gather(
        create_mock_lab(async_test_client),
        create_mock_lab(async_test_client, with_project=True),
        create_mock_lab(async_test_client),
    )
    all_ids = list(ids)
    yield async_test_client, all_ids

    await cleanup_resources(client=async_test_client, lab_id=all_ids[0][0])
    await cleanup_resources(
        client=async_test_client,
        lab_id=all_ids[1][0],
        project_ids=[all_ids[1][1]] if all_ids[1][1] is not None else [],
    )
    await cleanup_resources(client=async_test_client, lab_id=all_ids[2][0])


@pytest.mark.asyncio
async def test_paginated_labs(
    multiple_mock_labs: tuple[AsyncClient, list[tuple[str, str | None]]],
) -> None:
    client, mock_labs = multiple_mock_labs
    lab_id_with_project = mock_labs[1]

    response = await client.get(
        "/virtual-labs?page=1&size=5", headers=headers_for_test_user
    )

    assert response.status_code == 200

    data = response.json()["data"]
    assert data["total"] >= len(mock_labs)
    assert data["page_size"] <= 5
    assert data["page_size"] >= len(mock_labs)
    assert data["page"] == 1
    assert len(data["results"]) >= 1
    assert len(data["results"]) == data["page_size"]

    lab_with_project = [
        lab for lab in data["results"] if lab["id"] == lab_id_with_project[0]
    ]
    assert len(lab_with_project) == 1
    assert lab_with_project[0]["projects"][0]["id"] == lab_id_with_project[1]
    assert lab_with_project[0]["projects"][0]["starred"] is False
