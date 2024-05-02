import asyncio
from typing import Any, AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import (
    cleanup_resources,
    create_mock_lab,
    create_mock_lab_with_project,
    get_headers,
)

headers_for_test_user = get_headers()


async def delete_lab(client: AsyncClient, lab_id: str) -> None:
    response = await client.delete(
        f"/virtual-labs/{lab_id}", headers=headers_for_test_user
    )
    assert response.status_code == 200


@pytest_asyncio.fixture
async def multiple_mock_labs(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, list[Any]], None]:
    labs = await asyncio.gather(
        create_mock_lab(async_test_client),
        create_mock_lab_with_project(async_test_client),
        create_mock_lab(async_test_client),
    )
    all_labs = [
        labs[0].json()["data"]["virtual_lab"],
        labs[1][0],
        labs[2].json()["data"]["virtual_lab"],
    ]
    yield async_test_client, all_labs

    await cleanup_resources(client=async_test_client, lab_id=all_labs[0]["id"])
    await cleanup_resources(client=async_test_client, lab_id=all_labs[1]["id"])
    await cleanup_resources(client=async_test_client, lab_id=all_labs[2]["id"])


@pytest.mark.asyncio
async def test_paginated_labs(
    multiple_mock_labs: tuple[AsyncClient, list[Any]],
) -> None:
    client, expected_labs = multiple_mock_labs

    response = await client.get(
        "/virtual-labs?page=1&size=5", headers=headers_for_test_user
    )

    assert response.status_code == 200

    response_data = response.json()["data"]
    actual_labs = response_data["results"]

    assert response_data["total"] >= len(expected_labs)
    assert response_data["page_size"] <= 5
    assert response_data["page_size"] >= len(expected_labs)
    assert response_data["page"] == 1
    assert len(response_data["results"]) >= 1
    assert len(response_data["results"]) == response_data["page_size"]

    for expected_lab in expected_labs:
        assert expected_lab in actual_labs
