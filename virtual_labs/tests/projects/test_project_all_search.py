from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient

from virtual_labs.tests.conftest import PROJECTS_PER_VL_COUNT, VL_COUNT


@pytest.mark.asyncio
async def test_project_all_search_success(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    _, headers = mock_create_vl_projects

    query = "Test Project"
    response = await client.get(
        f"/virtual-labs/projects/_search?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["total"] >= VL_COUNT * PROJECTS_PER_VL_COUNT


@pytest.mark.asyncio
async def test_project_all_search_no_results(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    _, headers = mock_create_vl_projects

    query = uuid4()
    response = await client.get(
        f"/virtual-labs/projects/_search?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["total"] == 0
