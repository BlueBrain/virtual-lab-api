from uuid import UUID

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_project_existence_success(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    vl_projects, headers = mock_create_vl_projects

    query = "existed project 0"
    vl = vl_projects[0]
    vl_id = next(iter(vl))
    response = await client.get(
        f"/virtual-labs/{vl_id}/projects/_check?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["exist"] is True


@pytest.mark.asyncio
async def test_project_existence_insensitive_success(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    vl_projects, headers = mock_create_vl_projects

    query = "EXisted prOjecT 0"
    vl = vl_projects[0]
    vl_id = next(iter(vl))
    response = await client.get(
        f"/virtual-labs/{vl_id}/projects/_check?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["exist"] is True


@pytest.mark.asyncio
async def test_project_existence_with_spaces(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    vl_projects, headers = mock_create_vl_projects

    query = "  existed project 0   "
    vl = vl_projects[0]
    vl_id = next(iter(vl))
    response = await client.get(
        f"/virtual-labs/{vl_id}/projects/_check?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["exist"] is True


@pytest.mark.asyncio
async def test_project_not_found(
    async_test_client: AsyncClient,
    mock_create_vl_projects: tuple[list[dict[UUID, list[UUID]]], dict[str, str]],
) -> None:
    client = async_test_client
    vl_projects, headers = mock_create_vl_projects

    query = "existed project 5"
    vl = vl_projects[0]
    vl_id = next(iter(vl))
    response = await client.get(
        f"/virtual-labs/{vl_id}/projects/_check?q={query}",
        headers=headers,
    )

    details = response.json()

    assert response.status_code == 200
    assert details["data"]["exist"] is False
