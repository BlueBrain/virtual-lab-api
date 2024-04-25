from http import HTTPStatus
from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import cleanup_resources, get_headers

member_user = "test"
non_member_user = "test-2"


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, str, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Search Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
    }
    headers = get_headers(member_user)
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
async def test_non_member_user_cannot_get_lab_by_id(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.get(
        f"/virtual-labs/{lab_id}", headers=get_headers(non_member_user)
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_non_member_user_cannot_get_lab_users(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.get(
        f"/virtual-labs/{lab_id}/users", headers=get_headers(non_member_user)
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_non_member_user_cannot_update_lab(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.patch(
        f"/virtual-labs/{lab_id}",
        headers=get_headers(non_member_user),
        json={"name": "This request should fail"},
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_non_member_user_cannot_delete_lab(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.delete(
        f"/virtual-labs/{lab_id}",
        headers=get_headers(non_member_user),
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_non_member_user_cannot_delete_lab_users(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.delete(
        f"/virtual-labs/{lab_id}/users/{uuid4()}",
        headers=get_headers(non_member_user),
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_non_member_user_cannot_change_member_role(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, member_headers = mock_lab_create
    response = await client.patch(
        f"/virtual-labs/{lab_id}/users/{uuid4()}?new_role=admin",
        headers=get_headers(non_member_user),
    )

    assert response.status_code == HTTPStatus.FORBIDDEN
