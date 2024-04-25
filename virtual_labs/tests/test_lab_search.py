from typing import Any, AsyncGenerator, cast
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.tests.utils import cleanup_resources, get_headers


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, str, str, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Search Test Lab {uuid4()}",
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
    lab_name = response.json()["data"]["virtual_lab"]["name"]
    lab_id = response.json()["data"]["virtual_lab"]["id"]

    yield client, lab_name, lab_id, headers

    await cleanup_resources(client=client, lab_id=lab_id)


@pytest.mark.asyncio
async def test_searching_by_partial_lab_name(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_name, lab_id, headers = mock_lab_create
    query = "search test"

    response = await client.get(f"/virtual-labs/_search?q={query}", headers=headers)
    assert response.status_code == 200
    matching_labs = cast(list[Any], response.json()["data"]["virtual_labs"])
    assert len(matching_labs) >= 1

    for lab in matching_labs:
        assert query in str(lab["name"]).lower()
        if lab["id"] == lab_id:
            assert lab["name"] == lab_name


@pytest.mark.asyncio
async def test_check_lab_exists(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_name, lab_id, headers = mock_lab_create

    response = await client.get(f"/virtual-labs/_check?q={lab_name}", headers=headers)
    assert response.status_code == 200
    assert (
        response.json()["message"] == f"Virtual lab with name {lab_name} already exists"
    )
    assert response.json()["data"]["exists"] is True


@pytest.mark.asyncio
async def test_check_lab_does_not_exist(
    async_test_client: AsyncClient,
) -> None:
    non_existing_lab_name = str(uuid4())
    response = await async_test_client.get(
        f"/virtual-labs/_check?q={non_existing_lab_name}", headers=get_headers()
    )
    assert response.status_code == 200
    assert (
        response.json()["message"]
        == f"No virtual lab with name {non_existing_lab_name} was found"
    )
    assert response.json()["data"]["exists"] is False


@pytest.mark.asyncio
async def test_search_labs_only_include_users_lab(
    mock_lab_create: tuple[AsyncClient, str, str, dict[str, str]],
) -> None:
    client, lab_name, lab_id, headers = mock_lab_create
    query = "Search Test"

    test_user_1_response = await client.get(
        f"/virtual-labs/_search?q={query}", headers=headers
    )
    test_user_1_labs = cast(
        list[Any], test_user_1_response.json()["data"]["virtual_labs"]
    )
    assert len(test_user_1_labs) >= 1

    test_user_2_response = await client.get(
        f"/virtual-labs/_search?q={query}", headers=get_headers("test-2")
    )
    test_user_2_labs = cast(
        list[Any], test_user_2_response.json()["data"]["virtual_labs"]
    )
    assert len(test_user_2_labs) == 0
