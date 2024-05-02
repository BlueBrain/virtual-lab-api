from typing import Any, AsyncGenerator, cast
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response
from requests import get

from virtual_labs.infrastructure.settings import settings
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.tests.utils import cleanup_resources, get_client_headers, get_headers


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[Response, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
        "entity": "EPFL, Switzerland",
    }
    headers = get_headers()
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )

    yield response, headers

    lab_id = response.json()["data"]["virtual_lab"]["id"]
    await cleanup_resources(client=client, lab_id=lab_id)


@pytest_asyncio.fixture
async def mock_lab_create_with_users(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[dict[str, Any], Response, AsyncClient, dict[str, str]], None]:
    client = async_test_client
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
        "entity": "EPFL, Switzerland",
        "include_members": [
            {"email": "test-1@test.com", "role": "admin"},
            {"email": "test-2@test.com", "role": "member"},
        ],
    }
    headers = get_headers()
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )

    yield body, response, client, headers

    lab_id = response.json()["data"]["virtual_lab"]["id"]
    await cleanup_resources(client=client, lab_id=lab_id)


def assert_users_in_lab(response: Response) -> None:
    users = cast(list[dict[str, Any]], response.json()["data"]["users"])
    actual_users = [
        {
            "username": user.get("username"),
            "invite_accepted": user.get("invite_accepted"),
            "role": user.get("role"),
        }
        for user in users
    ]
    expected_users = [
        {
            "username": "test",
            "invite_accepted": True,
            "role": "admin",
        },
        {
            "username": "test-1",
            "invite_accepted": False,
            "role": "admin",
        },
        {
            "username": "test-2",
            "invite_accepted": False,
            "role": "member",
        },
    ]
    assert actual_users == expected_users


@pytest.mark.asyncio
async def test_virtual_lab_created(
    mock_lab_create: tuple[Response, dict[str, str]],
) -> None:
    response, headers = mock_lab_create
    # Test that the virtual lab was created
    assert response.status_code == 200
    data = response.json()["data"]
    lab_id = data["virtual_lab"]["id"]

    assert data.get("successful_invites") == []
    assert data.get("failed_invites") == []

    group_repo = GroupQueryRepository()
    group_id = f"vlab/{lab_id}/admin"

    # Test that the keycloak admin group was created
    group = group_repo.retrieve_group_by_name(name=group_id)
    assert group is not None

    nexus_org_request = get(
        f"{settings.NEXUS_DELTA_URI}/orgs/{str(lab_id)}", headers=get_client_headers()
    )
    # Test that the nexus organization was created
    assert nexus_org_request.status_code == 200


@pytest.mark.asyncio
async def test_virtual_lab_created_with_users(
    mock_lab_create_with_users: tuple[
        dict[str, Any], Response, AsyncClient, dict[str, str]
    ],
) -> None:
    request, response, client, headers = mock_lab_create_with_users
    assert response.status_code == 200
    actual_response = response.json()["data"]
    lab_id = actual_response["virtual_lab"]["id"]

    expected_response = {
        "virtual_lab": {
            "name": request.get("name"),
            "description": "Test",
            "reference_email": "user@test.org",
            "budget": 10.0,
            "id": lab_id,
            "plan_id": 1,
            "entity": "EPFL, Switzerland",
            "nexus_organization_id": f"http://delta:8080/v1/orgs/{lab_id}",
            "deleted": False,
            "created_at": actual_response["virtual_lab"]["created_at"],
            "deleted_at": None,
            "updated_at": None,
        },
        "successful_invites": [
            {"email": "test-1@test.com", "role": "admin"},
            {"email": "test-2@test.com", "role": "member"},
        ],
        "failed_invites": [],
    }

    assert actual_response == expected_response

    lab_response = await client.get(f"/virtual-labs/{lab_id}/users", headers=headers)
    assert_users_in_lab(lab_response)
