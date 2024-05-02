from http import HTTPStatus
from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response
from requests import get

from virtual_labs.tests.utils import cleanup_resources, get_headers

email_server_baseurl = "http://localhost:8025"


@pytest_asyncio.fixture
async def mock_lab_create(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[AsyncClient, str, dict[str, str]], None]:
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
    assert response.status_code == 200
    lab_id = response.json()["data"]["virtual_lab"]["id"]
    yield client, lab_id, headers

    await cleanup_resources(client=client, lab_id=lab_id)


def assert_invite_response(response: Response) -> None:
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Invite sent to user"
    assert data["data"]["invite_id"] is not None


def assert_right_users_in_lab(response: Response) -> None:
    assert response.status_code == 200
    lab_users_response_data = response.json()
    lab_users = lab_users_response_data["data"]["users"]
    assert len(lab_users) == 2
    for user in lab_users:
        if user["username"] == "test":
            assert user["role"] == "admin"
            assert user["invite_accepted"] is True
        else:
            assert user["username"] == "test-2"
            assert user["role"] == "admin"
            assert user["invite_accepted"] is False


@pytest.mark.asyncio
async def test_invite_user_to_lab(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, headers = mock_lab_create

    invite = {"email": "test-2@test.com", "role": "admin"}
    invite_response = await client.post(
        f"/virtual-labs/{lab_id}/invites", headers=headers, json=invite
    )
    assert_invite_response(invite_response)

    lab_users_response = await client.get(
        f"/virtual-labs/{lab_id}/users", headers=headers
    )
    assert_right_users_in_lab(lab_users_response)


@pytest.mark.asyncio
async def test_existing_invite_is_updated_when_user_invited_again(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, headers = mock_lab_create
    recipient = f"test-{uuid4()}@test.com"
    invite = {"email": recipient, "role": "admin"}

    # Invited first time
    invite_response = await client.post(
        f"/virtual-labs/{lab_id}/invites", headers=headers, json=invite
    )
    first_invite_id = invite_response.json()["data"]["invite_id"]

    # Invited second time
    reinvitation_response = await client.post(
        f"/virtual-labs/{lab_id}/invites", headers=headers, json=invite
    )
    second_invite_id = reinvitation_response.json()["data"]["invite_id"]

    # Invite id is same
    assert first_invite_id == second_invite_id

    # 2 emails are sent
    emails_sent = get(f"{email_server_baseurl}/api/v1/search?query=to:{recipient}")
    assert len(emails_sent.json()["messages"]) == 2


@pytest.mark.asyncio
async def test_user_already_in_lab_cannot_be_reinvited(
    mock_lab_create: tuple[AsyncClient, str, dict[str, str]],
) -> None:
    client, lab_id, headers = mock_lab_create
    invite = {"email": "test@test.com", "role": "admin"}
    invite_response = await client.post(
        f"/virtual-labs/{lab_id}/invites", headers=headers, json=invite
    )
    assert invite_response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert (
        "User with email test@test.com is already in lab"
        in invite_response.json()["message"]
    )
