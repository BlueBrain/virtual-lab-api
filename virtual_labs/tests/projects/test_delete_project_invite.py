from http import HTTPStatus
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response

from virtual_labs.tests.test_accept_lab_invite import get_invite_token_from_email
from virtual_labs.tests.utils import get_headers


@pytest_asyncio.fixture
async def mock_project_invite(
    async_test_client: AsyncClient,
    mock_create_project: tuple[Response, dict[str, str], dict[str, str]],
) -> AsyncGenerator[tuple[AsyncClient, str, str, str, str], None]:
    client = async_test_client
    response, headers, _ = mock_create_project
    lab_id = response.json()["data"]["virtual_lab_id"]
    project_id = response.json()["data"]["project"]["id"]
    invitee_email = "test-1@test.com"
    invitee_username = "test-1"
    invite_payload = {"email": f"{invitee_email}", "role": "member"}

    response = await client.post(
        f"/virtual-labs/{lab_id}/projects/{project_id}/invites",
        json=invite_payload,
        headers=headers,
    )
    assert response.status_code == HTTPStatus.OK

    yield client, lab_id, project_id, invitee_email, invitee_username


@pytest.mark.asyncio
async def test_deleted_invite_cannot_be_accepted(
    mock_project_invite: tuple[AsyncClient, str, str, str, str],
) -> None:
    client, lab_id, project_id, invitee_email, invitee_username = mock_project_invite
    delete_invite_response = await client.delete(
        f"/virtual-labs/{lab_id}/projects/{project_id}/invites?email={invitee_email}&role=member",
        headers=get_headers(),
    )
    assert delete_invite_response.status_code == HTTPStatus.OK

    invite_token = get_invite_token_from_email(invitee_email)
    accept_invite_response = await client.post(
        f"/invites?token={invite_token}", headers=get_headers(username=invitee_username)
    )
    assert accept_invite_response.status_code == HTTPStatus.NOT_FOUND
    assert (
        accept_invite_response.json()["message"] == "No invite was found for this link"
    )
