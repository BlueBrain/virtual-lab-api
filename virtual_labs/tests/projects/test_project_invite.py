from http import HTTPStatus

import pytest
from httpx import AsyncClient, Response

from virtual_labs.tests.test_accept_lab_invite import get_invite_token_from_email
from virtual_labs.tests.utils import get_headers


@pytest.mark.asyncio
async def test_invite_user_to_project(
    async_test_client: AsyncClient,
    mock_create_project: tuple[Response, dict[str, str]],
) -> None:
    client = async_test_client
    response, headers = mock_create_project
    lab_id = response.json()["data"]["virtual_lab_id"]
    project_id = response.json()["data"]["project"]["id"]
    user_to_invite = "test-1"
    invite_payload = {"email": f"{user_to_invite}@test.com", "role": "admin"}

    # invite user
    response = await client.post(
        f"/virtual-labs/{lab_id}/projects/{project_id}/invites",
        json=invite_payload,
        headers=headers,
    )
    assert response.status_code == HTTPStatus.OK

    # accept invite
    invite_token = get_invite_token_from_email(f"{user_to_invite}@test.com")
    accept_invite_response = await client.post(
        f"/invites?token={invite_token}", headers=get_headers(username=user_to_invite)
    )
    assert accept_invite_response.status_code == HTTPStatus.OK
    lab_response = await client.get(
        f"/virtual-labs/{lab_id}", headers=get_headers(username=user_to_invite)
    )
    assert lab_response.status_code == HTTPStatus.OK
    project_response = await client.get(
        f"/virtual-labs/{lab_id}/projects/{project_id}",
        headers=get_headers(username=user_to_invite),
    )
    assert project_response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_user_already_in_project_cannot_be_reinvited(
    async_test_client: AsyncClient,
    mock_create_project: tuple[Response, dict[str, str]],
) -> None:
    client = async_test_client
    response, headers = mock_create_project
    lab_id = response.json()["data"]["virtual_lab_id"]
    project_id = response.json()["data"]["project"]["id"]
    user_to_invite = "test-1"
    invite_payload = {"email": f"{user_to_invite}@test.com", "role": "admin"}

    invite_user_response = await client.post(
        f"/virtual-labs/{lab_id}/projects/{project_id}/invites",
        json=invite_payload,
        headers=headers,
    )
    assert invite_user_response.status_code == HTTPStatus.OK

    invite_token = get_invite_token_from_email(f"{user_to_invite}@test.com")
    await client.post(
        f"/invites?token={invite_token}", headers=get_headers(username=user_to_invite)
    )

    reinvite_user_response = await client.post(
        f"/virtual-labs/{lab_id}/projects/{project_id}/invites",
        json=invite_payload,
        headers=headers,
    )
    assert reinvite_user_response.status_code == HTTPStatus.PRECONDITION_FAILED
