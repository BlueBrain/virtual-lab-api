from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from requests import get

from virtual_labs.core.exceptions.email_error import EmailError
from virtual_labs.infrastructure.email.email_service import EmailDetails, send_invite
from virtual_labs.infrastructure.email.email_service import __name__ as EmailService
from virtual_labs.infrastructure.email.email_utils import (
    InviteOrigin,
    get_expiry_datetime_from_token,
    get_invite_details_from_token,
)

email_server_baseurl = "http://localhost:8025"


def get_invite_token_from_email_body(email_body: str) -> str:
    return email_body.split("?invite=")[2].split("</a>\n")[0]


def assert_time_is_in_future(d: datetime) -> None:
    """Asserts that given date time is atleast one day in future"""
    assert d > (datetime.now() + timedelta(1))


@pytest.mark.asyncio
async def test_email_invite_sent_for_virtual_lab() -> None:
    recipient_email = f"{str(uuid4())}@pytest.org"
    mock_invite_id = uuid4()
    mock_lab_name = "Mock Lab Name"
    invite_link = await send_invite(
        details=EmailDetails(
            recipient=recipient_email,
            invite_id=mock_invite_id,
            lab_id=uuid4(),
            lab_name=mock_lab_name,
        )
    )

    email_body = get(
        f"{email_server_baseurl}/view/latest.html?query=to:{recipient_email}"
    ).text

    encoded_invite_token = get_invite_token_from_email_body(email_body)
    decoded_token = get_invite_details_from_token(invite_token=encoded_invite_token)

    assert "?invite=" in invite_link
    assert "?invite=" in email_body
    assert mock_lab_name in email_body

    assert decoded_token["invite_id"] == str(mock_invite_id)
    assert decoded_token["origin"] == InviteOrigin.LAB.value
    assert_time_is_in_future(get_expiry_datetime_from_token(invite_token=decoded_token))


@pytest.mark.asyncio
async def test_email_invite_sent_for_project() -> None:
    recipient_email = f"{str(uuid4())}@pytest.org"
    mock_invite_id = uuid4()
    mock_lab_name = "Mock Lab Name"
    mock_project_name = "Mock Project Name"

    invite_link = await send_invite(
        details=EmailDetails(
            recipient=recipient_email,
            invite_id=mock_invite_id,
            lab_id=uuid4(),
            lab_name=mock_lab_name,
            project_id=uuid4(),
            project_name=mock_project_name,
        )
    )

    email_body = get(
        f"{email_server_baseurl}/view/latest.html?query=to:{recipient_email}"
    ).text

    encoded_invite_token = get_invite_token_from_email_body(email_body)
    decoded_token = get_invite_details_from_token(invite_token=encoded_invite_token)

    assert "?invite=" in invite_link
    assert "?invite=" in email_body
    assert mock_lab_name in email_body
    assert mock_project_name in email_body

    assert decoded_token["invite_id"] == str(mock_invite_id)
    assert decoded_token["origin"] == InviteOrigin.PROJECT.value
    assert_time_is_in_future(get_expiry_datetime_from_token(invite_token=decoded_token))


@pytest.mark.asyncio
async def test_throws_email_error_if_email_could_not_be_sent() -> None:
    with patch(
        f"{EmailService}.FastMail.send_message",
        side_effect=Exception("I am going to blow up for no reason"),
        new_callable=AsyncMock,
    ):
        try:
            invite_id = uuid4()
            await send_invite(
                details=EmailDetails(
                    recipient="mock@mock.com",
                    invite_id=invite_id,
                    lab_id=uuid4(),
                    lab_name="mock",
                    project_id=uuid4(),
                    project_name="mock",
                )
            )
        except EmailError as error:
            assert (
                error.message
                == f"Invite ID {invite_id} could not be emailed to user mock@mock.com"
            )
            assert error.detail == "I am going to blow up for no reason"