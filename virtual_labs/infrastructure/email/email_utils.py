from datetime import datetime, timedelta
from enum import Enum
from typing import TypedDict, cast

import jwt
from pydantic import UUID4

from virtual_labs.infrastructure.settings import settings

InviteToken = TypedDict(
    "InviteToken", {"invite_id": str, "expires_at": str, "origin": str}
)


class InviteOrigin(Enum):
    LAB = "Lab"
    PROJECT = "Project"


def generate_expiration_time() -> str:
    "Returns epoch timestamp for seven days from now as a str. Example: '1712131180000'"
    seven_days = datetime.now() + timedelta(settings.INVITE_EXPIRES_IN_DAYS)
    return seven_days.strftime("%s000")


def generate_encrypted_invite_token(invite_id: UUID4, origin: InviteOrigin) -> str:
    invite_data = {
        "invite_id": str(invite_id),
        "expires_at": generate_expiration_time(),
        "origin": origin.value,
    }
    return jwt.encode(invite_data, settings.INVITE_JWT_SECRET, algorithm="HS256")


# TODO: The links here might need updating depending on the actual lab/project details page where the user should be redirected to.
def generate_invite_link(invite_token: str) -> str:
    return f"{settings.INVITE_LINK_BASE}?invite={invite_token}"


def generate_invite_html(
    invite_link: str, lab_name: str, project_name: str | None
) -> str:
    if project_name is None:
        return f"""
            You have been invited to virtual lab {lab_name}. Please click on the link below to accept the invite:
            <a href="{invite_link}">{invite_link}</a>
        """
    else:
        return f"""
            You have been invited to project {project_name} within the {lab_name} virtual lab. Please click on the link below to accept the invite: <br />
            <a href="{invite_link}">{invite_link}</a>
        """


def get_invite_details_from_token(invite_token: str) -> InviteToken:
    decoded_token = jwt.decode(
        invite_token, settings.INVITE_JWT_SECRET, algorithms=["HS256"]
    )
    return cast(InviteToken, decoded_token)


def get_expiry_datetime_from_token(invite_token: InviteToken) -> datetime:
    expiry = float(invite_token["expires_at"])
    return datetime.fromtimestamp(expiry / 1000)