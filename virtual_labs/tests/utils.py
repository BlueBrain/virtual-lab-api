from contextlib import asynccontextmanager
from typing import AsyncGenerator, cast
from uuid import uuid4

from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.infrastructure.db.config import session_pool
from virtual_labs.infrastructure.kc.config import kc_auth

email_server_baseurl = "http://localhost:8025"


@asynccontextmanager
async def session_context_factory() -> AsyncGenerator[AsyncSession, None]:
    async with session_pool.session() as session:
        yield session


def auth(username: str = "test") -> str:
    token = kc_auth.token(username=username, password="test")
    return cast(str, token["access_token"])


def get_headers(username: str = "test") -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {auth(username)}",
    }


async def create_mock_lab(
    client: AsyncClient, owner_username: str = "test"
) -> Response:
    body = {
        "name": f"Test Lab {uuid4()}",
        "description": "Test",
        "reference_email": "user@test.org",
        "budget": 10,
        "plan_id": 1,
    }
    headers = get_headers(owner_username)
    response = await client.post(
        "/virtual-labs",
        json=body,
        headers=headers,
    )
    assert response.status_code == 200
    return response


def get_invite_token_from_email_body(email_body: str) -> str:
    return email_body.split("?token=")[2].split("</a>\n")[0]
