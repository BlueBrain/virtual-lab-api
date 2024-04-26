from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import AsyncGenerator, cast
from uuid import UUID, uuid4

from httpx import AsyncClient, Response
from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.infrastructure.db.config import session_pool
from virtual_labs.infrastructure.db.models import (
    Project,
    ProjectInvite,
    ProjectStar,
    VirtualLab,
    VirtualLabInvite,
)
from virtual_labs.infrastructure.kc.auth import get_client_token
from virtual_labs.infrastructure.kc.config import kc_auth
from virtual_labs.repositories.group_repo import GroupMutationRepository

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


def get_client_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Authorization": f"bearer {get_client_token()}",
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


async def cleanup_resources(client: AsyncClient, lab_id: str) -> None:
    """Performs cleanup of following resources for lab_id:
    1. Deprecates underlying nexus org/project by calling the DELETE endpoints
    2. Deletes lab/project row along with lab_invite, project_invite, project_star rows from the DB
    3. Deletes admin and member groups from keycloak
    """
    project_ids = []
    async with session_context_factory() as session:
        stmt = select(Project.id).filter(Project.virtual_lab_id == UUID(lab_id))
        all = (await session.execute(statement=stmt)).scalars().all()
        project_ids = [str(project_id) for project_id in all]

    # 1. Call DELETE endpoints (which will deprecate nexus resources)
    for project_id in project_ids:
        try:
            project_delete_response = await client.delete(
                f"/virtual-labs/{lab_id}/projects/{project_id}", headers=get_headers()
            )
        except Exception:
            assert (
                project_delete_response.status_code == HTTPStatus.BAD_REQUEST
            )  # TODO: The response code for deleting already deleted lab and project should be the same.
    try:
        lab_delete_response = await client.delete(
            f"/virtual-labs/{lab_id}", headers=get_headers()
        )
    except Exception:
        assert lab_delete_response.status_code == HTTPStatus.NOT_FOUND

    # 2. Delete database rows
    project_group_ids: list[tuple[str, str]] = []
    async with session_context_factory() as session:
        for project_id in project_ids:
            await session.execute(
                statement=delete(ProjectInvite).where(
                    ProjectInvite.project_id == project_id
                )
            )

            await session.execute(
                statement=delete(ProjectStar).where(
                    ProjectStar.project_id == project_id
                )
            )

            logger.debug(f"Deleting project {project_id}")
            project_data = (
                await session.execute(
                    statement=delete(Project)
                    .where(Project.id == project_id)
                    .returning(Project.admin_group_id, Project.member_group_id)
                )
            ).first()

            if project_data is not None:
                project_group_ids.append(project_data.tuple())

        await session.execute(
            statement=delete(VirtualLabInvite).where(
                VirtualLabInvite.virtual_lab_id == lab_id
            )
        )

        lab_data = (
            await session.execute(
                statement=delete(VirtualLab)
                .where(VirtualLab.id == lab_id)
                .returning(VirtualLab.admin_group_id, VirtualLab.member_group_id)
            )
        ).one()
        await session.commit()

    # 3. Delete KC groups
    group_repo = GroupMutationRepository()
    for project_group_id in project_group_ids:
        group_repo.delete_group(group_id=project_group_id[0])
        group_repo.delete_group(group_id=project_group_id[1])
    group_repo.delete_group(group_id=lab_data[0])
    group_repo.delete_group(group_id=lab_data[1])
