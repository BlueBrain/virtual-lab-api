from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response
from requests import get

from virtual_labs.infrastructure.settings import settings
from virtual_labs.repositories.group_repo import GroupQueryRepository
from virtual_labs.tests.utils import get_client_headers


def test_vlm_project_creation(
    mock_create_project: tuple[Response, dict[str, str]],
) -> None:
    (response, headers) = mock_create_project

    assert response.status_code == 200
    project_id = response.json()["data"]["project"]["id"]
    virtual_lab_id = response.json()["data"]["virtual_lab_id"]
    admin_group_name = f"proj/{virtual_lab_id}/{project_id}/admin"
    member_group_name = f"proj/{virtual_lab_id}/{project_id}/member"

    group_repo = GroupQueryRepository()

    admin_group = group_repo.retrieve_group_by_name(name=admin_group_name)
    member_group = group_repo.retrieve_group_by_name(name=member_group_name)

    # Test Kc group creation
    assert admin_group is not None
    assert member_group is not None

    # Test Nexus project creation
    nexus_project = get(
        f"{settings.NEXUS_DELTA_URI}/projects/{virtual_lab_id}/{str(project_id)}",
        headers=get_client_headers(),
    )

    assert nexus_project.status_code == 200


@pytest_asyncio.fixture
async def mock_create_project_with_users(
    async_test_client: AsyncClient,
    mock_lab_create: tuple[Response, dict[str, str]],
) -> AsyncGenerator[Response, None]:
    client = async_test_client
    vl_response, headers = mock_lab_create
    virtual_lab_id = vl_response.json()["data"]["virtual_lab"]["id"]

    payload = {
        "name": f"Test Project {uuid4()}",
        "description": "Test Project",
        "include_members": [{"email": "test-1@test.com", "role": "admin"}],
    }
    response = await client.post(
        f"/virtual-labs/{virtual_lab_id}/projects",
        json=payload,
    )
    yield response


@pytest.mark.asyncio
async def test_vlm_project_with_members_creation(
    mock_create_project_with_users: Response,
) -> None:
    response = mock_create_project_with_users

    assert response.status_code == 200
    failed_invites = response.json()["data"]["failed_invites"]
    assert failed_invites == []
