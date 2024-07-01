from typing import Any, AsyncGenerator, cast
from uuid import UUID, uuid4

import pytest_asyncio
from httpx import AsyncClient, Response
from pytest import FixtureRequest
from sqlalchemy import update

from virtual_labs.infrastructure.db.models import Project, VirtualLab
from virtual_labs.shared.utils.billing import amount_to_float
from virtual_labs.tests.utils import (
    cleanup_resources,
    create_mock_lab,
    get_headers,
    session_context_factory,
)

VL_COUNT = 2
PROJECTS_PER_VL_COUNT = 2
VL_BUDGET_AMOUNT = 100050  # in cent (1000.50$)
VL_PROJECTS_COUNT = 3


@pytest_asyncio.fixture
async def mock_create_project(
    request: FixtureRequest,
    async_test_client: AsyncClient,
    mock_lab_create: tuple[Response, dict[str, str]],
) -> AsyncGenerator[tuple[Response, dict[str, str], dict[str, str]], None]:
    param_name = getattr(request, "param", {"name": f"Test Project {uuid4()}"}).get(
        "name"
    )
    param_desc = getattr(
        request, "param", {"description": "Test Project description "}
    ).get("description")

    client = async_test_client
    vl_response, headers = mock_lab_create
    virtual_lab_id = vl_response.json()["data"]["virtual_lab"]["id"]

    payload = {
        "name": param_name,
        "description": param_desc,
    }
    response = await client.post(
        f"/virtual-labs/{virtual_lab_id}/projects",
        json=payload,
    )

    yield response, headers, cast(dict[str, str], payload)


@pytest_asyncio.fixture
async def mock_create_projects(
    async_test_client: AsyncClient,
    mock_lab_create: tuple[Response, dict[str, str]],
) -> AsyncGenerator[tuple[UUID, float, list[UUID], dict[str, str]], None]:
    client = async_test_client
    vl_response, headers = mock_lab_create
    virtual_lab_id = vl_response.json()["data"]["virtual_lab"]["id"]

    # mock the budget for virtual lab (instead using the stripe webhook)
    async with session_context_factory() as session:
        virtual_lab_budget = (
            await session.execute(
                statement=update(VirtualLab)
                .where(VirtualLab.id == UUID(virtual_lab_id))
                .values(budget_amount=VL_BUDGET_AMOUNT)
                .returning(VirtualLab.budget_amount)
            )
        ).scalar_one()
        await session.commit()

    projects: list[UUID] = []

    for i in range(VL_PROJECTS_COUNT):
        payload = {
            "name": f"Test Project {i} {uuid4()}",
            "description": f"Test Project description {i}",
        }

        response = await client.post(
            f"/virtual-labs/{virtual_lab_id}/projects",
            json=payload,
        )
        project_id = response.json()["data"]["project"]["id"]
        async with session_context_factory() as session:
            await session.execute(
                statement=update(Project)
                .where(Project.id == UUID(project_id))
                .values(budget_amount=int(VL_BUDGET_AMOUNT / VL_PROJECTS_COUNT))
                .returning(Project.budget_amount)
            )
            await session.commit()

        projects.append(project_id)

    yield (
        cast(UUID, virtual_lab_id),
        amount_to_float(virtual_lab_budget),
        projects,
        headers,
    )


@pytest_asyncio.fixture
async def mock_create_vl_projects(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[list[dict[str, list[UUID]]], dict[str, str]], None]:
    client = async_test_client
    headers = get_headers()

    vl_projects: list[dict[str, list[UUID]]] = []

    for i in range(VL_COUNT):
        virtual_lab_resp = await create_mock_lab(async_test_client)
        virtual_lab_id = virtual_lab_resp.json()["data"]["virtual_lab"]["id"]
        projects: list[UUID] = []
        payload = {
            "name": f"existed project {i}",
            "description": f"existed project description {i}",
        }
        response = await client.post(
            f"/virtual-labs/{virtual_lab_id}/projects",
            json=payload,
        )
        project_id = response.json()["data"]["project"]["id"]
        projects.append(project_id)

        for j in range(PROJECTS_PER_VL_COUNT):
            payload = {
                "name": f"Test Project {j} {uuid4()}",
                "description": f"Test Project description {j}",
            }

            response = await client.post(
                f"/virtual-labs/{virtual_lab_id}/projects",
                json=payload,
            )
            project_id = response.json()["data"]["project"]["id"]
            projects.append(project_id)

        vl_projects.append({virtual_lab_id: projects})

    yield vl_projects, headers

    for elt in vl_projects:
        for vl_id, projects in elt.items():
            await cleanup_resources(client, vl_id)


@pytest_asyncio.fixture
async def mock_create_full_vl_projects(
    async_test_client: AsyncClient,
) -> AsyncGenerator[tuple[list[dict[str, Any]], dict[str, str]], None]:
    client = async_test_client
    headers = get_headers()

    virtual_lab_resp = await create_mock_lab(async_test_client)
    virtual_lab_id = virtual_lab_resp.json()["data"]["virtual_lab"]["id"]
    projects: list[dict[str, Any]] = []

    for i in range(PROJECTS_PER_VL_COUNT):
        payload = {
            "name": f"existed project {i}",
            "description": f"existed project description {i}",
        }
        response = await client.post(
            f"/virtual-labs/{virtual_lab_id}/projects",
            json=payload,
        )
        projects.append(response.json()["data"]["project"])

    yield projects, headers

    await cleanup_resources(client, virtual_lab_id)
