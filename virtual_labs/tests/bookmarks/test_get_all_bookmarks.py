from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient

from virtual_labs.domain.bookmark import BookmarkCategory, BookmarkIn
from virtual_labs.infrastructure.db.models import Bookmark
from virtual_labs.tests.utils import session_context_factory

mock_bookmarks: list[BookmarkIn] = [
    BookmarkIn(
        resource_id="resource-1", category=BookmarkCategory.ExperimentalNeuronMorphology
    ),
    BookmarkIn(
        resource_id="resource-2", category=BookmarkCategory.ExperimentalNeuronMorphology
    ),
    BookmarkIn(
        resource_id="resource-3",
        category=BookmarkCategory.ExperimentalElectroPhysiology,
    ),
    BookmarkIn(
        resource_id="resource-4", category=BookmarkCategory.ExperimentsBoutonDensity
    ),
    BookmarkIn(
        resource_id="resource-5", category=BookmarkCategory.ExperimentsBoutonDensity
    ),
    BookmarkIn(
        resource_id="resource-6", category=BookmarkCategory.ExperimentalNeuronDensity
    ),
    BookmarkIn(
        resource_id="resource-7", category=BookmarkCategory.ExperimentalNeuronDensity
    ),
    BookmarkIn(
        resource_id="resource-8", category=BookmarkCategory.ExperimentalNeuronMorphology
    ),
]


@pytest_asyncio.fixture
async def add_bookmarks_to_project(
    mock_create_project: tuple[str, str, dict[str, str], AsyncClient],
) -> AsyncGenerator[tuple[str, str, dict[str, str], AsyncClient], None]:
    lab_id, project_id, headers, client = mock_create_project
    async with session_context_factory() as session:
        for bookmark in mock_bookmarks:
            session.add(
                Bookmark(
                    resource_id=bookmark.resource_id,
                    category=bookmark.category,
                    project_id=project_id,
                )
            )

        await session.commit()
    yield lab_id, project_id, headers, client


@pytest.mark.asyncio
async def test_user_can_get_all_project_bookmarks_by_type(
    add_bookmarks_to_project: tuple[str, str, dict[str, str], AsyncClient],
) -> None:
    lab_id, project_id, headers, client = add_bookmarks_to_project

    response = await client.get(
        f"/virtual-labs/{lab_id}/projects/{project_id}/bookmarks",
        headers=headers,
    )

    assert response.status_code == 200
    data = response.json()["data"]

    assert len(data[BookmarkCategory.ExperimentalNeuronMorphology.value]) == 3
    assert len(data[BookmarkCategory.ExperimentsBoutonDensity.value]) == 2
    assert len(data[BookmarkCategory.ExperimentalNeuronDensity.value]) == 2
    assert len(data[BookmarkCategory.ExperimentalElectroPhysiology.value]) == 1
    assert data.get(BookmarkCategory.ExperimentalSynapsePerConnection.value) is None
