import pytest
from httpx import AsyncClient, Response


@pytest.mark.asyncio
async def test_update_project_star_status_to_starred(
    async_test_client: AsyncClient,
    mock_create_project: tuple[Response, dict[str, str], dict[str, str]],
) -> None:
    client = async_test_client
    (response, headers, _) = mock_create_project
    project_id = response.json()["data"]["project"]["id"]
    virtual_lab_id = response.json()["data"]["virtual_lab_id"]

    response = await client.patch(
        f"/virtual-labs/{virtual_lab_id}/projects/{project_id}/star-status",
        json={"value": True},
        headers=headers,
    )
    result = response.json()

    assert response.status_code == 200
    assert result["data"]["starred"] is True


@pytest.mark.asyncio
async def test_update_project_star_status_to_un_starred(
    async_test_client: AsyncClient,
    mock_create_project: tuple[Response, dict[str, str], dict[str, str]],
) -> None:
    client = async_test_client
    (response, headers, _) = mock_create_project
    project_id = response.json()["data"]["project"]["id"]
    virtual_lab_id = response.json()["data"]["virtual_lab_id"]

    await client.patch(
        f"/virtual-labs/{virtual_lab_id}/projects/{project_id}/star-status",
        json={"value": True},
        headers=headers,
    )

    response = await client.patch(
        f"/virtual-labs/{virtual_lab_id}/projects/{project_id}/star-status",
        json={"value": False},
        headers=headers,
    )
    result = response.json()

    assert response.status_code == 200
    assert result["data"]["starred"] is False
