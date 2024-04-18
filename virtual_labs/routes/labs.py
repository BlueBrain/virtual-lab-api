from fastapi import APIRouter, Depends
from pydantic import UUID4
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.authorization import (
    verify_user_authenticated,
    verify_vlab_read,
    verify_vlab_write,
)
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.common import PageParams, PaginatedResultsResponse
from virtual_labs.domain.invite import AddUser
from virtual_labs.domain.labs import (
    CreateLabOut,
    InviteSent,
    Lab,
    LabByIdOut,
    LabResponse,
    SearchLabResponse,
    VirtualLabCreate,
    VirtualLabDomain,
    VirtualLabUpdate,
    VirtualLabUser,
    VirtualLabUsers,
    VirtualLabWithProject,
)
from virtual_labs.infrastructure.db.config import default_session_factory
from virtual_labs.infrastructure.kc.auth import verify_jwt
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.shared.utils.auth import get_user_id_from_auth
from virtual_labs.usecases import labs as usecases
from virtual_labs.usecases.labs.check_virtual_lab_name_exists import LabExists

PaginatedLabs = LabResponse[PaginatedResultsResponse[VirtualLabWithProject]]
router = APIRouter(prefix="/virtual-labs", tags=["Virtual Labs Endpoints"])


@router.get("", response_model=PaginatedLabs)
@verify_user_authenticated
async def get_paginated_virtual_labs_for_user(
    page: int = 1,
    size: int = 50,
    db: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> PaginatedLabs:
    return LabResponse(
        message="Paginated virtual labs for user",
        data=await usecases.paginated_labs_for_user(
            db,
            page_params=PageParams(page=page, size=size),
            user_id=get_user_id_from_auth(auth),
        ),
    )


@router.get("/_check", response_model=LabResponse[LabExists])
async def check_if_virtual_lab_name_exists(
    q: str, db: AsyncSession = Depends(default_session_factory)
) -> LabResponse[LabExists]:
    response = await usecases.check_virtual_lab_name_exists(db, q)
    return LabResponse[LabExists](
        message=f"Virtual lab with name {q} already exists"
        if response["exists"] > 0
        else f"No virtual lab with name {q} was found",
        data=response,
    )


@router.get(
    "/_search",
    response_model=LabResponse[SearchLabResponse],
    description="Search virtual labs that user is a member of, by lab name",
)
async def search_virtual_lab_by_name(
    q: str,
    db: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[SearchLabResponse]:
    return LabResponse[SearchLabResponse](
        message=f"All labs with names matching {q} for user",
        data=await usecases.search_virtual_labs_by_name(
            q, db, get_user_id_from_auth(auth)
        ),
    )


@router.get(
    "/{virtual_lab_id}",
    response_model=LabResponse[LabByIdOut],
    summary="Get non deleted virtual lab by id",
)
@verify_vlab_read
async def get_virtual_lab(
    virtual_lab_id: UUID4,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[LabByIdOut]:
    lab_response = await usecases.get_virtual_lab(
        session, virtual_lab_id, user_id=get_user_id_from_auth(auth)
    )
    return LabResponse[LabByIdOut](
        message="Virtual lab resource for id {}".format(virtual_lab_id),
        data=lab_response,
    )


@router.get("/{virtual_lab_id}/users", response_model=LabResponse[VirtualLabUsers])
@verify_vlab_read
async def get_virtual_lab_users(
    virtual_lab_id: UUID4,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[VirtualLabUsers]:
    return LabResponse[VirtualLabUsers](
        message="Users for virtual lab",
        data=await usecases.get_virtual_lab_users(session, virtual_lab_id),
    )


@router.post(
    "", response_model=LabResponse[CreateLabOut], response_model_exclude_none=True
)
async def create_virtual_lab(
    lab: VirtualLabCreate,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[CreateLabOut]:
    result = await usecases.create_virtual_lab(session, lab, auth)
    return LabResponse[CreateLabOut](message="Newly created virtual lab", data=result)


@router.patch("/{virtual_lab_id}", response_model=LabResponse[LabByIdOut])
@verify_vlab_write
async def update_virtual_lab(
    virtual_lab_id: UUID4,
    lab: VirtualLabUpdate,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[LabByIdOut]:
    udpated_lab = await usecases.update_virtual_lab(
        session, virtual_lab_id, lab=lab, user_id=get_user_id_from_auth(auth)
    )
    return LabResponse[LabByIdOut](message="Updated virtual lab", data=udpated_lab)


@router.post(
    "/{virtual_lab_id}/invites",
    summary="Invite user to lab by email",
    response_model=LabResponse[InviteSent],
)
@verify_vlab_write
async def invite_user_to_virtual_lab(
    virtual_lab_id: UUID4,
    invite_details: AddUser,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[InviteSent]:
    invite_id = await usecases.invite_user_to_lab(
        virtual_lab_id,
        inviter_id=get_user_id_from_auth(auth),
        invite_details=invite_details,
        db=session,
    )
    return LabResponse[InviteSent](
        message="Invite sent to user", data=InviteSent(invite_id=invite_id)
    )


@router.patch(
    "/{virtual_lab_id}/users/{user_id}",
    response_model=LabResponse[VirtualLabUser],
)
@verify_vlab_write
async def change_user_role_for_lab(
    virtual_lab_id: UUID4,
    user_id: UUID4,
    new_role: UserRoleEnum,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[VirtualLabUser]:
    return await usecases.change_user_role_for_lab(
        virtual_lab_id,
        user_id=user_id,
        new_role=new_role,
        db=session,
    )


@router.delete(
    "/{virtual_lab_id}/users/{user_id}",
    response_model=LabResponse[None],
)
@verify_vlab_write
async def remove_user_from_virtual_lab(
    virtual_lab_id: UUID4,
    user_id: UUID4,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[None]:
    await usecases.remove_user_from_lab(virtual_lab_id, user_id=user_id, db=session)
    return LabResponse[None](message="User removed from virtual lab", data=None)


@router.delete("/{virtual_lab_id}", response_model=LabResponse[Lab])
@verify_vlab_write
async def delete_virtual_lab(
    virtual_lab_id: UUID4,
    session: AsyncSession = Depends(default_session_factory),
    auth: tuple[AuthUser, str] = Depends(verify_jwt),
) -> LabResponse[Lab]:
    deleted_lab = Lab(
        virtual_lab=VirtualLabDomain.model_validate(
            await usecases.delete_virtual_lab(session, virtual_lab_id, auth=auth)
        )
    )
    return LabResponse[Lab](message="Deleted virtual lab", data=deleted_lab)
