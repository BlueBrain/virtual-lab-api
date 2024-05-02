from typing import List

from pydantic import UUID4
from sqlalchemy import func, select, update
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, noload, subqueryload
from sqlalchemy.sql import and_, or_

from virtual_labs.core.types import PaginatedDbResult
from virtual_labs.domain import labs
from virtual_labs.domain.common import PageParams
from virtual_labs.infrastructure.db.models import Project, VirtualLab


class VirtualLabDbCreate(labs.VirtualLabCreate):
    id: UUID4
    owner_id: UUID4
    admin_group_id: str
    member_group_id: str
    nexus_organization_id: str


def get_all_virtual_lab_for_user(db: Session) -> List[VirtualLab]:
    return db.query(VirtualLab).filter(~VirtualLab.deleted).all()


async def get_paginated_virtual_labs(
    db: AsyncSession, page_params: PageParams, group_ids: list[str]
) -> PaginatedDbResult[list[VirtualLab]]:
    count_query = paginated_query = select(VirtualLab).where(
        and_(
            ~VirtualLab.deleted,
            or_(
                (VirtualLab.admin_group_id.in_(group_ids)),
                (VirtualLab.member_group_id.in_(group_ids)),
            ),
        )
    )
    count = await db.scalar(
        select(func.count()).select_from(count_query.options(noload("*")).subquery())
    )
    paginated_query = (
        select(VirtualLab)
        .options(
            subqueryload(VirtualLab.projects).subqueryload(Project.project_stars),
        )
        .where(
            and_(
                ~VirtualLab.deleted,
                or_(
                    (VirtualLab.admin_group_id.in_(group_ids)),
                    (VirtualLab.member_group_id.in_(group_ids)),
                ),
            )
        )
    )

    result = (
        (
            await db.execute(
                statement=paginated_query.order_by(
                    VirtualLab.created_at.desc(), VirtualLab.updated_at.desc()
                )
                .offset((page_params.page - 1) * page_params.size)
                .limit(page_params.size)
            )
        )
        .unique()
        .scalars()
        .all()
    )

    return PaginatedDbResult(
        count=count or 0,
        rows=list(result),
    )


async def get_undeleted_virtual_lab(db: AsyncSession, lab_id: UUID4) -> VirtualLab:
    """Returns non-deleted virtual lab by id. Raises an exception if the lab by id is not found or if it is deleted."""
    query = select(VirtualLab).where(VirtualLab.id == lab_id, ~VirtualLab.deleted)
    return (await db.execute(statement=query)).unique().scalar_one()


async def get_virtual_lab_soft(db: AsyncSession, lab_id: UUID4) -> VirtualLab | None:
    query = select(VirtualLab).where(VirtualLab.id == lab_id)
    return (await db.execute(statement=query)).scalar()


async def get_virtual_lab_async(db: AsyncSession, lab_id: UUID4) -> VirtualLab:
    """Returns irtual lab by id. Raises an exception if the lab by id is not found.
    The returned virtual lab might be deleted (i.e. Virtual.deleted might be True).
    """
    lab = await db.get(VirtualLab, lab_id)
    if lab is None:
        raise NoResultFound
    return lab


async def create_virtual_lab(db: AsyncSession, lab: VirtualLabDbCreate) -> VirtualLab:
    db_lab = VirtualLab(
        owner_id=lab.owner_id,
        id=lab.id,
        admin_group_id=lab.admin_group_id,
        member_group_id=lab.member_group_id,
        name=lab.name,
        description=lab.description,
        reference_email=lab.reference_email,
        nexus_organization_id=str(lab.nexus_organization_id),
        projects=[],
        budget=lab.budget,
        plan_id=lab.plan_id,
        entity=lab.entity,
    )
    db.add(db_lab)
    await db.commit()
    await db.refresh(db_lab)
    return db_lab


async def update_virtual_lab(
    db: AsyncSession, lab_id: UUID4, lab: labs.VirtualLabUpdate
) -> VirtualLab:
    current = await get_undeleted_virtual_lab(db, lab_id)
    data_to_update = lab.model_dump(exclude_unset=True)
    query = (
        update(VirtualLab)
        .where(VirtualLab.id == lab_id)
        .values(
            {
                "name": data_to_update.get("name", current.name),
                "description": data_to_update.get("description", current.description),
                "reference_email": data_to_update.get(
                    "reference_email", current.reference_email
                ),
                "updated_at": func.now(),
                "budget": data_to_update.get("budget", current.budget),
                "plan_id": data_to_update.get("plan_id", current.plan_id),
                "entity": data_to_update.get("entity", current.entity),
            }
        )
    )
    await db.execute(statement=query)
    await db.commit()
    return await get_undeleted_virtual_lab(db, lab_id)


async def delete_virtual_lab(
    db: AsyncSession, lab_id: UUID4, user_id: UUID4
) -> VirtualLab:
    now = func.now()
    # Mark virtual lab as deleted
    await db.execute(
        update(VirtualLab)
        .where(VirtualLab.id == lab_id)
        .values(deleted=True, deleted_at=now, deleted_by=user_id)
    )
    # Mark projects for the virtual lab as deleted
    await db.execute(
        update(Project)
        .where(Project.virtual_lab_id == lab_id)
        .values(deleted=True, deleted_at=now, deleted_by=user_id)
    )

    await db.commit()

    return await get_virtual_lab_async(db, lab_id)


async def count_virtual_labs_with_name(db: AsyncSession, name: str) -> int:
    query = select(VirtualLab).filter(
        ~VirtualLab.deleted,
        func.lower(VirtualLab.name) == func.lower(name),
    )
    count = await db.scalar(
        select(func.count()).select_from(query.options(noload("*")).subquery())
    )
    if count is None:
        return 0
    return count


async def get_virtual_labs_with_matching_name(
    db: AsyncSession, term: str, group_ids: list[str]
) -> list[VirtualLab]:
    query = select(VirtualLab).filter(
        and_(
            ~VirtualLab.deleted,
            func.lower(VirtualLab.name).like(f"%{term.strip().lower()}%"),
            or_(
                (VirtualLab.admin_group_id.in_(group_ids)),
                (VirtualLab.member_group_id.in_(group_ids)),
            ),
        )
    )
    result = (await db.execute(statement=query)).unique().scalars().all()
    return list(result)


async def retrieve_lab_distributed_budget(
    session: AsyncSession,
    *,
    current_project_id: UUID4,
    virtual_lab_id: UUID4,
) -> float:
    stmt = (
        select(
            func.coalesce(func.sum(Project.budget), 0).label("sum_budget_projects"),
        )
        .where(
            and_(
                Project.id != current_project_id,
                Project.budget.isnot(None),
                Project.virtual_lab_id == virtual_lab_id,
            )
        )
        .group_by(Project.virtual_lab_id)
    )
    result = await session.execute(stmt)
    sum_budget_projects = result.t.scalar()
    return sum_budget_projects if sum_budget_projects else 0
