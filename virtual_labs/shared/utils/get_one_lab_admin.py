from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.labs import UserWithInviteStatus
from virtual_labs.infrastructure.db.models import VirtualLab
from virtual_labs.repositories.group_repo import GroupQueryRepository


def get_one_lab_admin(lab: VirtualLab) -> UserWithInviteStatus:
    """
    Returns one admin for a virtual lab.
    If there are multiple admins, the one whose username appears first in alphabetical order is returned.
    If there are no admins, an exception is raised
    """
    group_repo = GroupQueryRepository()
    all_admins = group_repo.retrieve_group_users(str(lab.admin_group_id))

    assert len(all_admins) >= 1
    all_admins.sort(key=lambda x: x.username)

    return UserWithInviteStatus(
        **all_admins[0].model_dump(),
        invite_accepted=True,
        role=UserRoleEnum.admin.value,
    )
