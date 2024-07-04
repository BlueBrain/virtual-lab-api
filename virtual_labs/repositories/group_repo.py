from typing import Any, Dict, List, cast

from keycloak import KeycloakAdmin  # type: ignore
from loguru import logger
from pydantic import UUID4

from virtual_labs.core.exceptions.generic_exceptions import UserNotInList
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.project import ProjectCreationBody
from virtual_labs.infrastructure.kc.config import kc_realm
from virtual_labs.infrastructure.kc.models import (
    CreatedGroup,
    GroupRepresentation,
    UserRepresentation,
)


class GroupQueryRepository:
    Kc: KeycloakAdmin

    def __init__(self) -> None:
        self.Kc = kc_realm

    def retrieve_group_users(self, group_id: str) -> List[UserRepresentation]:
        members = self.Kc.get_group_members(group_id=group_id)
        return [UserRepresentation(**member) for member in members]

    def retrieve_user_groups(self, user_id: str) -> List[GroupRepresentation]:
        groups = self.Kc.get_user_groups(user_id=user_id)
        return [GroupRepresentation(**group) for group in groups]

    def retrieve_group_by_name(self, name: str) -> GroupRepresentation:
        group = self.Kc.get_group_by_path(name)
        return GroupRepresentation(**group)

    def retrieve_group_by_id(self, group_id: str) -> GroupRepresentation:
        group = self.Kc.get_group(group_id=group_id)
        return GroupRepresentation(**group)

    def check_user_in_group(self, group_id: str, user_id: str) -> bool:
        group_users = self.retrieve_group_users(group_id=group_id)
        if any([cast(Dict[str, object], u)["id"] == user_id for u in group_users]):
            return True
        else:
            raise UserNotInList("User not found in the list")


class GroupMutationRepository:
    Kc: KeycloakAdmin

    def __init__(self) -> None:
        self.Kc = kc_realm

    def create_virtual_lab_group(
        self,
        *,
        vl_id: UUID4,
        vl_name: str,
        role: UserRoleEnum,
    ) -> CreatedGroup:
        """
        NOTE: you can not set the ID even in the docs says that is Optional
        virtual lab group must be following this format
        vlab/vl-app-id/role
        """
        try:
            group_name = "vlab/{}/{}".format(vl_id, role.value)
            group_id = self.Kc.create_group({"name": group_name})

            return {"id": group_id, "name": group_name}

        # TODO: Add custom Keycloak error class to catch KeyClak errors from keycloak dependencies that are not type safe.
        except Exception as error:
            logger.error(
                f"Error when creating {role} group for lab {vl_name} with id {vl_id}: ({error})"
            )
            raise IdentityError(
                message=f"Error when creating {role} group for lab {vl_name} with id {vl_id}: ({error})",
                detail=str(error),
            )

    def create_project_group(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        role: UserRoleEnum,
        payload: ProjectCreationBody,
    ) -> CreatedGroup | None:
        """
        NOTE: you can not set the ID even in the docs says that is Optional
        project group must be following this format
        proj/virtual_lab_id/project_id/role
        """
        group_name = "proj/{}/{}/{}".format(virtual_lab_id, project_id, role.value)
        group_id = self.Kc.create_group(
            {"name": group_name},
        )

        return {"id": group_id, "name": group_name}

    def delete_group(self, *, group_id: str) -> Any | Dict[str, str]:
        return self.Kc.delete_group(group_id=group_id)
