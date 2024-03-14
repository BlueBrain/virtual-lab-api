from json import loads
from typing import Any, Dict, cast

from keycloak import KeycloakAdmin, KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4

from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.project import ProjectCreationModel
from virtual_labs.infrastructure.kc.config import kc_realm


class GroupQueryRepository:
    Kc: KeycloakAdmin

    def __init__(self) -> None:
        self.Kc = kc_realm

    # TODO: the return type should be update, probably Keycloack will return UserRepresentation
    def retrieve_group_users(self, group_id: str) -> list[str]:
        users = self.Kc.get_group_members(group_id=group_id)

        # TODO: We can also accept dicts later if need be.
        if not isinstance(users, list):
            raise ValueError(
                f"Expected list of users for group {group_id} instead received {type(users)}"
            )

        return users


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
    ) -> str:
        """
        NOTE: you can not set the ID even in the docs says that is Optional
        virtual lab group must be following this format
        vlab/vl-app-id/role
        """
        try:
            group_id = self.Kc.create_group(
                {
                    "name": "vlab/{}/{}".format(vl_id, role.value),
                    "attributes": {
                        "_name": [vl_name],
                    },
                }
            )

            return cast(
                str,
                group_id,
            )
        # TODO: Add custom Keycloak error class to catch KeyClak errors from keycloak dependencies that are not type safe.
        except Exception as error:
            logger.error(
                f"Error when creating {role} group for lab {vl_name} with id {vl_id}: ({error})"
            )
            raise Exception(
                f"Error when creating {role} group for lab {vl_name} with id {vl_id}: ({error})"
            )

    def create_project_group(
        self,
        *,
        virtual_lab_id: UUID4,
        project_id: UUID4,
        role: UserRoleEnum,
        payload: ProjectCreationModel,
    ) -> str | None:
        """
        NOTE: you can not set the ID even in the docs says that is Optional
        project group must be following this format
        proj/virtual_lab_id/project_id/role
        """
        group_id = self.Kc.create_group(
            {
                # TODO: if we will use flat structure then this one must be removed
                # "parentId": f"vl/{virtual_lab_id}",
                "name": "proj/{}/{}/{}".format(virtual_lab_id, project_id, role.value),
                "attributes": {
                    "_name": [payload.name],
                    "_description": [payload.description],
                },
            },
            # TODO: if we will use flat structure then this one must be removed
            # parent=f"vl/{virtual_lab_id}",
        )

        return cast(
            str | None,
            group_id,
        )

    def delete_group(self, *, group_id: str) -> Any | Dict[str, str]:
        try:
            return self.Kc.delete_group(group_id=group_id)
        except KeycloakError as error:
            logger.error(
                f"Group {group_id} could not be deleted.  {loads(error.error_message)["error"]}"
            )
            raise Exception(
                f"Keycloak error when deleting group {group_id}: {loads(error.error_message)["error"]}"
            )