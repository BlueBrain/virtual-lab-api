from typing import Any, Dict, List

from keycloak import KeycloakAdmin  # type: ignore
from pydantic import UUID4

from virtual_labs.infrastructure.kc.config import kc_realm


class UserQueryRepository:
    Kc: KeycloakAdmin

    def __init__(self) -> None:
        self.Kc = kc_realm

    def retrieve_user_from_kc(self, user_id: str) -> Any | Dict[str, str]:
        return self.Kc.get_user(user_id)

    def retrieve_user_groups(self, user_id: UUID4) -> Any | Dict[str, str] | List[Any]:
        return self.Kc.get_user_groups(user_id=user_id)

    def is_user_in_group(self, user_id: UUID4, group_id: str) -> bool:
        current_groups = self.retrieve_user_groups(user_id)
        return group_id in current_groups


class UserMutationRepository:
    Kc: KeycloakAdmin

    def __init__(self) -> None:
        self.Kc = kc_realm

    def attach_user_to_group(
        self,
        *,
        user_id: UUID4,
        group_id: str,
    ) -> Any | Dict[str, str]:
        return self.Kc.group_user_add(user_id=user_id, group_id=group_id)

    def detach_user_from_group(
        self,
        *,
        user_id: UUID4,
        group_id: str,
    ) -> Any | Dict[str, str]:
        return self.Kc.group_user_remove(user_id=user_id, group_id=group_id)
