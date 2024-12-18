from enum import StrEnum
from http import HTTPStatus


# TODO: NOTE: do we keep the suffix ERROR or not ?
class NexusErrorValue(StrEnum):
    CREATE_ORGANIZATION_ERROR = "NEXUS_CREATE_ORGANIZATION_ERROR"
    FETCH_ORGANIZATION_ERROR = "NEXUS_FETCH_ORGANIZATION_ERROR"
    DEPRECATE_ORGANIZATION_ERROR = "NEXUS_DEPRECATE_ORGANIZATION_ERROR"

    CREATE_PROJECT_ERROR = "NEXUS_CREATE_PROJECT_ERROR"
    UPDATE_PROJECT_ERROR = "NEXUS_UPDATE_PROJECT_ERROR"
    DEPRECATE_PROJECT_ERROR = "NEXUS_DEPRECATE_PROJECT_ERROR"
    APPEND_ACL_ERROR = "NEXUS_APPEND_ACL_ERROR"
    SUBTRACT_ACL_ERROR = "NEXUS_SUBTRACT_ACL_ERROR"
    DELETE_PROJECT_ACL_ERROR = "NEXUS_DELETE_PROJECT_ACL_ERROR"
    FETCH_PROJECT_ERROR = "NEXUS_FETCH_PROJECT_ERROR"
    FETCH_PROJECT_ACL_ERROR = "NEXUS_FETCH_PROJECT_ACL_ERROR"

    FETCH_NEXUS_PERMISSIONS_ERROR = "NEXUS_FETCH_NEXUS_PERMISSIONS_ERROR"

    FETCH_SUITE_ERROR = "NEXUS_FETCH_SUITE_ERROR"

    CREATE_RESOURCE_ERROR = "NEXUS_CREATE_RESOURCE_ERROR"
    CREATE_RESOLVER_ERROR = "NEXUS_CREATE_RESOLVER_ERROR"
    CREATE_ES_VIEW_ERROR = "NEXUS_CREATE_ES_VIEW_ERROR"
    CREATE_SP_VIEW_ERROR = "NEXUS_CREATE_SP_VIEW_ERROR"
    CREATE_ES_AGG_VIEW_ERROR = "NEXUS_CREATE_ES_AGG_VIEW_ERROR"
    CREATE_SP_AGG_VIEW_ERROR = "NEXUS_CREATE_SP_AGG_VIEW_ERROR"
    FETCH_RESOURCE_ERROR = "NEXUS_FETCH_RESOURCE_ERROR"

    CREATE_S3_STORAGE_ERROR = "NEXUS_CREATE_S3_STORAGE_ERROR"

    GET_AGENT_ERROR = "NEXUS_GET_AGENT_ERROR"
    CREATE_AGENT_ERROR = "CREATE_AGENT_ERROR"

    GENERIC_ERROR = "NEXUS_GENERIC_ERROR"


class NexusError(Exception):
    message: str | None
    type: NexusErrorValue | None
    http_status_code: HTTPStatus | None

    def __init__(
        self,
        *,
        message: str | None = None,
        type: NexusErrorValue | None = None,
        http_status_code: HTTPStatus | None = None,
    ) -> None:
        self.message = message
        self.type = type
        self.http_status_code = http_status_code
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.message}"
