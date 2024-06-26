from uuid import UUID


from pydantic import UUID4

from virtual_labs.infrastructure.kc.models import AuthUser


def get_user_id_from_auth(auth: tuple[AuthUser, str]) -> UUID4:
    """Returns uuid of the test user created in keycloak."""
    return UUID(auth[0].sub)
