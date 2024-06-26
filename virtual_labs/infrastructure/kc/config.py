from keycloak import KeycloakOpenID  # type: ignore
from keycloak import KeycloakAdmin

from virtual_labs.infrastructure.settings import settings

"""
    will have many realms 
    so for every realm we should configure another instance of connection
    or we should have service account and then use the credentials for every realm
    change realm_name depends on the user token for further ops
"""

kc_realm = KeycloakAdmin(
    server_url=settings.KC_SERVER_URI,
    client_id=settings.KC_CLIENT_ID,
    client_secret_key=settings.KC_CLIENT_SECRET,
    realm_name=settings.KC_REALM_NAME,
)

# NOTE: this is just for testing purpose (token will be recieved from AWS-Keyclok)
kc_auth = KeycloakOpenID(
    client_id=settings.KC_CLIENT_ID,
    client_secret_key=settings.KC_CLIENT_SECRET,
    realm_name=settings.KC_REALM_NAME,
    server_url=settings.KC_SERVER_URI,
    verify=True,
)
