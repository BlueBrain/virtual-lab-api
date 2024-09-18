from http import HTTPStatus as status
from typing import Tuple

from fastapi import Depends
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2AuthorizationCodeBearer,
)
from keycloak import KeycloakError  # type:ignore
from loguru import logger

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.infrastructure.kc.config import kc_realm
from virtual_labs.infrastructure.kc.models import AuthUser, ClientToken
from virtual_labs.infrastructure.settings import settings

from .config import kc_auth

auth_header: HTTPBearer | OAuth2AuthorizationCodeBearer = HTTPBearer(auto_error=False)

KC_SUBJECT: str = f"service-account-{settings.KC_CLIENT_ID}"


def get_public_key() -> str:
    """
    get the public key to decode the token
    """
    return (
        f"-----BEGIN PUBLIC KEY-----\n{kc_auth.public_key()}\n-----END PUBLIC KEY-----"
    )


def verify_jwt(
    header: HTTPAuthorizationCredentials = Depends(auth_header),
) -> Tuple[AuthUser, str]:
    if not header:
        raise VliError(
            error_code=VliErrorCode.AUTHORIZATION_ERROR,
            http_status_code=status.UNAUTHORIZED,
            message="No Authentication was provided",
            details="The supplied authentication is not authorized to access",
        )

    try:
        token = header.credentials
        decoded_token = kc_auth.decode_token(token=token, validate=True)
    except Exception as error:
        logger.exception(f"Auth Error {error}")
        raise VliError(
            error_code=VliErrorCode.AUTHORIZATION_ERROR,
            http_status_code=status.UNAUTHORIZED,
            message="Invalid authentication credentials",
        )

    try:
        introspected_token = kc_auth.introspect(
            token=token,
        )

        if introspected_token and introspected_token["active"] is False:
            raise IdentityError(
                message="Session not active",
                detail="Session is dead or user not found",
            )
    except KeycloakError as exception:
        logger.error(f"Keyclock error while token introspection {exception.__str__}")
        logger.exception(f"Keycloak introspection exception {exception}")
        raise VliError(
            error_code=VliErrorCode.AUTHORIZATION_ERROR,
            http_status_code=status.UNAUTHORIZED,
            message="Invalid authentication session",
            details=str(exception),
        ) from exception
    except Exception as exception:
        raise VliError(
            error_code=VliErrorCode.AUTHORIZATION_ERROR,
            http_status_code=status.UNAUTHORIZED,
            message="Invalid authentication session",
            details=str(exception),
        ) from exception

    try:
        user = AuthUser(**decoded_token)
        return (user, token)
    except Exception:
        raise VliError(
            error_code=VliErrorCode.INVALID_REQUEST,
            http_status_code=status.BAD_REQUEST,
            message="Generating authentication details failed",
            details="The user details is not correct",
        )


def get_client_token() -> str:
    try:
        kc_realm.connection.get_token()  # This refreshes client token
        return ClientToken.model_validate(kc_realm.connection.token).access_token
    except Exception as error:
        logger.error(f"Error retrieving client token {error}")
        raise error
        raise error
