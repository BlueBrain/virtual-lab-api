from os import getenv
from typing import Any, Literal, Optional, TypeGuard, get_args

from dotenv import load_dotenv
from pydantic import EmailStr, PostgresDsn, ValidationInfo, field_validator
from pydantic_core import MultiHostUrl, Url
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv("")

_ENVS = Literal["development", "testing", "staging", "production"]


def _is_valid_env(env: str | None) -> TypeGuard[_ENVS]:
    return env in get_args(_ENVS)


_ENV = getenv("DEPLOYMENT_ENV")
_DEPLOYMENT_ENV = _ENV if _is_valid_env(_ENV) else "development"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # `.env.local` takes priority over `.env`
        env_file=(".env", f".env.{_DEPLOYMENT_ENV}", ".env.local")
    )

    APP_NAME: str = "virtual-lab-manager service"
    APP_DEBUG: bool = False
    DEPLOYMENT_ENV: _ENVS = _DEPLOYMENT_ENV
    BASE_PATH: str = ""
    DEBUG_DATABASE_ECHO: bool = False
    CORS_ORIGINS: list[str] = []
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 15432
    POSTGRES_USER: str = "vlm"
    POSTGRES_PASSWORD: str = "vlm"
    POSTGRES_DB: str = "vlm"
    DATABASE_URI: PostgresDsn = MultiHostUrl(
        "postgresql+asyncpg://vlm:vlm@localhost:15432/vlm"
    )
    NEXUS_DELTA_URI: Url = Url("http://localhost:8080/v1")
    NEXUS_CROSS_RESOLVER_PROJECTS: list[str] = []

    KC_SERVER_URI: str = "http://localhost:9090/"
    KC_USER_NAME: str = "admin"
    KC_PASSWORD: str = "admin"
    KC_CLIENT_ID: str = "obpapp"
    KC_CLIENT_SECRET: str = "obp-secret"
    KC_REALM_NAME: str = "obp-realm"
    DEPLOYMENT_NAMESPACE: str = "https://openbrainplatform.org"
    VLAB_ADMIN_PATH: str = "{}/mmb-beta/virtual-lab/lab/{}/admin?panel=billing"

    MAIL_USERNAME: str = "dummyusername"
    MAIL_PASSWORD: str = "dummypassword"
    MAIL_FROM: EmailStr = "obp@bbp.org"
    MAIL_PORT: int = 1025
    MAIL_SERVER: str = "localhost"
    MAIL_STARTTLS: bool = False

    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = False

    INVITE_JWT_SECRET: str = "TEST_JWT_SECRET"
    INVITE_EXPIRES_IN_DAYS: int = 7
    INVITE_LINK_BASE: str = "http://localhost:3000/"

    STRIPE_SECRET_KEY: str = ""
    STRIPE_DEVICE_NAME: str = ""
    STRIPE_WEBHOOK_SECRET: str = getenv("STRIPE_WEBHOOK_SECRET", "")

    @field_validator("DATABASE_URI", mode="before")
    @classmethod
    def build_db_connection(cls, v: Optional[str], values: ValidationInfo) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=values.data.get("POSTGRES_USER"),
            password=values.data.get("POSTGRES_PASSWORD"),
            host=values.data.get("POSTGRES_HOST"),
            port=values.data.get("POSTGRES_PORT"),
            path=f"{values.data.get('POSTGRES_DB') or ''}",
        )


settings = Settings()
