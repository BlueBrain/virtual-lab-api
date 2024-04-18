from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Any, Generator

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from loguru import logger
from starlette.middleware.cors import CORSMiddleware

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.schemas import api
from virtual_labs.infrastructure.db.config import session_pool
from virtual_labs.infrastructure.settings import settings
from virtual_labs.routes.invites import router as invite_router
from virtual_labs.routes.labs import router as virtual_lab_router
from virtual_labs.routes.plans import router as plans_router
from virtual_labs.routes.projects import router as project_router


@asynccontextmanager  # type: ignore
async def lifespan(app: FastAPI) -> Generator[None, Any, None]:  # type: ignore
    yield
    if session_pool._engine is not None:
        await session_pool.close()


app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.APP_DEBUG,
    lifespan=lifespan,
)

base_router = APIRouter(prefix=settings.BASE_PATH)

origins = []
if settings.CORS_ORIGINS:
    for origin in settings.CORS_ORIGINS:
        origins.append(origin)


@app.exception_handler(VliError)
async def vli_exception_handler(request: Request, exception: VliError) -> JSONResponse:
    """
    this is will handle (format, standardize) all exceptions raised by the app
    any VliError raised anywhere in the app, will be captured by this handler
    and format it.
    """
    logger.error(f"{request.method} {request.url} failed: {repr(exception)}")

    return JSONResponse(
        status_code=int(exception.http_status_code),
        content=api.ErrorResponse(
            message=exception.message,
            error_code=VliErrorCode(exception.error_code),
            details=exception.details,
        ).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = {
        err.get("loc", (0, index))[1]: err.get(
            "msg", "Field value is invalid. Further details unavailable."
        )
        for index, err in enumerate(exc.errors())
    }
    return JSONResponse(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        content=jsonable_encoder(
            {"error_code": VliErrorCode.INVALID_REQUEST, "details": errors}
        ),
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@base_router.get("/")
def root() -> str:
    return "Server is running."


# TODO: add a proper health check logic, see https://pypi.org/project/fastapi-health/.
@base_router.get("/healthz")
def health() -> str:
    return "OK"


base_router.include_router(project_router)
base_router.include_router(virtual_lab_router)
base_router.include_router(plans_router)
base_router.include_router(invite_router)

app.include_router(base_router)
