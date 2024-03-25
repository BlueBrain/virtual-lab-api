from http import HTTPStatus as status
from typing import Tuple
from uuid import uuid4

from fastapi.responses import Response
from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import IntegrityError, NoResultFound, SQLAlchemyError
from sqlalchemy.orm import Session

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.project import Project, ProjectCreationBody
from virtual_labs.external.nexus.project_instance import instantiate_nexus_project
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.group_repo import GroupMutationRepository
from virtual_labs.repositories.labs import get_virtual_lab
from virtual_labs.repositories.project_repo import (
    ProjectMutationRepository,
    ProjectQueryRepository,
)
from virtual_labs.repositories.user_repo import UserMutationRepository
from virtual_labs.shared.utils.auth import get_user_id_from_auth


async def create_new_project_use_case(
    session: Session,
    *,
    virtual_lab_id: UUID4,
    payload: ProjectCreationBody,
    auth: Tuple[AuthUser, str],
) -> Response | VliError:
    pmr = ProjectMutationRepository(session)
    pqr = ProjectQueryRepository(session)
    gmr = GroupMutationRepository()
    umr = UserMutationRepository()

    project_id: UUID4 = uuid4()
    user_id = get_user_id_from_auth(auth)

    try:
        get_virtual_lab(session, virtual_lab_id)

        if pqr.retrieve_one_project_by_name(name=payload.name):
            raise

    except NoResultFound:
        raise VliError(
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=status.BAD_REQUEST,
            message="Virtual lab not found",
        )
    except Exception as ex:
        logger.error(f"Error during retrieving the project ({ex})")
        raise VliError(
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=status.BAD_REQUEST,
            message="Another project with the same name already exists",
        )

    try:
        admin_group_id = gmr.create_project_group(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=payload,
            role=UserRoleEnum.admin,
        )

        member_group_id = gmr.create_project_group(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=payload,
            role=UserRoleEnum.member,
        )

        assert admin_group_id is not None
        assert member_group_id is not None

        # TODO: to asyncio need to run in parallel
        umr.attach_user_to_group(
            user_id=user_id,
            group_id=admin_group_id,
        )
        if payload.include_members:
            for member in payload.include_members:
                umr.attach_user_to_group(
                    user_id=member,
                    group_id=member_group_id,
                )

    except AssertionError:
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Admin/Member group_id failed to be generated",
        )
    except KeycloakError as ex:
        logger.error(f"Error during creating/attaching to group in KC: ({ex})")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="KC Group creation/attaching failed",
        )
    except Exception as ex:
        logger.error(f"Error during creating/attaching to group in KC: ({ex})")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="KC Group creation/attaching failed",
        )

    try:
        nexus_project_id = await instantiate_nexus_project(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            description=payload.description,
            admin_group_id=admin_group_id,
            member_group_id=member_group_id,
            auth=auth,
        )
    except NexusError as ex:
        logger.error(f"Error during creating project instance due nexus error ({ex})")
        gmr.delete_group(group_id=admin_group_id)
        gmr.delete_group(group_id=member_group_id)

        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Nexus Project creation failed",
            details=ex.type,
        )

    try:
        project = pmr.create_new_project(
            id=project_id,
            payload=payload,
            virtual_lab_id=virtual_lab_id,
            nexus_project_id=nexus_project_id,
            admin_group_id=admin_group_id,
            member_group_id=member_group_id,
            owner_id=user_id,
        )
    except AssertionError:
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Admin/Member group_id failed to be generated",
        )
    except IntegrityError:
        raise VliError(
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=status.BAD_REQUEST,
            message="Project already exists",
        )
    except SQLAlchemyError:
        raise VliError(
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=status.BAD_REQUEST,
            message="Project creation failed",
        )
    except Exception as ex:
        logger.error(f"Error during creating new project ({ex})")
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=status.INTERNAL_SERVER_ERROR,
            message="Error during creating a new project",
        )
    else:
        return VliResponse.new(
            message="Project created successfully",
            data={
                "project": Project(**project.__dict__),
            },
        )
