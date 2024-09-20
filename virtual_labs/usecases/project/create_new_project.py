from http import HTTPStatus as status
from typing import List, Tuple
from uuid import UUID, uuid4

from fastapi.responses import Response
from keycloak import KeycloakError  # type: ignore
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import IntegrityError, NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.email_error import EmailError
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.core.response.api_response import VliResponse
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain.invite import AddUser
from virtual_labs.domain.project import FailedInvite, ProjectCreationBody, ProjectVlOut
from virtual_labs.external.nexus.project_instance import instantiate_nexus_project
from virtual_labs.infrastructure.db.models import Project as DbProject
from virtual_labs.infrastructure.db.models import VirtualLab
from virtual_labs.infrastructure.email.email_service import EmailDetails, send_invite
from virtual_labs.infrastructure.kc.models import AuthUser
from virtual_labs.repositories.group_repo import GroupMutationRepository
from virtual_labs.repositories.invite_repo import InviteMutationRepository
from virtual_labs.repositories.labs import get_undeleted_virtual_lab
from virtual_labs.repositories.project_repo import (
    ProjectMutationRepository,
    ProjectQueryRepository,
)
from virtual_labs.repositories.user_repo import (
    UserMutationRepository,
    UserQueryRepository,
)
from virtual_labs.shared.utils.auth import get_user_id_from_auth


async def invite_project_members(
    session: AsyncSession,
    members: list[AddUser],
    virtual_lab: VirtualLab,
    project: DbProject,
    inviter_id: UUID4,
) -> List[FailedInvite]:
    invite_repo = InviteMutationRepository(session)
    user_query_repo = UserQueryRepository()
    failed_invites: List[FailedInvite] = []
    for member in members:
        try:
            user = user_query_repo.retrieve_user_by_email(member.email)
            inviter = user_query_repo.retrieve_user_from_kc(str(inviter_id))

            invitee_id = UUID(user.id) if user is not None else None
            invitee_name = None if user is None else f"{user.firstName} {user.lastName}"

            try:
                invite = await invite_repo.add_project_invite(
                    inviter_id=inviter_id,
                    project_id=UUID(str(project.id)),
                    invitee_role=member.role,
                    invitee_id=invitee_id,
                    invitee_email=str(member.email),
                )
                await session.refresh(project)
                await session.refresh(virtual_lab)
                await send_invite(
                    details=EmailDetails(
                        recipient=str(member.email),
                        invitee_name=invitee_name,
                        inviter_name=f"{inviter.firstName} {inviter.lastName}",
                        invite_id=UUID(str(invite.id)),
                        lab_id=UUID(str(virtual_lab.id)),
                        lab_name=str(virtual_lab.name),
                        project_id=UUID(str(project.id)),
                        project_name=str(project.name),
                    )
                )
            except (EmailError, Exception) as ex:
                logger.error(f"Error during sending invite to {member}: ({ex})")
                if invite:
                    await invite_repo.delete_project_invite(
                        invite_id=UUID(str(invite.id))
                    )
                if user:
                    failed_invites.append(
                        FailedInvite(
                            user_email=member.email,
                            first_name=user.firstName,
                            last_name=user.lastName,
                        )
                    )
                pass
        except IdentityError:
            failed_invites.append(
                FailedInvite(
                    user_email=member.email,
                    exists=False,
                )
            )
            pass

    return failed_invites


async def create_new_project_use_case(
    session: AsyncSession,
    *,
    virtual_lab_id: UUID4,
    payload: ProjectCreationBody,
    auth: Tuple[AuthUser, str],
) -> Response:
    pmr = ProjectMutationRepository(session)
    pqr = ProjectQueryRepository(session)
    gmr = GroupMutationRepository()
    umr = UserMutationRepository()

    project_id: UUID4 = uuid4()
    user_id = get_user_id_from_auth(auth)
    failed_invites = []

    try:
        vlab = await get_undeleted_virtual_lab(session, virtual_lab_id)

        if bool(
            await pqr.check_project_exists_by_name_per_vlab(
                vlab_id=virtual_lab_id,
                query_term=payload.name,
            )
        ):
            raise

    except NoResultFound:
        raise VliError(
            error_code=VliErrorCode.ENTITY_NOT_FOUND,
            http_status_code=status.BAD_REQUEST,
            message="Virtual lab not found",
        )
    except Exception as ex:
        logger.error(
            f"Error during retrieving the Virtual lab or Project with same name exist ({ex})"
        )
        raise VliError(
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=status.BAD_REQUEST,
            message="Another project with the same name already exists",
        )

    try:
        admin_group = gmr.create_project_group(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=payload,
            role=UserRoleEnum.admin,
        )

        member_group = gmr.create_project_group(
            virtual_lab_id=virtual_lab_id,
            project_id=project_id,
            payload=payload,
            role=UserRoleEnum.member,
        )

        assert admin_group is not None
        assert member_group is not None

        umr.attach_user_to_group(
            user_id=user_id,
            group_id=admin_group["id"],
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
            error_code=ex.response_code or VliErrorCode.EXTERNAL_SERVICE_ERROR,
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
            admin_group_name=admin_group["name"],
            member_group_name=member_group["name"],
            auth=auth,
        )
    except NexusError as ex:
        logger.error(f"Error during creating project instance due nexus error ({ex})")
        gmr.delete_group(group_id=admin_group["id"])
        gmr.delete_group(group_id=member_group["id"])

        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=status.BAD_GATEWAY,
            message="Nexus Project creation failed",
            details=ex.type,
        )

    try:
        project = await pmr.create_new_project(
            id=project_id,
            payload=payload,
            virtual_lab_id=virtual_lab_id,
            nexus_project_id=nexus_project_id,
            admin_group_id=admin_group["id"],
            member_group_id=member_group["id"],
            owner_id=user_id,
        )

        if payload.include_members:
            failed_invites = await invite_project_members(
                session=session,
                inviter_id=user_id,
                members=payload.include_members,
                virtual_lab=vlab,
                project=project,
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
                "project": ProjectVlOut.model_validate(project),
                "virtual_lab_id": virtual_lab_id,
                "failed_invites": failed_invites,
            },
        )
