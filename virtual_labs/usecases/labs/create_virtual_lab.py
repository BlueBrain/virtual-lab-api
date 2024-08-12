from http import HTTPStatus
from typing import Literal, TypedDict
from uuid import UUID, uuid4

import stripe
from loguru import logger
from pydantic import UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from virtual_labs.core.exceptions.api_error import VliError, VliErrorCode
from virtual_labs.core.exceptions.identity_error import IdentityError
from virtual_labs.core.exceptions.nexus_error import NexusError
from virtual_labs.core.types import UserRoleEnum
from virtual_labs.domain import labs as domain
from virtual_labs.domain.invite import AddUser
from virtual_labs.external.nexus.create_organization import create_nexus_organization
from virtual_labs.infrastructure.db import models
from virtual_labs.infrastructure.kc.models import AuthUser, CreatedGroup
from virtual_labs.infrastructure.stripe.config import stripe_client
from virtual_labs.repositories import labs as repository
from virtual_labs.repositories.group_repo import GroupMutationRepository
from virtual_labs.repositories.invite_repo import InviteMutationRepository
from virtual_labs.repositories.user_repo import (
    UserMutationRepository,
    UserQueryRepository,
)
from virtual_labs.shared.utils.auth import get_user_id_from_auth
from virtual_labs.usecases.labs.invite_user_to_lab import send_email_to_user_or_rollback
from virtual_labs.usecases.plans.verify_plan import verify_plan

GroupIds = dict[Literal["member_group"] | Literal["admin_group"], CreatedGroup]
UserInvites = TypedDict(
    "UserInvites",
    {
        "successful_invites": list[AddUser],
        "failed_invites": list[AddUser],
    },
)


async def create_keycloak_groups(lab_id: UUID4, lab_name: str) -> GroupIds:
    kc = GroupMutationRepository()

    try:
        admin_group = kc.create_virtual_lab_group(
            vl_id=lab_id, vl_name=lab_name, role=UserRoleEnum.admin
        )
        member_group = kc.create_virtual_lab_group(
            vl_id=lab_id, vl_name=lab_name, role=UserRoleEnum.member
        )

        assert admin_group is not None
        assert member_group is not None

        return {"admin_group": admin_group, "member_group": member_group}
    except IdentityError as error:
        raise error
    except Exception as error:
        raise VliError(
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            message=str(error),
        )


async def invite_members_to_lab(
    db: AsyncSession,
    members: list[AddUser],
    virtual_lab: models.VirtualLab,
    inviter_id: UUID4,
) -> UserInvites:
    user_repo = UserQueryRepository()
    invite_mutation_repo = InviteMutationRepository(db)

    successful_invites: list[AddUser] = []
    failed_invites: list[AddUser] = []
    inviting_user = user_repo.retrieve_user_from_kc(str(inviter_id))

    for member in members:
        try:
            user_to_invite = user_repo.retrieve_user_by_email(member.email)
            user_id = UUID(user_to_invite.id) if user_to_invite is not None else None
            invitee_name = (
                None
                if user_to_invite is None
                else f"{user_to_invite.firstName} {user_to_invite.lastName}"
            )

            if user_id == inviter_id:
                logger.error(
                    f"User cannot invite oneself. Inviter {inviter_id}. Invitee {member.email}"
                )
                raise VliError(
                    message=f"User with email {member.email} is already in lab {virtual_lab.name}",
                    http_status_code=HTTPStatus.PRECONDITION_FAILED,
                    error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
                )

            invite = await invite_mutation_repo.add_lab_invite(
                virtual_lab_id=UUID(str(virtual_lab.id)),
                # Inviter details
                inviter_id=inviter_id,
                # Invitee details
                invitee_id=user_id,
                invitee_role=member.role,
                invitee_email=member.email,
            )
            # Need to refresh the lab because the invite is commited inside the repo.
            await db.refresh(virtual_lab)
            await send_email_to_user_or_rollback(
                invite_id=UUID(str(invite.id)),
                invitee_name=invitee_name,
                inviter_name=f"{inviting_user.firstName} {inviting_user.lastName}",
                email=member.email,
                lab_name=str(virtual_lab.name),
                lab_id=UUID(str(virtual_lab.id)),
                invite_repo=invite_mutation_repo,
            )
            successful_invites.append(member)

        except VliError as error:
            logger.error(
                f"Email error when inviting user {member.email} during lab creation: {error}"
            )
            failed_invites.append(member)
        except SQLAlchemyError as error:
            logger.error(
                f"Db error when inviting user {member.email} during lab creation: {error}"
            )
            failed_invites.append(member)
        except Exception as error:
            logger.error(
                f"Unknown error when inviting user {member.email} during lab creation: {error}"
            )
            failed_invites.append(member)
    return {"failed_invites": failed_invites, "successful_invites": successful_invites}


async def create_virtual_lab(
    db: AsyncSession, lab: domain.VirtualLabCreate, auth: tuple[AuthUser, str]
) -> domain.CreateLabOut:
    group_repo = GroupMutationRepository()

    # 1. Create kc groups and add user to adming group
    try:
        await verify_plan(db, lab.plan_id)
        new_lab_id = uuid4()
        owner_id = get_user_id_from_auth(auth)
        # Create admin & member groups
        groups = await create_keycloak_groups(new_lab_id, lab.name)

        # Add user as admin for this lab
        user_repo = UserMutationRepository()
        user_repo.attach_user_to_group(
            user_id=owner_id, group_id=groups["admin_group"]["id"]
        )
    except ValueError as error:
        raise VliError(
            message=str(error),
            error_code=VliErrorCode.INVALID_REQUEST,
            http_status_code=HTTPStatus.BAD_REQUEST,
        )
    except IdentityError as error:
        logger.error(
            f"Virtual lab could not be created because of idenity error {error}"
        )
        raise VliError(
            message=f"User {owner_id} is not authorized to create virtual lab",
            error_code=VliErrorCode.NOT_ALLOWED_OP,
            http_status_code=HTTPStatus.FORBIDDEN,
        )

    # 2. Create nexus org
    try:
        nexus_org = await create_nexus_organization(
            nexus_org_id=new_lab_id,
            description=lab.description,
            admin_group_name=groups["admin_group"]["name"],
            member_group_name=groups["member_group"]["name"],
        )

    except NexusError as ex:
        group_repo.delete_group(group_id=groups["admin_group"]["id"])
        group_repo.delete_group(group_id=groups["member_group"]["id"])
        logger.error(f"Error during reverting project instance due nexus error ({ex})")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=HTTPStatus.BAD_GATEWAY,
            message="Nexus organization creation failed",
            details=ex.type,
        )
    except Exception as ex:
        logger.error(f"Error when creating nexus origin {ex}")
        raise VliError(
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=HTTPStatus.BAD_GATEWAY,
            message="Nexus organization creation failed",
        )

    try:
        customer = await stripe_client.customers.create_async(
            {
                "name": lab.name,
                "email": str(lab.reference_email),
                "metadata": {
                    "virtual_lab_id": str(new_lab_id),
                },
            }
        )
    except stripe.StripeError as ex:
        logger.error(f"Error during creating stripe customer :({ex})")
        raise VliError(
            message="creating stripe customer failed",
            error_code=VliErrorCode.EXTERNAL_SERVICE_ERROR,
            http_status_code=HTTPStatus.BAD_GATEWAY,
        )

    # 3. Save lab to db
    try:
        # Save lab to db
        lab_with_ids = repository.VirtualLabDbCreate(
            id=new_lab_id,
            owner_id=owner_id,
            nexus_organization_id=nexus_org.self,
            admin_group_id=groups["admin_group"]["id"],
            member_group_id=groups["member_group"]["id"],
            stripe_customer_id=customer.id,
            **lab.model_dump(),
        )
        db_lab = await repository.create_virtual_lab(db, lab_with_ids)
        if lab.include_members is None or len(lab.include_members) == 0:
            return domain.CreateLabOut(
                virtual_lab=domain.VirtualLabDetails.model_validate(db_lab),
                successful_invites=[],
                failed_invites=[],
            )
        # 4. Invite users
        invites = await invite_members_to_lab(db, lab.include_members, db_lab, owner_id)
        return domain.CreateLabOut(
            virtual_lab=domain.VirtualLabDetails.model_validate(db_lab),
            successful_invites=invites["successful_invites"],
            failed_invites=invites["failed_invites"],
        )
    except IntegrityError as error:
        logger.error(
            "Virtual lab could not be created due to database error {}".format(error)
        )
        raise VliError(
            message="Another virtual lab with same name already exists",
            error_code=VliErrorCode.ENTITY_ALREADY_EXISTS,
            http_status_code=HTTPStatus.CONFLICT,
        )
    except SQLAlchemyError as error:
        logger.error(
            "Virtual lab could not be created due to an unknown database error {}".format(
                error
            )
        )
        raise VliError(
            message="Virtual lab could not be saved to the database",
            error_code=VliErrorCode.DATABASE_ERROR,
            http_status_code=HTTPStatus.BAD_REQUEST,
        )
    except VliError as error:
        raise error
    except Exception as error:
        logger.error(
            "Virtual lab could not be created due to an unknown error {}".format(error)
        )

        raise VliError(
            message="Virtual lab could not be created",
            error_code=VliErrorCode.SERVER_ERROR,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
