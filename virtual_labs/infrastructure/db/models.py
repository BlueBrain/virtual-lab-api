import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    not_,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class VirtualLab(Base):
    __tablename__ = "virtual_lab"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), nullable=False)
    admin_group_id = Column(String, nullable=False, unique=True)
    member_group_id = Column(String, nullable=False, unique=True)

    nexus_organization_id = Column(String, nullable=False, unique=True)

    name = Column(String(250), index=True)
    description = Column(Text)
    reference_email = Column(String(255))

    budget = Column(
        Float, CheckConstraint("budget > 0"), nullable=False
    )  # Amount in USD

    deleted = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    deleted_at = Column(DateTime)

    projects = relationship("Project", back_populates="virtual_lab")
    invites = relationship("VirtualLabInvite", back_populates="virtual_lab")

    plan_id = Column(Integer, ForeignKey("plan.id"))
    plan = relationship("Plan", back_populates="virtual_labs")

    # Virtual lab name should be unique among non-deleted labs
    __table_args__ = (
        Index(
            "unique_lab_name_for_non_deleted",
            name,
            deleted,
            unique=True,
            postgresql_where=(not_(deleted)),
        ),
    )


class Project(Base):
    __tablename__ = "project"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nexus_project_id = Column(String, nullable=False, unique=True)
    admin_group_id = Column(String, nullable=False, unique=True)
    member_group_id = Column(String, nullable=False, unique=True)
    owner_id = Column(UUID(as_uuid=True), nullable=False)
    name = Column(String(250), index=True)
    description = Column(Text)
    deleted = Column(Boolean, default=False)
    budget = Column(Float, default=None)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now(), default=func.now())
    deleted_at = Column(DateTime)
    deleted_by = Column(UUID(as_uuid=True))

    virtual_lab_id = Column(
        "virtual_lab_id", UUID(as_uuid=True), ForeignKey("virtual_lab.id")
    )
    virtual_lab = relationship("VirtualLab", back_populates="projects")
    project_stars = relationship("ProjectStar", back_populates="project")
    invites = relationship("ProjectInvite", back_populates="project")

    __table_args__ = (
        Index(
            "unique_name_for_non_deleted",
            name,
            deleted,
            unique=True,
            postgresql_where=(not_(deleted)),
        ),
    )


class ProjectStar(Base):
    __tablename__ = "project_star"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now(), default=func.now())

    user_id = Column(UUID, nullable=False)
    project_id = Column(UUID, ForeignKey("project.id"))
    project = relationship("Project", back_populates="project_stars")


class Plan(Base):
    __tablename__ = "plan"

    id = Column(Integer, primary_key=True, default=uuid.uuid4)
    name = Column(String(50), nullable=False, unique=True, index=True)
    price = Column(Float, nullable=False)
    features = Column(JSON, nullable=False)
    virtual_labs = relationship("VirtualLab", back_populates="plan")


class ProjectInvite(Base):
    __tablename__ = "project_invite"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    inviter_id = Column(UUID(as_uuid=True), nullable=False)
    user_id = Column(UUID(as_uuid=True))
    accepted = Column(Boolean)
    user_email = Column(String, nullable=False)
    role = Column(String, nullable=False)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now(), default=func.now())

    project_id = Column(UUID(as_uuid=True), ForeignKey("project.id"))
    project = relationship("Project", back_populates="invites")


class VirtualLabInvite(Base):
    __tablename__ = "virtual_lab_invite"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    inviter_id = Column(UUID, nullable=False)
    user_id = Column(UUID)
    role = Column(String, nullable=False)
    user_email = Column(String, nullable=False)
    virtual_lab_id = Column(UUID, ForeignKey("virtual_lab.id"))
    virtual_lab = relationship("VirtualLab", back_populates="invites")

    accepted = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now(), default=func.now())


# class PaymentCard(Base):
#     __tablename__ = "payment_card"

#     id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
#     cardNumber = Column(String(19))
#     expiration_date = Column(DateTime)

#     created_at = Column(DateTime, default=datetime.utcnow)
#     updated_at = Column(DateTime, onupdate=datetime.utcnow)

#     virtual_lab_id = Column(
#         "virtual_lab_id", UUID(as_uuid=True), ForeignKey("virtual_lab.id")
#     )
#     virtual_lab = relationship("VirtualLab")


# class Billing(Base):
#     __tablename__ = "billing"

#     id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

#     payment_card_id = Column(
#         "payment_card_id", UUID(as_uuid=True), ForeignKey("payment_card.id")
#     )
#     payment_card = relationship("PaymentCard")
