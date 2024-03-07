from typing import List
from pydantic import UUID4
from sqlalchemy.orm import Session
import uuid
from sqlalchemy.sql import func
from virtual_labs.domain import labs
from virtual_labs.infrastructure.db.models import VirtualLab


def get_all_virtual_lab_for_user(db: Session) -> List[VirtualLab]:
    return db.query(VirtualLab).all()


def get_virtual_lab(db: Session, lab_id: UUID4) -> VirtualLab:
    return db.query(VirtualLab).filter(VirtualLab.id == lab_id).one()


def create_virtual_lab(db: Session, lab: labs.VirtualLabCreate) -> VirtualLab:
    db_lab = VirtualLab(
        name=lab.name,
        description=lab.description,
        reference_email=lab.reference_email,
        nexus_organization_id=uuid.uuid4(),
        projects=[],
    )

    db.add(db_lab)
    db.commit()

    return db_lab


def update_virtual_lab(
    db: Session, lab_id: UUID4, lab: labs.VirtualLabUpdate
) -> VirtualLab:
    query = db.query(VirtualLab).filter(VirtualLab.id == lab_id)
    current = query.one()

    updated_data = lab.model_dump(exclude_unset=True)
    query.update(
        {
            "name": updated_data.get("name", current.name),
            "description": updated_data.get("description", current.description),
            "reference_email": updated_data.get(
                "reference_email", current.reference_email
            ),
            "updated_at": func.now(),
        }
    )
    db.commit()
    return current


def delete_virtual_lab(db: Session, lab_id: UUID4) -> VirtualLab:
    lab = get_virtual_lab(db, lab_id)
    db.delete(lab)
    db.commit()
    return lab