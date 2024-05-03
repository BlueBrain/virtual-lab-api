from virtual_labs.domain.labs import VirtualLabDetails
from virtual_labs.infrastructure.db.models import VirtualLab
from virtual_labs.shared.utils.get_one_lab_admin import get_one_lab_admin


def db_lab_to_domain_lab(lab: VirtualLab) -> VirtualLabDetails:
    an_admin = get_one_lab_admin(lab)

    params = dict(
        id=lab.id,
        name=lab.name,
        description=lab.description,
        reference_email=lab.reference_email,
        budget=lab.budget,
        entity=lab.entity,
        plan_id=lab.plan_id,
        nexus_organization_id=lab.nexus_organization_id,
        created_at=lab.created_at,
        updated_at=lab.updated_at,
        admin=an_admin,
    )

    return VirtualLabDetails.model_validate(params)
