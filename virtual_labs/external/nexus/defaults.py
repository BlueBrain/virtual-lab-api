from typing import Any, Dict, List

from virtual_labs.external.nexus.models import (
    NexusApiMapping,
    NexusIdentity,
    ProjectView,
)
from virtual_labs.infrastructure.settings import settings

AGGREGATE_SPARQL_VIEW = ["View", "AggregateSparqlView"]
AGGREGATE_ELASTIC_SEARCH_VIEW = ["View", "AggregateElasticSearchView"]
ELASTIC_SEARCH_VIEW = ["View", "ElasticSearchView"]
CROSS_RESOLVER: List[str] = ["Resolver", "CrossProject"]
PROJECTS_TO_AGGREGATE = ["bbp/atlas"]
ES_RESOURCE_TYPE: List[str] = [
    "http://www.w3.org/ns/prov#Entity",
    "http://schema.org/Dataset",
    "http://www.w3.org/ns/prov#Activity",
    "http://www.w3.org/ns/prov#Agent",
]

ES_VIEW_ID = "https://bbp.epfl.ch/neurosciencegraph/data/views/es/dataset"
SP_VIEW_ID = "https://bluebrain.github.io/nexus/vocabulary/defaultSparqlIndex"
AG_ES_VIEW_ID = "https://bbp.epfl.ch/neurosciencegraph/data/views/aggreg-es/dataset"
AG_SP_VIEW_ID = "https://bbp.epfl.ch/neurosciencegraph/data/views/aggreg-sp/dataset"

ES_VIEWS = [ProjectView(project=pr, viewId=ES_VIEW_ID) for pr in PROJECTS_TO_AGGREGATE]
SP_VIEWS = [{"project": f"{pr}", "viewId": SP_VIEW_ID} for pr in PROJECTS_TO_AGGREGATE]

API_MAPPING: List[NexusApiMapping] = []

DEFAULT_RESOLVER_PRIORITY = 50
DEFAULT_PROJECT_VOCAB = "https://bbp.epfl.ch/ontologies/core/bmo/"
DEFAULT_API_MAPPING_RESOURCE = "https://bbp.epfl.ch/nexus/v1/resources/neurosciencegraph/datamodels/_/nexus_api_mappings"
DEFAULT_API_MAPPING: List[NexusApiMapping] = [
    {"namespace": "https://neuroshapes.org/dash/", "prefix": "datashapes"},
    {"namespace": "https://neuroshapes.org/dash/ontology", "prefix": "ontologies"},
    {
        "namespace": "https://incf.github.io/neuroshapes/contexts/",
        "prefix": "context",
    },
    {"namespace": "https://provshapes.org/commons/", "prefix": "provcommonshapes"},
    {"namespace": "https://neuroshapes.org/commons/", "prefix": "commonshapes"},
    {"namespace": "https://provshapes.org/datashapes/", "prefix": "provdatashapes"},
    {
        "namespace": "https://bluebrain.github.io/nexus/vocabulary/defaultElasticSearchIndex",
        "prefix": "documents",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/vocabulary/defaultInProject",
        "prefix": "defaultResolver",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/shacl-20170720.ttl",
        "prefix": "schema",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/unconstrained.json",
        "prefix": "resource",
    },
    {"namespace": "https://neuroshapes.org/dash/taxonomy", "prefix": "taxonomies"},
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/unconstrained.json",
        "prefix": "_",
    },
    {"namespace": "http://schema.org/", "prefix": "schemaorg"},
    {"namespace": "https://bluebrain.github.io/nexus/vocabulary/", "prefix": "nxv"},
    {"namespace": "http://www.w3.org/ns/prov#", "prefix": "prov"},
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/storages.json",
        "prefix": "storage",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/files.json",
        "prefix": "file",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/resolvers.json",
        "prefix": "resolver",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/vocabulary/defaultSparqlIndex",
        "prefix": "graph",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/archives.json",
        "prefix": "archive",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/vocabulary/diskStorageDefault",
        "prefix": "defaultStorage",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/schemas/views.json",
        "prefix": "view",
    },
    {
        "namespace": "https://bluebrain.github.io/nexus/vocabulary/searchView",
        "prefix": "search",
    },
]


def prep_project_base(virtual_lab_id: str, project_id: str) -> str:
    return f"{settings.DEPLOYMENT_NAMESPACE}/data/{virtual_lab_id}/{project_id}/"


def prep_subtract_identity(
    realm: str,
    user: str,
) -> NexusIdentity:
    return {"realm": realm, "subject": user}


def prep_default_local_context(vocab: str) -> Dict[str, Any]:
    return {
        "@context": ["https://neuroshapes.org", {"@vocab": vocab}],
        "@id": "https://bbp.neuroshapes.org",
    }
