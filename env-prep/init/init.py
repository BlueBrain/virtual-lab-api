# type: ignore
import http.client
import json
import logging
import os

import requests

acls_payload = {
    "@type": "Append",
    "acl": [
        {
            "identity": {
                "realm": "obp-realm",
                "subject": "service-account-obpapp",
                "@type": "User",
            },
            "permissions": [
                "acls/read",
                "acls/write",
                "events/read",
                "export/run",
                "files/write",
                "organizations/create",
                "organizations/read",
                "organizations/write",
                "permissions/read",
                "permissions/write",
                "projects/create",
                "projects/delete",
                "projects/read",
                "projects/write",
                "quotas/read",
                "realms/read",
                "realms/write",
                "resolvers/write",
                "resources/read",
                "resources/write",
                "schemas/write",
                "storages/write",
                "supervision/read",
                "typehierarchy/write",
                "version/read",
                "views/query",
                "views/write",
            ],
        }
    ],
}

public_project_acl = {
    "@type": "Append",
    "acl": [
        {
            "identity": {
                "realm": "obp-realm",
                "@type": "Authenticated",
            },
            "permissions": [
                "export/run",
                "organizations/read",
                "permissions/read",
                "projects/read",
                "quotas/read",
                "realms/read",
                "resources/read",
                "supervision/read",
                "version/read",
                "views/query",
            ],
        }
    ],
}


org_payload = json.dumps({"description": "organization"})
project_payload = json.dumps({"description": "organization"})


KC_SERVER_URI = "http://localhost:9090/"
KC_USER_NAME = "admin"
KC_PASSWORD = "admin"
KC_CLIENT_ID = "obpapp"
KC_CLIENT_SECRET = "obp-secret"
KC_REALM_NAME = "obp-realm"
NEXUS_BASEURL = "http://localhost:8080"


def print_response(nexus_conn):
    print(nexus_conn.getresponse().read().decode("utf-8"), "\n")


nexus_conn = http.client.HTTPConnection("localhost", 8080)
kc_conn = http.client.HTTPConnection("localhost", 9090)
__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

params = "scope=openid&grant_type=client_credentials"
headers = {
    "Authorization": "basic b2JwYXBwOm9icC1zZWNyZXQ=",
    "Content-Type": "application/x-www-form-urlencoded",
}

kc_conn.request(
    "POST",
    f"{KC_SERVER_URI}/realms/{KC_REALM_NAME}/protocol/openid-connect/token",
    params,
    headers,
)

client_data = json.loads((kc_conn.getresponse().read()).decode("utf-8"))
client_token = client_data["access_token"]
print("CLIENT_TOKEN:\n", client_token, "\n")

params = "client_id={}&client_secret={}&username={}&password={}&grant_type={}&scope=openid".format(
    KC_CLIENT_ID, KC_CLIENT_SECRET, "test", "test", "password"
)

kc_conn.request(
    "POST",
    f"{KC_SERVER_URI}/realms/{KC_REALM_NAME}/protocol/openid-connect/token",
    params,
    headers,
)

user_data = json.loads((kc_conn.getresponse().read()).decode("utf-8"))
user_token = user_data["access_token"]
print("USER_TOKEN:\n", user_token, "\n")

client_headers = {
    "Authorization": f"bearer {client_token}",
    "Content-Type": "application/json",
}

# print("---- #0 get test user id 'subject'")
# kc_conn.request(
#     "GET",
#     f"{KC_SERVER_URI}/admin/realms/{KC_REALM_NAME}/users?username=test&exact=true",
#     headers=client_headers,
# )

# user_data = json.loads((kc_conn.getresponse().read()).decode("utf-8"))
# user_id = user_data[0]["id"]
# print("USER_TOKEN:\n", user_id, "\n")


print("---- #1 append ACLs to the nexus client \n")
nexus_conn.request("PATCH", "/v1/acls", json.dumps(acls_payload), client_headers)
print_response(nexus_conn)


print("---- #2 create neurosciencegraph/datamodels (org/project) \n")
nexus_conn.request("PUT", "/v1/orgs/neurosciencegraph", org_payload, client_headers)
print_response(nexus_conn)

nexus_conn.request(
    "PUT", "/v1/projects/neurosciencegraph/datamodels", project_payload, client_headers
)
print_response(nexus_conn)

nexus_conn.request(
    "PATCH",
    "/v1/acls/neurosciencegraph/datamodels?rev=1",
    json.dumps(public_project_acl),
    client_headers,
)
print_response(nexus_conn)


print("---- #3- create bbp/atlas org/project \n")
nexus_conn.request("PUT", "/v1/orgs/bbp", org_payload, client_headers)
print_response(nexus_conn)

nexus_conn.request("PUT", "/v1/projects/bbp/atlas", project_payload, client_headers)
print_response(nexus_conn)

nexus_conn.request(
    "PATCH", "/v1/acls/bbp/atlas?rev=1", json.dumps(public_project_acl), client_headers
)
print_response(nexus_conn)


def log_nexus_response(
    response: requests.Response, message: str = "Response is", warning_message: str = ""
):
    if response.status_code >= 200 and response.status_code <= 300:
        logging.info(f"{message} : {response.json()}")
    else:
        logging.warning(f"Error in dev setup. {warning_message} : {response.json()}")


print("---- #4- Setup bbp/agents project \n")
AGENTS_SETUP_WARNING = "This might affect agents feature"
response = requests.put(
    url=f"{NEXUS_BASEURL}/v1/projects/bbp/agents",
    headers=client_headers,
    data=json.dumps({"description": "description"}),
)
log_nexus_response(
    response=response,
    message="Agent project creation",
    warning_message=AGENTS_SETUP_WARNING,
)

response = requests.patch(
    url=f"{NEXUS_BASEURL}/v1/acls/bbp/agents?rev=1",
    headers=client_headers,
    data=json.dumps(public_project_acl),
)
log_nexus_response(
    response=response,
    message="Agent project - acls",
    warning_message=AGENTS_SETUP_WARNING,
)

with open(os.path.join(__location__, "neuroshapes_org_resource.json")) as f:
    data = json.dumps(json.load(f))
    response = requests.put(
        url=f"{NEXUS_BASEURL}/v1/resources/bbp/agents/_/https%3A%2F%2Fneuroshapes.org",
        data=data,
        headers=client_headers,
    )
    log_nexus_response(
        response=response,
        message="Agents project - neuroshapes.org resource",
        warning_message=AGENTS_SETUP_WARNING,
    )


response = requests.post(
    url=f"{NEXUS_BASEURL}/v1/resources/bbp/agents/_",
    headers=client_headers,
    data=json.dumps(
        {
            "@context": [
                "https://neuroshapes.org",
                {"@vocab": "https://bbp.epfl.ch/ontologies/core/bmo/"},
            ],
            "@id": "https://bbp.neuroshapes.org",
        }
    ),
)
log_nexus_response(
    response=response,
    message="Agents project - context",
    warning_message=AGENTS_SETUP_WARNING,
)

with open(os.path.join(__location__, "bbp-agents-schemas/person_shape.json")) as f:
    data = json.dumps(json.load(f))

    response = requests.post(
        url=f"{NEXUS_BASEURL}/v1/schemas/bbp/agents",
        headers=client_headers,
        data=data,
    )
    log_nexus_response(
        response=response,
        message="Agents project - person shape",
        warning_message=AGENTS_SETUP_WARNING,
    )

print("bbp/agents setup done.")
# -------------------------------------bbp/agents setup done----------------------------------------------------

print("---- #5 create dataset es view for  neurosciencegraph/datamodels \n")
with open(os.path.join(__location__, "es_view_dataset_payload.json")) as f:
    data = json.dumps(json.load(f))

    nexus_conn.request(
        "POST",
        "/v1/views/neurosciencegraph/datamodels",
        data,
        client_headers,
    )
    print_response(nexus_conn)

print("---- #5 create dataset es view for  bbp/atlas \n")
with open(os.path.join(__location__, "es_view_dataset_payload.json")) as f:
    data = json.dumps(json.load(f))

    nexus_conn.request(
        "POST",
        "/v1/views/bbp/atlas",
        data,
        client_headers,
    )
    print_response(nexus_conn)


print("---- #6 create neuroshapes.org resource\n")
with open(os.path.join(__location__, "neuroshapes_org_resource.json")) as f:
    data = json.dumps(json.load(f))
    nexus_conn.request(
        "PUT",
        "/v1/resources/neurosciencegraph/datamodels/_/https%3A%2F%2Fneuroshapes.org",
        data,
        client_headers,
    )
    print_response(nexus_conn)


print("---- #7 create api_mapping_resource\n")
with open(os.path.join(__location__, "api_mappings_payload.json")) as f:
    data = json.dumps(json.load(f))
    nexus_conn.request(
        "PUT",
        "/v1/resources/neurosciencegraph/datamodels/_/https%3A%2F%2Fbbp.epfl.ch%2Fnexus%2Fv1%2Fresources%2Fneurosciencegraph%2Fdatamodels%2F_%2Fnexus_api_mappings",
        data,
        client_headers,
    )
    print_response(nexus_conn)


print("\n------END------\n")
