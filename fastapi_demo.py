"""A disposable, in-process API for exercising the authorization contract."""
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from authz import Decision
from demo import ACTORS, RECORDS, run


class Update(BaseModel):
    title: str


def build_fixture():
    records = {name: {"title": "Fictional report", "review_status": "pending"}
               for name in RECORDS}
    application = FastAPI()

    def authorize(resource: str, actor: str, admin_only: bool = False):
        if actor == "anonymous":
            raise HTTPException(status_code=401)
        owner, tenant = RECORDS[resource]
        if ACTORS.get(actor) != tenant or (actor != "admin" and (admin_only or actor != owner)):
            raise HTTPException(status_code=404)

    @application.get("/reports/{resource}")
    def read(resource: str, x_fixture_actor: str = Header(default="anonymous")):
        authorize(resource, x_fixture_actor)
        return {"title": records[resource]["title"]}

    @application.patch("/reports/{resource}")
    def update(resource: str, payload: Update, x_fixture_actor: str = Header(default="anonymous")):
        authorize(resource, x_fixture_actor)
        records[resource]["title"] = payload.title
        return {"title": records[resource]["title"]}

    @application.get("/reports/{resource}/export")
    def export(resource: str, x_fixture_actor: str = Header(default="anonymous")):
        authorize(resource, x_fixture_actor, admin_only=True)
        return records[resource].copy()

    return application, records


def first_party_adapter(case):
    application, records = build_fixture()
    before = {key: value.copy() for key, value in records.items()}
    route = f"/reports/{case.resource}"
    headers = {"X-Fixture-Actor": case.actor}
    with TestClient(application) as client:
        if case.action == "read":
            response = client.get(route, headers=headers)
        elif case.action == "update":
            response = client.patch(route, headers=headers, json={"title": "Updated"})
        elif case.action == "export":
            response = client.get(route + "/export", headers=headers)
        else:
            raise ValueError("Unsupported fixture action")
    if response.status_code not in {200, 401, 404}:
        raise ValueError(f"Unexpected fixture status {response.status_code}")
    allowed = response.status_code == 200
    returned = response.json()
    # FastAPI uses one standard field for empty HTTPException details.
    harmless_error = returned == {"detail": "Unauthorized"} or returned == {"detail": "Not Found"}
    fields = frozenset() if not allowed and harmless_error else frozenset(returned)
    return Decision(allowed, fields, before != records)


if __name__ == "__main__":
    results = run(first_party_adapter)
    failures = [row for row in results if row["issues"]]
    print(f"HTTP contract: {len(results)} cases, {len(failures)} failures")
    raise SystemExit(bool(failures))
