import json
from pathlib import Path

from authz import Decision, evaluate, matrix

ACTORS = {"anonymous": None, "amy": "A", "sam": "A", "bob": "B", "admin": "A"}
RECORDS = {"amy-report": ("amy", "A"), "sam-report": ("sam", "A"), "bob-report": ("bob", "B")}
FIELDS = {"read": {"title"}, "update": {"title"}, "export": {"title", "review_status"}}


def adapter(case):
    owner, tenant = RECORDS[case.resource]
    same_tenant = ACTORS[case.actor] == tenant
    admin = case.actor == "admin"
    allowed = same_tenant and (
        (case.action in {"read", "update"} and (case.actor == owner or admin))
        or (case.action == "export" and admin)
    )
    fields = {"title", "review_status"} if case.action == "export" else {"title"}
    return Decision(allowed, frozenset(fields if allowed else ()),
                    allowed and case.action == "update")


def run(decide=adapter):
    policy = json.loads(Path(__file__).with_name("policy.json").read_text(encoding="utf-8"))
    cases = matrix(list(ACTORS), list(RECORDS), list(FIELDS),
                   {tuple(row) for row in policy["allow"]})
    return evaluate(cases, decide, FIELDS)


if __name__ == "__main__":
    rows = run()
    failures = sum(bool(row["issues"]) for row in rows)
    print(json.dumps({"cases": len(rows), "failures": failures, "results": rows}, indent=2))
    raise SystemExit(bool(failures))
