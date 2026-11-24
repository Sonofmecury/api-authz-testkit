"""Evaluate an explicit access matrix against a first-party application callback."""
from dataclasses import dataclass
from itertools import product
from typing import Callable


@dataclass(frozen=True)
class Case:
    actor: str
    resource: str
    action: str
    allowed: bool


@dataclass(frozen=True)
class Decision:
    allowed: bool
    fields: frozenset[str] = frozenset()
    changed: bool = False


def matrix(actors: list[str], resources: list[str], actions: list[str],
           grants: set[tuple[str, str, str]]) -> list[Case]:
    for dimension in (actors, resources, actions):
        if not dimension or len(set(dimension)) != len(dimension):
            raise ValueError("Matrix dimensions must be nonempty and unique")
    combinations = set(product(actors, resources, actions))
    if grants - combinations:
        raise ValueError("A grant references an unknown actor, resource or action")
    return [Case(*key, key in grants) for key in sorted(combinations)]


def evaluate(cases: list[Case], decide: Callable[[Case], Decision],
             visible_fields: dict[str, set[str]]) -> list[dict]:
    """Return decisions only. Never serialize response bodies or credentials."""
    results = []
    for case in cases:
        if case.action not in visible_fields:
            raise ValueError(f"Missing field policy for {case.action}")
        decision = decide(case)
        if not isinstance(decision, Decision):
            raise TypeError("Adapter must return a Decision")
        issues = []
        if decision.allowed != case.allowed:
            issues.append("unexpected_access_decision")
        if decision.fields - (visible_fields[case.action] if case.allowed else set()):
            issues.append("unexpected_visible_fields")
        if decision.changed and (not case.allowed or case.action == "read"):
            issues.append("unexpected_state_change")
        if case.allowed and case.action == "update" and not decision.changed:
            issues.append("expected_state_change_missing")
        results.append({"actor": case.actor, "resource": case.resource,
                        "action": case.action, "expected_allow": case.allowed,
                        "observed_allow": decision.allowed, "issues": issues})
    return results
