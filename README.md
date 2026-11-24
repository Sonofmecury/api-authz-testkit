# API authorization testkit

Verify the access policy for an application you maintain. The tool expands an explicit actor × resource × action matrix and checks each result against an application adapter. The example has 45 cases covering anonymous access, ownership, tenant isolation, administrator functions, returned properties and unintended writes.

**Run:** Python 3.11+, no dependencies.

```sh
python demo.py
python -m unittest discover -v
```

The demo prints a JSON report and exits with code 1 when any case fails.

## Integrate

1. Define named fixture actors, resources and actions. Write grants independently of the implementation; all remaining combinations are denied.
2. In the application’s existing integration tests, implement a callback that accepts a `Case` and returns a `Decision`. Use the framework’s in-process test client if the route boundary matters. Create fresh test state for each invocation. Map actual authorization, visible field names and a before/after storage check into the decision.
3. Configure allowed response field names by action, then call `evaluate`. Treat an adapter exception as a test error. Configure CI to fail if any row carries an issue.

## Coverage and limits

The demo adapter is a fictional service policy. It does not establish coverage of a deployed API. This project exercises authored contracts without taking a target URL, performing endpoint discovery or running against live services. Token validation, rate limits and OpenAPI schema compatibility belong in first-party application tests. Reports show case names and outcomes without copying data or credentials.
