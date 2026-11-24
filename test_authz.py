import unittest

from authz import Case, Decision, evaluate, matrix
from demo import adapter, run


class ContractTest(unittest.TestCase):
    def test_all_45_explicit_access_cases(self):
        rows = run()
        self.assertEqual(len(rows), 45)
        self.assertEqual(sum(row["expected_allow"] for row in rows), 12)
        self.assertEqual([row for row in rows if row["issues"]], [])

    def test_response_and_write_invariants(self):
        case = Case("fixture-reader", "fixture-record", "read", False)
        rows = evaluate([case], lambda _: Decision(False, frozenset({"title"}), True),
                        {"read": {"title"}})
        self.assertEqual(rows[0]["issues"], ["unexpected_visible_fields", "unexpected_state_change"])

    def test_update_requires_state_change(self):
        case = Case("fixture-editor", "fixture-record", "update", True)
        rows = evaluate([case], lambda _: Decision(True), {"update": set()})
        self.assertEqual(rows[0]["issues"], ["expected_state_change_missing"])

    def test_unknown_policy_reference(self):
        with self.assertRaises(ValueError):
            matrix(["reader"], ["report"], ["read"], {("unknown", "report", "read")})

    def test_admin_cannot_cross_tenants(self):
        self.assertFalse(adapter(Case("admin", "bob-report", "export", False)).allowed)
