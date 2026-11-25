"""Tests for the exact-test qualification receipt gate."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import qualification_inventory as gate


CANDIDATE = "a" * 40
BINARY = "b" * 64
TEST = "module::parent"
FIXTURE = "module::child_fixture"


class QualificationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = {
            "schema": 1, "candidate": CANDIDATE,
            "suites": [{
                "id": "cli-windows", "platform": "windows",
                "binary_sha256": BINARY,
                "discovered": [TEST, FIXTURE],
                "required": [TEST],
                "fixtures": {FIXTURE: [TEST]},
            }],
        }
        self.receipt = {"schema": 1, "candidate": CANDIDATE, "results": []}
        self.add_log(
            "parent.log",
            f"running 1 test\n"
            f"test {TEST} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; "
            "0 measured; 1 filtered out; finished in 0.01s\n",
        )

    def add_log(self, name, content):
        raw = content.encode()
        (self.root / name).write_bytes(raw)
        self.receipt["results"] = [{
            "suite": "cli-windows", "test": TEST,
            "binary_sha256": BINARY, "exit_code": 0,
            "log": name, "log_sha256": hashlib.sha256(raw).hexdigest(),
        }]

    def check(self):
        return gate.verify(self.plan, self.receipt, self.root, CANDIDATE)

    def test_parent_proof_covers_only_declared_fixture(self):
        result = self.check()
        self.assertEqual(result["required"], 1)
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["fixtures"], 1)

    def test_missing_required_receipt_fails(self):
        self.receipt["results"] = []
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_duplicate_receipts_are_not_a_pass(self):
        self.receipt["results"] *= 2
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_wrong_candidate_is_rejected(self):
        self.receipt["candidate"] = "c" * 40
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_wrong_binary_is_rejected(self):
        self.receipt["results"][0]["binary_sha256"] = "c" * 64
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_ignored_or_zero_tests_cannot_be_success(self):
        for summary in (
            "ok. 0 passed; 0 failed; 1 ignored;",
            "ok. 0 passed; 0 failed; 0 ignored;",
            "FAILED. 0 passed; 1 failed; 0 ignored;",
        ):
            with self.subTest(summary=summary):
                self.add_log("parent.log", f"running 1 test\n"
                             f"test {TEST} ... ignored\n"
                             f"test result: {summary} 0 measured; 0 filtered out;\n")
                with self.assertRaises(gate.QualificationError):
                    self.check()

    def test_other_test_is_not_evidence(self):
        self.add_log("parent.log", "running 1 test\ntest other ... ok\n"
                     "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;\n")
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_nonzero_exit_fails_even_with_green_text(self):
        self.receipt["results"][0]["exit_code"] = 1
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_changed_log_is_rejected(self):
        (self.root / "parent.log").write_text("tampered")
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_unclassified_discovered_test_fails(self):
        self.plan["suites"][0]["discovered"].append("module::new")
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_fixture_needs_a_real_required_parent(self):
        self.plan["suites"][0]["fixtures"][FIXTURE] = ["unknown"]
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_unknown_suite_and_escaping_log_are_rejected(self):
        for field, value in (("suite", "unknown"), ("log", "../parent.log")):
            with self.subTest(field=field):
                original = copy.deepcopy(self.receipt)
                self.receipt["results"][0][field] = value
                with self.assertRaises(gate.QualificationError):
                    self.check()
                self.receipt = original

    def test_zero_suites_does_not_pass(self):
        self.plan["suites"] = []
        self.receipt["results"] = []
        with self.assertRaises(gate.QualificationError):
            self.check()

    def test_unexpected_extra_result_is_not_accepted(self):
        extra = copy.deepcopy(self.receipt["results"][0])
        extra["test"] = FIXTURE
        self.receipt["results"].append(extra)
        with self.assertRaises(gate.QualificationError):
            self.check()


if __name__ == "__main__":
    unittest.main()
