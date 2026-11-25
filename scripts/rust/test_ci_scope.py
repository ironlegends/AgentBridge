import unittest
from unittest.mock import patch
import subprocess
import ci_scope as scope


class ScopeTests(unittest.TestCase):
    def test_docs_only_and_identical_tree(self):
        for paths in ([], ["README.md", "docs/plan.md", "docs/a/b.md"]):
            self.assertEqual(scope.choose_lane("pull_request", False, "", paths), "hygiene")
            self.assertEqual(scope.choose_lane("push", False, "", paths), "hygiene")

    def test_ci_policy_only(self):
        self.assertEqual(scope.choose_lane("pull_request", False, "", list(scope.LIGHTWEIGHT)), "hygiene")

    def test_unknown_paths_and_mixed_changes_are_quick(self):
        for path in ["rust/cli/src/lib.rs", "app/src-tauri/Cargo.lock", "native/helper.cs",
                     "docs/image.png", "scripts/rust/package-rust.py", "docs/../README.md",
                     "README.md.bak", "new-component", "Cargo.lock"]:
            self.assertEqual(scope.choose_lane("pull_request", False, "", ["docs/plan.md", path]), "quick")

    def test_draft_only_hygiene_until_ready(self):
        for paths in (None, ["rust/cli/src/lib.rs"]):
            self.assertEqual(scope.choose_lane("pull_request", True, "", paths), "hygiene")
            self.assertEqual(scope.choose_lane("pull_request", False, "", paths), "quick")

    def test_unknown_boundary_is_not_documentation(self):
        for event in ("push", "pull_request"):
            self.assertEqual(scope.choose_lane(event, False, "", None), "quick")

    def test_only_explicit_dispatch_selects_full(self):
        for event in ("push", "pull_request"):
            self.assertNotEqual(scope.choose_lane(event, False, "full", None), "full")
        self.assertEqual(scope.choose_lane("workflow_dispatch", False, "full", None), "full")
        self.assertEqual(scope.choose_lane("workflow_dispatch", False, "quick", None), "quick")
        with self.assertRaises(ValueError):
            scope.choose_lane("workflow_dispatch", False, "unknown", None)

    def test_invalid_event_fails_closed(self):
        with self.assertRaises(ValueError):
            scope.choose_lane("schedule", False, "", [])

    def test_invalid_sha_never_executes_git(self):
        with patch("ci_scope.subprocess.check_output") as call:
            for base in ("", "0"*40, "--help", "main"):
                self.assertIsNone(scope.changed_paths(base, "b"*40))
            call.assert_not_called()

    def test_nonmatching_head_is_unknown(self):
        with patch("ci_scope.subprocess.check_output", return_value="c"*40) as call:
            self.assertIsNone(scope.changed_paths("a"*40, "b"*40))
            self.assertEqual(call.call_count, 1)

    def test_diff_includes_deletions_and_does_not_split_newlines(self):
        with patch("ci_scope.subprocess.check_output", side_effect=["b"*40, b"rust/old.rs\0docs/new\nname.md\0"]) as call:
            paths = scope.changed_paths("a"*40, "b"*40)
            self.assertEqual(paths, ["rust/old.rs", "docs/new\nname.md"])
            self.assertIn("--no-renames", call.call_args.args[0])
            self.assertEqual(scope.choose_lane("push", False, "", paths), "quick")

    def test_git_failure_and_bad_encoding_fall_back(self):
        for result in (subprocess.CalledProcessError(128, "git"), b"\xff\0"):
            with patch("ci_scope.subprocess.check_output", side_effect=["b"*40, result]):
                self.assertIsNone(scope.changed_paths("a"*40, "b"*40))


if __name__ == "__main__":
    unittest.main()
