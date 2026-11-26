#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("export_public_snapshot", Path(__file__).with_name("export-public-snapshot.py"))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.public = self.root / "public"
        self.private = self.root / "private"
        self.public.mkdir()
        self.private.mkdir()
        for repo in (self.public, self.private):
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.email", "fixture@example.invalid")
            self.git(repo, "config", "user.name", "Fixture")
            self.git(repo, "config", "core.autocrlf", "false")
            (repo / "README.md").write_bytes(b"old\n")
            (repo / "retired.txt").write_bytes(b"retire\n")
            (repo / "asset.bin").write_bytes(b"\x00\xffold")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "Baseline")
        self.base = self.git(self.public, "rev-parse", "HEAD").decode().strip()
        (self.private / "README.md").write_bytes(b"new\n")
        (self.private / "retired.txt").unlink()
        (self.private / "asset.bin").write_bytes(b"\x00\xffnew")
        (self.private / "private-only.txt").write_bytes(b"DO NOT EXPORT\n")
        (self.private / "approved.txt").write_bytes(b"new public file\n")
        self.git(self.private, "add", "-A")
        self.git(self.private, "commit", "-qm", "Changed")
        self.source = self.git(self.private, "rev-parse", "HEAD").decode().strip()

    def git(self, repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    def plan(self, additions=()):
        return exporter.plan(self.private, self.public, self.source, self.base, additions)

    def test_export_uses_only_reviewed_paths_and_applies_exactly(self):
        plan = self.plan(["approved.txt"])
        self.assertEqual(plan["excluded_new_path_count"], 1)
        self.assertEqual([r["path"] for r in plan["changes"]],
                         ["README.md", "approved.txt", "asset.bin", "retired.txt"])
        review = exporter.encode(plan)
        patch = exporter.export(self.private, self.public, review, exporter.digest(review))
        self.assertNotIn(b"private-only", patch)
        self.assertNotIn(b"DO NOT EXPORT", patch)
        output = self.root / "review.patch"
        exporter.write_new(output, patch)
        self.git(self.public, "apply", "--check", "--index", str(output))
        self.git(self.public, "apply", "--index", str(output))
        self.assertEqual((self.public / "README.md").read_bytes(), b"new\n")
        self.assertEqual((self.public / "asset.bin").read_bytes(), b"\x00\xffnew")
        self.assertEqual((self.public / "approved.txt").read_bytes(), b"new public file\n")
        self.assertFalse((self.public / "retired.txt").exists())
        self.assertFalse((self.public / "private-only.txt").exists())

    def test_wrong_review_and_tampered_plan_fail(self):
        plan = self.plan()
        review = exporter.encode(plan)
        with self.assertRaises(ValueError):
            exporter.export(self.private, self.public, review, "0" * 64)
        plan["changes"].clear()
        bad = exporter.encode(plan)
        with self.assertRaises(ValueError):
            exporter.export(self.private, self.public, bad, exporter.digest(bad))

    def test_default_excludes_all_private_only_paths(self):
        self.assertEqual(self.plan()["excluded_new_path_count"], 2)
        with self.assertRaises(ValueError):
            self.plan(["missing.txt"])
        with self.assertRaises(ValueError):
            exporter.validate_paths(["a", "A/b"])

    def test_refuses_moving_refs_and_existing_output(self):
        with self.assertRaises(ValueError):
            exporter.tree(self.private, "HEAD")
        output = self.root / "exists"
        exporter.write_new(output, b"original")
        with self.assertRaises(FileExistsError):
            exporter.write_new(output, b"replacement")
        self.assertEqual(output.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
