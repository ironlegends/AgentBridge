#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A separate Tauri workspace must retain the enclosing project's notices."""
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("desktop_release_notices", Path(__file__).with_name("release-notices.py"))
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)


class DesktopNotices(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "project"
        self.app = self.root / "app/src-tauri"
        self.crate = self.root / "rust/core"
        self.vendor = self.root.parent / "registry/third-party"
        for directory in (self.root, self.app, self.crate, self.vendor):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "Cargo.toml").write_text("[package]\n")
        (self.root / "LICENSE").write_text("Apache License Version 2.0\n")
        (self.root / "NOTICE").write_text("Agent Bridge\n")
        (self.vendor / "LICENSE").write_text("Third-party MIT attribution\n")
        packages = [self.package("app", "agent-bridge-desktop-app", self.app), self.package("core", "agent-bridge-core", self.crate),
                    self.package("vendor", "third-party", self.vendor, "registry+test")]
        self.application = {"workspace_root": str(self.app), "workspace_members": ["app"], "packages": packages,
                            "resolve": {"nodes": [{"id": "app", "deps": [{"pkg": "core"}, {"pkg": "vendor"}]},
                                                  {"id": "core", "deps": []}, {"id": "vendor", "deps": []}]}}
        self.enclosing = {"workspace_root": str(self.root), "workspace_members": ["core"], "packages": packages[1:]}

    def package(self, ident, name, root, source=None):
        return {"id": ident, "name": name, "version": "1.0.0", "manifest_path": str(root / "Cargo.toml"),
                "license": "MIT" if source else "Apache-2.0", "source": source}

    def collect(self, enclosing=None):
        output = self.root.parent / "notices"
        def metadata(manifest, target):
            return self.application if manifest.parent == self.app else (enclosing or self.enclosing)
        with patch.object(NOTICES, "cargo_metadata", side_effect=metadata), contextlib.redirect_stdout(io.StringIO()):
            status = NOTICES.main(["--manifest-path", str(self.app / "Cargo.toml"), "--package", "agent-bridge-desktop-app",
                                  "--project-root", str(self.root), "--target", "x86_64-pc-windows-msvc", "--out-dir", str(output)])
        self.assertEqual(status, 0)
        return output, json.loads((output / "index.json").read_text())

    def test_separate_app_keeps_project_attribution_and_third_party_notices(self):
        output, index = self.collect()
        self.assertEqual((output / "notices/LICENSE").read_bytes(), (self.root / "LICENSE").read_bytes())
        self.assertEqual((output / "notices/NOTICE").read_bytes(), (self.root / "NOTICE").read_bytes())
        packages = {p["name"]: p for p in index["packages"]}
        self.assertTrue(packages["agent-bridge-core"]["workspace"])
        self.assertFalse(packages["third-party"]["workspace"])
        self.assertEqual(len(packages["third-party"]["notices"]), 1)
        self.assertEqual(index["to_verify"], [])

    def test_foreign_member_cannot_be_promoted_to_first_party(self):
        foreign = {**self.enclosing, "workspace_members": ["core", "vendor"]}
        with self.assertRaisesRegex(ValueError, "(member|project)"):
            self.collect(foreign)


if __name__ == "__main__":
    unittest.main()
