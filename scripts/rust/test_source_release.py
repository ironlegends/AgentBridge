#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source archive fixtures for the independent native desktop workspace."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location(
    "source_release", Path(__file__).with_name("source-release.py")
)
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)

DESKTOP_INPUTS = {
    "app/src-tauri/Cargo.toml": b"[workspace]\n[package]\nname = 'fixture-desktop'\nversion = '1.2.3'\n",
    "app/src-tauri/Cargo.lock": b"# desktop locked dependencies\n",
    "app/src-tauri/build.rs": b"fn main() {}\n",
    "app/src-tauri/tauri.conf.json": b'{"build":{"frontendDist":"../ui"}}\n',
    "app/src-tauri/capabilities/default.json": b'{"permissions":["core:default"]}\n',
    "app/src-tauri/src/main.rs": b"fn main() {}\n",
    "app/src-tauri/src/lib.rs": b"pub fn run() {}\n",
    "app/src-tauri/src/supervisor.rs": b"pub fn inspect() {}\n",
    "app/src-tauri/src/supervisor_tests.rs": b"#[test] fn fixture() {}\n",
    "app/src-tauri/icons/32x32.png": b"tracked icon 32",
    "app/src-tauri/icons/128x128.png": b"tracked icon 128",
    "app/src-tauri/icons/128x128@2x.png": b"tracked icon 256",
    "app/src-tauri/icons/icon.png": b"tracked primary icon",
    "app/src-tauri/icons/icon.ico": b"tracked Windows icon",
    "app/ui/index.html": b"<html><script src='app.js'></script></html>\n",
    "app/ui/app.js": b"document.title = 'fixture';\n",
    "app/ui/styles.css": b"body { margin: 0; }\n",
    "app/tests/live-profile.test.cjs": b"require('node:test')('fixture', () => {});\n",
}
EXCLUDED = (
    "app/src-tauri/target/compiled.rs",
    "app/src-tauri/vendor/dependency/src/lib.rs",
    "app/src-tauri/src/target/generated.rs",
    "app/src-tauri/src/.cache/generated.rs",
    "app/src-tauri/gen/schemas/desktop-schema.json",
    "app/ui/node_modules/dependency/index.js",
    "app/ui/vendor/library.js",
    "app/ui/.cache/runtime.js",
    "app/ui/.env",
    "app/ui/operator-connection.json",
    "app/src-tauri/capabilities/operator-connection.json",
    "app/src-tauri/capabilities/oauth-workstation.json",
    "app/src-tauri/capabilities/tokens.json",
    "app/src-tauri/credentials/private.pem",
    "app/src-tauri/agent-bridge-desktop-app.exe",
    "workers/browser-playwright/.test-state/profile/Cookies",
    "workers/browser-playwright/node_modules/playwright-core/lib/server.js",
    "workers/browser-playwright/tests/.private/credentials.mjs",
    "native/agent-bridge-native/bin/Release/Program.cs",
    "native/agent-bridge-native/obj/generated.cs",
    "native/agent-bridge-native/.state/settings.cs",
)

UNIFIED_INPUTS = {
    "contracts/browser-tools-v1.json": b'{"tools":[]}\n',
    "contracts/windows-tools-v1.json": b'{"tools":[]}\n',
    "workers/browser-playwright/worker.mjs": b"import './protocol.mjs';\n",
    "workers/browser-playwright/package-lock.json": b'{"lockfileVersion":3}\n',
    "workers/browser-playwright/notices/DeskMCP-LICENSE": b"Apache License fixture\n",
    "workers/browser-playwright/tests/worker.test.mjs": b"import 'node:test';\n",
    "native/agent-bridge-native/AgentBridge.Native.csproj": b'<Project Sdk="Microsoft.NET.Sdk"/>\n',
    "native/agent-bridge-native/Program.cs": b"namespace Fixture;\n",
    "native/agent-bridge-native/app.manifest": b"<assembly/>\n",
    "native/agent-bridge-native/notices/DESKMCP-APACHE-2.0.txt": b"Apache License fixture\n",
    "native/agent-bridge-native/tests/helper_protocol.py": b"# fixture\n",
    "scripts/rust/package-browser-worker.py": b"# browser build input\n",
    "scripts/rust/package-native-tools.py": b"# native build input\n",
}


class DesktopSourceArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-bridge-source-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "repository"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        for name in SOURCE.REQUIRED:
            self.write(name, b"source fixture\n")
        self.write("LICENSE", b"Apache License\nVersion 2.0\n")
        self.write("NOTICE", b"Agent Bridge test notice\n")
        self.write("rust/cli/Cargo.toml", b'[package]\nname = "agent-bridge"\nversion = "1.2.3"\n')
        for name, data in DESKTOP_INPUTS.items():
            self.write(name, data)
        self.git("add", "--all")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True, capture_output=True,
        )

    def write(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def archive(self, name):
        output = self.base / name
        with contextlib.redirect_stdout(io.StringIO()):
            result = SOURCE.main(["--repo", str(self.repo), "--output", str(output)])
        self.assertEqual(result, 0)
        return output

    def entries(self, archive):
        with zipfile.ZipFile(archive) as package:
            prefix = "agent-bridge-1.2.3-rust-src/"
            self.assertTrue(all(name.startswith(prefix) for name in package.namelist()))
            return {name.removeprefix(prefix): package.read(name) for name in package.namelist()}

    def test_archive_contains_staged_desktop_sources_locks_configuration_and_assets(self):
        self.write("app/ui/app.js", b"unstaged changes must not enter the archive\n")
        self.write("app/ui/untracked.js", b"untracked changes must not enter the archive\n")
        contents = self.entries(self.archive("desktop.zip"))
        for name, expected in DESKTOP_INPUTS.items():
            with self.subTest(path=name):
                self.assertIn(name, contents)
                self.assertEqual(contents[name], expected)
        self.assertNotIn("app/ui/untracked.js", contents)

    def test_desktop_build_outputs_caches_vendor_and_private_state_are_excluded_even_if_tracked(self):
        for name in EXCLUDED:
            self.write(name, b"private or generated fixture\n")
        self.git("add", "--all")
        contents = self.entries(self.archive("filtered.zip"))
        self.assertIn("app/src-tauri/src/supervisor.rs", contents)
        for name in EXCLUDED:
            with self.subTest(path=name):
                self.assertNotIn(name, contents)

    def test_archive_retains_exact_readme_images_and_excludes_unrelated_images(self):
        images = {
            "docs/images/desktop-guide.png": b"indexed guide image",
            "docs/images/desktop-views.png": b"indexed views image",
        }
        for name, expected in images.items():
            self.write(name, expected)
        unrelated = "docs/images/unrelated.png"
        self.write(unrelated, b"unrelated tracked image")
        self.git("add", "--", "docs/images")
        contents = self.entries(self.archive("documentation.zip"))
        for name, expected in images.items():
            with self.subTest(path=name):
                self.assertIn(name, contents)
                self.assertEqual(contents[name], expected)
        self.assertNotIn(unrelated, contents)

    def test_missing_indexed_desktop_lockfile_refuses_an_incomplete_release(self):
        self.git("rm", "--cached", "app/src-tauri/Cargo.lock")
        with self.assertRaisesRegex(ValueError, r"missing required index files: .*app/src-tauri/Cargo.lock"):
            self.archive("incomplete.zip")

    def test_unified_source_archive_contains_real_runtime_build_inputs_without_private_state(self):
        for name, contents in UNIFIED_INPUTS.items():
            self.write(name, contents)
        for name in EXCLUDED:
            self.write(name, b"private or generated fixture\n")
        self.git("add", "--all")
        archive = self.entries(self.archive("unified.zip"))
        for name, contents in UNIFIED_INPUTS.items():
            with self.subTest(path=name):
                self.assertEqual(archive.get(name), contents)
        for name in EXCLUDED:
            self.assertNotIn(name, archive)

    def test_missing_browser_contract_refuses_a_source_archive_that_would_not_compile(self):
        path = "contracts/browser-tools-v1.json"
        self.write(path, b'{"tools":[]}\n')
        self.git("add", "--", path)
        self.git("rm", "--cached", path)
        with self.assertRaisesRegex(ValueError, r"missing required index files: .*contracts/browser-tools-v1.json"):
            self.archive("missing-browser.zip")

    def test_reviewed_release_inputs_are_complete_and_only_explicit(self):
        private = "licenses/rust-fallbacks/unreviewed/private.txt"
        self.write(private, b"not an admitted legal file")
        self.git("add", "--all")
        entries = self.entries(self.archive("reviewed.zip"))
        self.assertTrue(SOURCE.REVIEWED_RELEASE_INPUTS.issubset(entries))
        self.assertNotIn(private, entries)
        missing = "native/winapp-patches/0004-exact-passive-window.patch"
        self.git("rm", "--cached", missing)
        with self.assertRaisesRegex(ValueError, "missing required index files"):
            self.archive("missing-native-patch.zip")

    def test_vendored_glib_paths_modes_and_required_license_are_enforced(self):
        extra_allowed = {
            "app/src-tauri/patches/glib-0.18.5/src/auto/date_time.rs": b"pub struct DateTime;\n",
            "app/src-tauri/patches/glib-0.18.5/benches/gstring.rs": b"fn main() {}\n",
            "app/src-tauri/patches/glib-0.18.5/tests/value.rs": b"#[test] fn v() {}\n",
            "app/src-tauri/patches/glib-0.18.5/tests/subclass_compiletest/02-no-auto-send-sync.stderr": b"error\n",
        }
        excluded = (
            "app/src-tauri/patches/glib-0.18.5/.cargo_vcs_info.json",
            "app/src-tauri/patches/glib-0.18.5/src/unreviewed.json",
            "app/src-tauri/patches/glib-0.18.5/target/out.rs",
            "app/src-tauri/patches/glib-0.18.5/evil.exe",
            "app/src-tauri/patches/other/lib.rs",
        )
        for rel, content in extra_allowed.items():
            self.write(rel, content)
        for rel in excluded:
            self.write(rel, b"excluded fixture\n")
        self.git("add", "--all")

        archive = self.archive("vendored-glib.zip")
        entries = self.entries(archive)
        for rel, content in extra_allowed.items():
            self.assertEqual(entries.get(rel), content)
        for rel in excluded:
            self.assertNotIn(rel, entries)

        with zipfile.ZipFile(archive) as pkg:
            prefix = "agent-bridge-1.2.3-rust-src/"
            for info in pkg.infolist():
                rel = info.filename.removeprefix(prefix)
                if rel.startswith("app/src-tauri/patches/"):
                    self.assertEqual(info.external_attr >> 16, 0o100644, rel)

        exec_target = "app/src-tauri/patches/glib-0.18.5/src/auto/date_time.rs"
        self.git("update-index", "--chmod=+x", exec_target)
        with self.assertRaisesRegex(ValueError, "unexpected executable mode"):
            self.archive("exec-vendored.zip")
        self.git("update-index", "--chmod=-x", exec_target)

        for required_path in (
            "app/src-tauri/patches/glib-0.18.5/LICENSE",
            "app/src-tauri/patches/glib-0.18.5/src/variant_iter.rs",
        ):
            data = (self.repo / required_path).read_bytes()
            self.git("rm", "--cached", required_path)
            with self.assertRaisesRegex(ValueError, "missing required index files"):
                self.archive("missing-glib-req.zip")
            self.write(required_path, data)
            self.git("add", "--", required_path)

    def test_desktop_archive_bytes_are_deterministic(self):
        first = self.archive("first.zip").read_bytes()
        second = self.archive("second.zip").read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())


if __name__ == "__main__":
    unittest.main()
