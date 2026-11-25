#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline fixtures for notices referenced by ring's vendored once_cell code."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "release_notices", Path(__file__).with_name("release-notices.py")
)
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)
NESTED = (
    "src/polyfill/once_cell/LICENSE-APACHE",
    "src/polyfill/once_cell/LICENSE-MIT",
)


class RingNoticeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-bridge-notice-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.workspace = self.base / "workspace"
        self.crate = self.base / "ring-0.17.14"
        self.workspace.mkdir()
        self.crate.mkdir()
        for name in ("LICENSE", "NOTICE", "Cargo.toml"):
            (self.workspace / name).write_text("fixture\n", encoding="utf-8")
        self.sources = {
            "LICENSE": ("See " + " and ".join(NESTED) + " for once_cell.\n").encode(),
            "LICENSE-BoringSSL": b"Apache-2.0 fixture\n",
            "LICENSE-other-bits": b"ISC fixture\n",
            NESTED[0]: b"Vendored Apache license fixture\n",
            NESTED[1]: b"Vendored MIT license fixture\n",
        }
        for relative, data in self.sources.items():
            path = self.crate / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.metadata = {
            "workspace_root": str(self.workspace),
            "workspace_members": ["root"],
            "packages": [
                {"id": "root", "name": "agent-bridge", "version": "2.0.0-rc.1",
                 "manifest_path": str(self.workspace / "Cargo.toml"),
                 "license": "Apache-2.0", "source": None},
                {"id": "ring", "name": "ring", "version": "0.17.14",
                 "manifest_path": str(self.crate / "Cargo.toml"),
                 "license": "Apache-2.0 AND ISC", "source": "registry+fixture",
                 "links": "ring_core_0_17_14_"},
            ],
            "resolve": {"nodes": [
                {"id": "root", "features": [], "deps": [{"pkg": "ring"}]},
                {"id": "ring", "features": [], "deps": []},
            ]},
        }

    def collect(self):
        output = self.base / "notices-out"
        with mock.patch.object(NOTICES, "cargo_metadata", return_value=self.metadata):
            with contextlib.redirect_stdout(io.StringIO()):
                status = NOTICES.main([
                    "--manifest-path", str(self.workspace / "Cargo.toml"),
                    "--target", "x86_64-pc-windows-msvc", "--out-dir", str(output),
                ])
        self.assertEqual(status, 0)
        return output, json.loads((output / "index.json").read_text(encoding="utf-8"))

    def test_ring_copies_referenced_notices_with_exact_hashes(self):
        output, index = self.collect()
        ring = next(item for item in index["packages"] if item["name"] == "ring")
        self.assertEqual({item["source"] for item in ring["notices"]}, set(self.sources))
        for item in ring["notices"]:
            expected = self.sources[item["source"]]
            self.assertEqual((output / item["packaged"]).read_bytes(), expected)
            self.assertEqual(item["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(index["to_verify"], [{
            "package": "ring@0.17.14", "code": "native_links_check",
            "links": "ring_core_0_17_14_",
        }])

    def test_ring_refuses_missing_referenced_notice(self):
        (self.crate / NESTED[1]).unlink()
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_ring_refuses_non_regular_referenced_notice(self):
        notice = self.crate / NESTED[1]
        notice.unlink()
        notice.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_ring_keeps_oversized_notice_blocking(self):
        (self.crate / NESTED[1]).write_bytes(b"x" * (NOTICES.MAX_NOTICE_BYTES + 1))
        output, index = self.collect()
        self.assertIn({"package": "ring@0.17.14", "code": "oversized_notice_skipped",
                       "path": NESTED[1]}, index["to_verify"])
        self.assertFalse((output / "notices/ring-0.17.14" / NESTED[1]).exists())

    def test_ring_refuses_symlinked_notice(self):
        outside = self.base / "external-license"
        outside.write_text("external bytes must not be read\n", encoding="utf-8")
        notice = self.crate / NESTED[1]
        notice.unlink()
        try:
            notice.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_ring_refuses_symlinked_ancestor(self):
        source = self.crate / "src"
        outside = self.base / "external-src"
        shutil.move(source, outside)
        try:
            source.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_explicit_license_file_keeps_its_declared_source(self):
        content = b"Explicit license fixture\n"
        (self.crate / "terms.txt").write_bytes(content)
        self.metadata["packages"][1]["license_file"] = "terms.txt"
        output, index = self.collect()
        ring = next(item for item in index["packages"] if item["name"] == "ring")
        self.assertEqual(ring["license_file"], "terms.txt")
        notice = next(item for item in ring["notices"] if item["source"] == "terms.txt")
        self.assertEqual((output / notice["packaged"]).read_bytes(), content)
        self.assertEqual(notice["sha256"], hashlib.sha256(content).hexdigest())

    def test_explicit_license_file_refuses_an_internal_symlink(self):
        actual = self.crate / "actual-license"
        actual.write_text("internal symlink target\n", encoding="utf-8")
        try:
            (self.crate / "custom-license").symlink_to(actual)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        self.metadata["packages"][1]["license_file"] = "custom-license"
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_explicit_license_file_refuses_a_linked_parent(self):
        actual = self.crate / "actual-terms"
        actual.mkdir()
        (actual / "terms.txt").write_text("internal parent target\n", encoding="utf-8")
        linked = self.crate / "custom-terms"
        if os.name == "nt":
            result = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(actual)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            linked.symlink_to(actual, target_is_directory=True)
        self.metadata["packages"][1]["license_file"] = "custom-terms/terms.txt"
        with self.assertRaises((OSError, ValueError)):
            self.collect()

    def test_explicit_external_license_is_not_copied(self):
        outside = self.base / "external-terms.txt"
        outside.write_bytes(b"external bytes must not be copied\n")
        for declared in (str(outside), "../external-terms.txt"):
            with self.subTest(declared=declared):
                self.metadata["packages"][1]["license_file"] = declared
                output, index = self.collect()
                ring = next(item for item in index["packages"] if item["name"] == "ring")
                self.assertEqual(ring["license_file"], "<external>")
                self.assertEqual({item["source"] for item in ring["notices"]}, set(self.sources))
                shutil.rmtree(output)

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture")
    def test_ring_refuses_junction_ancestor(self):
        source = self.crate / "src"
        outside = self.base / "external-src"
        shutil.move(source, outside)
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(source), str(outside)],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises((OSError, ValueError)):
            self.collect()


class ReviewedUpstreamNoticeTests(unittest.TestCase):
    collect = RingNoticeTests.collect

    def setUp(self):
        RingNoticeTests.setUp(self)
        self.crate = self.base / "reviewed-fixture-1.2.3"
        self.crate.mkdir()
        self.label = "reviewed-fixture@1.2.3"
        self.checksum = "a" * 64
        self.vcs = {"git": {"sha1": "b" * 40}, "path_in_vcs": "crate"}
        self.license = b"Reviewed legal fixture\n"
        self.native = b"native image fixture"
        (self.crate / ".cargo_vcs_info.json").write_text(json.dumps(self.vcs), encoding="utf-8")
        (self.crate / "native.lib").write_bytes(self.native)
        self.pkg = {"id": "ring", "name": "reviewed-fixture", "version": "1.2.3",
                    "manifest_path": str(self.crate / "Cargo.toml"),
                    "license": "MPL-2.0", "source": NOTICES.CRATES_IO_SOURCE}
        self.metadata["packages"][1] = self.pkg
        (self.workspace / "Cargo.lock").write_text(
            '[[package]]\nname = "reviewed-fixture"\nversion = "1.2.3"\n'
            f'source = "{NOTICES.CRATES_IO_SOURCE}"\nchecksum = "{self.checksum}"\n',
            encoding="utf-8")
        self.pins_root = self.workspace / NOTICES.PINNED_NOTICE_ROOT
        self.folder = self.pins_root / "reviewed-fixture-1.2.3"
        self.folder.mkdir(parents=True)
        (self.folder / "LICENSE").write_bytes(self.license)
        self.pin = {"registry": NOTICES.CRATES_IO_SOURCE, "crate_sha256": self.checksum,
                    "license": "MPL-2.0", "source_revision": "b"*40, "source_path": "crate",
                    "notices": {"LICENSE": hashlib.sha256(self.license).hexdigest()},
                    "native_files": {"native.lib": hashlib.sha256(self.native).hexdigest()}}
        self.manifest = self.pins_root / "pins.json"
        self.manifest.write_text(json.dumps({self.label:self.pin}), encoding="utf-8")
        patcher = mock.patch.object(NOTICES, "PINNED_NOTICE_MANIFEST_SHA256",
                                   hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_reviewed_notice_and_mpl_source_are_packaged(self):
        output, index = self.collect()
        package = index["packages"][1] if index["packages"][1]["name"] == "reviewed-fixture" else index["packages"][0]
        self.assertEqual(package["name"], "reviewed-fixture")
        self.assertEqual(len(package["notices"]), 2)
        base = output / "notices/reviewed-fixture-1.2.3"
        self.assertEqual((base / "reviewed-upstream/LICENSE").read_bytes(), self.license)
        link = (base / "SOURCE-AVAILABILITY.txt").read_text(encoding="utf-8")
        self.assertIn("https://static.crates.io/crates/reviewed-fixture/reviewed-fixture-1.2.3.crate", link)
        self.assertIn(self.checksum, link)
        self.assertEqual([i["code"] for i in index["to_verify"]], ["native_links_check"])

    def test_tampered_manifest_refused(self):
        self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            self.collect()

    def test_tampered_notice_refused(self):
        (self.folder / "LICENSE").write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "notice digest"):
            self.collect()

    def test_mismatched_native_binary_refused(self):
        (self.crate / "native.lib").write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "SDK member digest"):
            self.collect()

    def test_mismatched_crate_revision_refused(self):
        (self.crate / ".cargo_vcs_info.json").write_text(
            json.dumps({"git":{"sha1":"c"*40},"path_in_vcs":"crate"}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "upstream revision"):
            self.collect()

    def test_wrong_lock_checksum_refused(self):
        lock = self.workspace / "Cargo.lock"
        lock.write_text(lock.read_text().replace(self.checksum, "c"*64), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "package identity"):
            self.collect()

    def test_other_version_cannot_inherit_reviewed_notice(self):
        self.pkg["version"] = "1.2.4"
        _, index = self.collect()
        self.assertIn({"package":"reviewed-fixture@1.2.4","code":"no_notice_file_found","license":"MPL-2.0"},
                      index["to_verify"])

    def test_missing_manifest_cannot_suppress_missing_notice(self):
        self.manifest.unlink()
        _, index = self.collect()
        self.assertIn({"package":self.label,"code":"no_notice_file_found","license":"MPL-2.0"},
                      index["to_verify"])


if __name__ == "__main__":
    unittest.main()
