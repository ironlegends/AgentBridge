#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import release_components as components


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ResourcePackaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self, kind):
        root = self.root / kind
        root.mkdir()
        records = []
        paths = ["worker/worker.mjs", "node/node.exe", "notices/LICENSE.txt"] if kind == "browser" else [
            "agent-bridge-native.exe", "winapp/winapp.exe", "winapp/libSkiaSharp.dll", "VirtualDesktopAccessor.dll", "notices/LICENSE.txt"]
        for path in paths:
            data = (path + "\n").encode()
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records.append({"path": path, "sha256": sha(data), "bytes": len(data)})
        if kind == "browser":
            manifest = {"schema_version": 1, "protocol_version": 2, "files": records}
        else:
            records = [{"path": r["path"], "sha256": r["sha256"], "size": r["bytes"]} for r in records]
            manifest = {"schema": 1, "protocol": 1, "platform": "windows-x64",
                        "files": dict(zip(("native", "winapp", "skia", "vda"), records[:4])),
                        "notices": {"LICENSE.txt": records[-1]}}
        self.save_manifest(root, manifest)
        return root, sha((root / "manifest.json").read_bytes())

    def save_manifest(self, root, value):
        (root / "manifest.json").write_text(json.dumps(value), encoding="utf-8")

    def test_verified_resources_are_copied_with_exact_manifest_and_tauri_mapping(self):
        browser, browser_sha = self.bundle("browser")
        native, native_sha = self.bundle("native")
        target = self.root / "application"
        result = components.stage_resources(browser, browser_sha, native, native_sha, target)
        for kind, original in (("browser", browser), ("native", native)):
            for path in original.rglob("*"):
                if path.is_file():
                    self.assertEqual(path.read_bytes(), (target / "resources/automation" / kind / path.relative_to(original)).read_bytes())
        self.assertEqual(result["browser"]["manifest_sha256"], browser_sha)
        self.assertEqual(result["browser"]["protocol"], 2)
        self.assertEqual(result["native"]["protocol"], 1)
        config = components.tauri_resources(target)
        self.assertEqual(config["bundle"]["resources"][(target / "resources").as_posix() + "/"], "resources/")

    def test_browser_rejects_legacy_ambiguous_and_wrong_manifest_versions(self):
        browser, _ = self.bundle("browser")
        original = json.loads((browser / "manifest.json").read_text())
        for changes in (
            {"schema": 1, "protocol": 2, "schema_version": None, "protocol_version": None},
            {"schema": 1}, {"protocol": 2}, {"schema_version": True},
            {"schema_version": 2}, {"protocol_version": 1}, {"protocol_version": 2.0},
        ):
            with self.subTest(changes=changes):
                value = {**original, **changes}
                self.save_manifest(browser, value)
                with self.assertRaisesRegex(ValueError, "(schema|protocol)"):
                    components.component_files(browser, sha((browser / "manifest.json").read_bytes()), "browser")

    def test_tampered_or_unlisted_files_refuse_publication(self):
        browser, expected = self.bundle("browser")
        native, native_sha = self.bundle("native")
        (browser / "worker/worker.mjs").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "(digest|size)"):
            components.stage_resources(browser, expected, native, native_sha, self.root / "bad")
        self.assertFalse((self.root / "bad").exists())
        (browser / "worker/worker.mjs").write_bytes(b"worker/worker.mjs\n")
        (browser / "Cookies").write_bytes(b"private state")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            components.stage_resources(browser, expected, native, native_sha, self.root / "bad")
        self.assertFalse((self.root / "bad").exists())

    def test_traversal_case_collision_and_manifest_identity_are_refused(self):
        browser, expected = self.bundle("browser")
        original = json.loads((browser / "manifest.json").read_text())
        for path in ("../outside", "C:/outside", "worker/CON.txt", "worker/../secret"):
            with self.subTest(path=path):
                value = json.loads(json.dumps(original))
                value["files"][0]["path"] = path
                self.save_manifest(browser, value)
                with self.assertRaises(ValueError):
                    components.component_files(browser, sha((browser / "manifest.json").read_bytes()), "browser")
        self.save_manifest(browser, original)
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            components.component_files(browser, "0" * 64, "browser")
        original["files"].append({**original["files"][0], "path": "WORKER/worker.mjs"})
        self.save_manifest(browser, original)
        with self.assertRaisesRegex(ValueError, "(duplicate|collision)"):
            components.component_files(browser, sha((browser / "manifest.json").read_bytes()), "browser")

    def test_linked_parent_is_not_followed(self):
        browser, expected = self.bundle("browser")
        outside = self.root / "external"
        (browser / "worker").rename(outside)
        try:
            (browser / "worker").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink unavailable")
        with self.assertRaisesRegex(ValueError, "(link|reparse)"):
            components.component_files(browser, expected, "browser")

    def test_console_subsystem_is_rejected_even_with_correct_exe_name(self):
        image = bytearray(512)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3c, 0x80)
        image[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", image, 0x84, 0x8664)
        struct.pack_into("<H", image, 0x94, 240)
        struct.pack_into("<H", image, 0x96, 0x0002)
        struct.pack_into("<H", image, 0x98, 0x020b)
        struct.pack_into("<H", image, 0x98 + 68, 3)
        with self.assertRaisesRegex(ValueError, "GUI"):
            components.verify_gui_image(bytes(image))
        struct.pack_into("<H", image, 0x98 + 68, 2)
        components.verify_gui_image(bytes(image))


if __name__ == "__main__":
    unittest.main()
