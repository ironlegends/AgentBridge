#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("package_desktop", Path(__file__).with_name("package-desktop.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class DesktopArchive(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "agent-bridge-desktop"
        (self.stage / "resources/automation/browser").mkdir(parents=True)
        (self.stage / "agent-bridge-desktop-app.exe").write_bytes(b"validated binary fixture")
        (self.stage / "resources/automation/browser/worker.mjs").write_bytes(b"export const fixture = true;\n")

    def test_streamed_archive_is_deterministic_and_contains_exact_validated_bytes(self):
        records = PACKAGE.stage_records(self.stage)
        first, second = self.root / "first.zip", self.root / "second.zip"
        one = PACKAGE.write_archive(self.stage, first, records)
        two = PACKAGE.write_archive(self.stage, second, records)
        self.assertEqual(one, two)
        self.assertEqual(one, hashlib.sha256(first.read_bytes()).hexdigest())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(set(archive.namelist()), {self.stage.name + "/" + r["path"] for r in records})
            for record in records:
                self.assertEqual(archive.read(self.stage.name + "/" + record["path"]), (self.stage / record["path"]).read_bytes())

    def test_changed_input_refuses_archive_without_leaving_partial_output(self):
        records = PACKAGE.stage_records(self.stage)
        (self.stage / "agent-bridge-desktop-app.exe").write_bytes(b"different binary fixture")
        output = self.root / "application.zip"
        with self.assertRaisesRegex(ValueError, "(digest|size|changed)"):
            PACKAGE.write_archive(self.stage, output, records)
        self.assertFalse(output.exists())

    def test_windows_remap_destination_is_absolute_even_on_other_build_hosts(self):
        from pathlib import PureWindowsPath, PurePosixPath
        for name in ("cargo", "agent-bridge", "build"):
            win = PACKAGE.COMMON.virtual_source_root("x86_64-pc-windows-msvc", name)
            self.assertTrue(PureWindowsPath(win).is_absolute())
            self.assertEqual(win, "C:/agent-bridge-build/" + name)
            unix = PACKAGE.COMMON.virtual_source_root("x86_64-unknown-linux-gnu", name)
            self.assertTrue(PurePosixPath(unix).is_absolute())
            self.assertEqual(unix, "/" + name)
        flags = []
        PACKAGE.COMMON.remap_source_root(flags, self.root, PACKAGE.TARGET, "cargo")
        self.assertTrue(flags)
        self.assertTrue(all(flag.endswith("=C:/agent-bridge-build/cargo") for flag in flags))

    def test_private_build_paths_are_refused_in_ascii_and_utf16(self):
        private = self.root / "Private-Checkout"
        records = PACKAGE.stage_records(self.stage)
        PACKAGE.assert_no_private_paths(self.stage, records, [private])
        for spelling in (str(private.resolve()) + "\\src\\desktop.rs", private.resolve().as_posix().upper() + "/x.pdb"):
            for encoding in ("utf-8", "utf-16-le"):
                (self.stage / "agent-bridge-desktop-app.exe").write_bytes(b"\x00prefix" + spelling.encode(encoding) + b"\x00")
                with self.assertRaisesRegex(ValueError, "private build path found in staged file: agent-bridge-desktop-app.exe"):
                    PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private])
        # Non-ASCII capitals survive ASCII-only lowering of the scanned bytes.
        accented = self.root / "Élodie-Checkout"
        spellings = [str(accented.resolve()) + "\\a.rs", str(accented.resolve()).upper() + "\\b.rs"]
        resolved = private.resolve()
        if resolved.drive:
            spellings.append("/" + resolved.drive[0].lower() + resolved.as_posix()[2:] + "/c.rs")
        for spelling in spellings:
            for encoding in ("utf-8", "utf-16-le"):
                (self.stage / "agent-bridge-desktop-app.exe").write_bytes(b"\x00" + spelling.encode(encoding) + b"\x00")
                with self.subTest(spelling=spelling, encoding=encoding):
                    with self.assertRaisesRegex(ValueError, "private build path found in staged file"):
                        PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private, accented])

    def test_existing_archive_is_preserved(self):
        output = self.root / "application.zip"
        output.write_bytes(b"previous qualified release")
        with self.assertRaises(FileExistsError):
            PACKAGE.write_archive(self.stage, output, PACKAGE.stage_records(self.stage))
        self.assertEqual(output.read_bytes(), b"previous qualified release")


if __name__ == "__main__":
    unittest.main()
