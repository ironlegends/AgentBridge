#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import gzip
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from unittest import mock
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

    def test_release_channel_is_always_set_by_the_packager_and_validated(self):
        from unittest import mock
        seen = []
        def refuse(cmd, **kwargs):
            seen.append(kwargs["env"].get("AGENT_BRIDGE_RELEASE_CHANNEL"))
            raise RuntimeError("stop before any build")
        inherited = {"AGENT_BRIDGE_RELEASE_CHANNEL": "stable"}
        with mock.patch.object(PACKAGE.COMMON.subprocess, "run", side_effect=refuse):
            for channel in ("development", "stable"):
                with self.assertRaisesRegex(RuntimeError, "stop before any build"):
                    PACKAGE.COMMON.cargo_build_artifact(self.root / "Cargo.toml", PACKAGE.TARGET, "cargo", inherited,
                                                        "id", self.root / channel, False, release_channel=channel)
        self.assertEqual(seen, ["development", "stable"])
        with self.assertRaisesRegex(ValueError, "development or stable"):
            PACKAGE.COMMON.cargo_build_artifact(self.root / "Cargo.toml", PACKAGE.TARGET, "cargo", {}, "id",
                                                self.root / "other", False, release_channel="production")

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
            for encoding in ("utf-8", "utf-16-le", "json"):
                encoded = json.dumps(spelling)[1:-1].encode("ascii") if encoding == "json" else spelling.encode(encoding)
                (self.stage / "agent-bridge-desktop-app.exe").write_bytes(b"\x00" + encoded + b"\x00")
                with self.subTest(spelling=spelling, encoding=encoding):
                    with self.assertRaisesRegex(ValueError, "private build path found in staged file"):
                        PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private, accented])

    def test_private_paths_inside_compressed_members_and_embedded_sources_are_refused(self):
        private = self.root / "Private-Checkout"
        leak = (str(private.resolve()) + "\\src\\main.rs").encode("utf-8")
        def zipped(name, data, method=zipfile.ZIP_DEFLATED):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", method) as archive:
                archive.writestr(name, data)
            return buffer.getvalue()
        target = self.stage / "resources/automation/browser/bundle.bin"
        half = len(leak) // 2
        for label, data in (("zip", zipped("inner.txt", leak)), ("stored zip", zipped("inner.txt", leak, zipfile.ZIP_STORED)),
                            ("gzip", gzip.compress(leak)), ("zip in gzip", gzip.compress(zipped("inner.txt", leak))),
                            ("two gzip members", gzip.compress(b"clean") + gzip.compress(leak)),
                            ("split across gzip members", gzip.compress(leak[:half]) + gzip.compress(leak[half:])),
                            ("member after zero padding", gzip.compress(b"clean") + b"\x00" * 8 + gzip.compress(leak)),
                            ("zip after a preamble", b"MZ executable stub" + zipped("inner.txt", leak)),
                            ("zip after a preamble with trailing bytes", b"MZ stub" + zipped("inner.txt", leak) + b"trailing"),
                            ("deflated zip in a stored zip", zipped("outer.zip", zipped("inner.txt", leak), zipfile.ZIP_STORED))):
            target.write_bytes(data)
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, "private build path found in staged file: resources/automation/browser/bundle.bin"):
                    PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private])
        # Clean compressed members and incidental end-record signatures pass,
        # also at the nesting limit.
        incidental = b"MZ code PK\x05\x06 more code" + b"\x00" * 64
        at_limit = incidental
        for _ in range(PACKAGE.COMMON.PRIVATE_SCAN_DEPTH):
            at_limit = gzip.compress(at_limit)
        for data in (gzip.compress(zipped("inner.txt", b"clean")), incidental, at_limit):
            target.write_bytes(data)
            PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private])
        # One decompression budget covers every staged file.
        target.write_bytes(gzip.compress(b"x" * 600))
        (self.stage / "resources/automation/browser/second.bin").write_bytes(gzip.compress(b"y" * 600))
        with mock.patch.object(PACKAGE.COMMON, "PRIVATE_SCAN_MAX_BYTES", 1000):
            with self.assertRaisesRegex(ValueError, "too large"):
                PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private])
        (self.stage / "resources/automation/browser/second.bin").unlink()
        # Too deep, understated, unreadable or ambiguous members are refused.
        nested = b"clean"
        for _ in range(PACKAGE.COMMON.PRIVATE_SCAN_DEPTH + 1):
            nested = gzip.compress(nested)
        crc = bytearray(zipped("inner.txt", b"clean", zipfile.ZIP_STORED))
        crc[30 + len("inner.txt")] ^= 1
        understated = bytearray(zipped("inner.txt", b"clean" * 64))
        central = understated.rfind(b"PK\x01\x02")
        understated[central + 24:central + 28] = (10).to_bytes(4, "little")
        commented = zipped("inner.txt", b"clean")
        commented = b"stub" + commented[:-2] + (6).to_bytes(2, "little") + b"PK\x05\x06"[:4] + b"!!"
        for label, data in (("too deep", nested), ("truncated", gzip.compress(b"clean" * 64)[:24]),
                            ("gzip trailing data", gzip.compress(b"clean") + b"trailing"),
                            ("bzip2 member", zipped("inner.txt", b"clean", zipfile.ZIP_BZIP2)), ("crc mismatch", bytes(crc)),
                            ("understated size", bytes(understated)), ("signature in comment", commented)):
            target.write_bytes(data)
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, "(nested too deeply|unreadable|unsupported)"):
                    PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private])
        target.unlink()
        # The frontend that Tauri compresses into the executable is scanned from source.
        frontend = self.root / "ui-source"
        frontend.mkdir()
        (frontend / "app.js").write_bytes(b"const path = '" + leak + b"';\n")
        with self.assertRaisesRegex(ValueError, "private build path found in staged file: embedded app.js"):
            PACKAGE.assert_no_private_paths(self.stage, PACKAGE.stage_records(self.stage), [private], [frontend / "app.js"])
        repo = Path(__file__).resolve().parents[2]
        self.assertIn(repo / "app/ui/index.html", PACKAGE.frontend_files(repo, {}))
        # A merged configuration could embed another frontend than the scanned one.
        with self.assertRaisesRegex(ValueError, "TAURI_CONFIG is not admitted"):
            PACKAGE.frontend_files(repo, {"TAURI_CONFIG": "{}"})
        fake = self.root / "repo"
        (fake / "app/src-tauri").mkdir(parents=True)
        (fake / "app/ui").mkdir()
        (fake / "app/ui/index.html").write_bytes(b"<p></p>")
        (fake / "app/src-tauri/tauri.conf.json").write_text('{"build": {"frontendDist": "../ui"}}', encoding="utf-8")
        self.assertEqual(PACKAGE.frontend_files(fake, {}), [(fake / "app/ui/index.html").resolve()])
        (fake / "app/src-tauri/tauri.windows.conf.json").write_text('{"build": {"frontendDist": "../other"}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "only app/src-tauri/tauri.conf.json"):
            PACKAGE.frontend_files(fake, {})

    def test_existing_archive_is_preserved(self):
        output = self.root / "application.zip"
        output.write_bytes(b"previous qualified release")
        with self.assertRaises(FileExistsError):
            PACKAGE.write_archive(self.stage, output, PACKAGE.stage_records(self.stage))
        self.assertEqual(output.read_bytes(), b"previous qualified release")


if __name__ == "__main__":
    unittest.main()
