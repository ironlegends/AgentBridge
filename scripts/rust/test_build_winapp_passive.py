#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline fixture tests for scripts/rust/build-winapp-passive.py (patches 0001..0004)."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("build-winapp-passive.py")
SPEC = importlib.util.spec_from_file_location("build_winapp_passive", SCRIPT)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)

REPO_ROOT = Path(__file__).resolve().parents[2]
PATCHES_DIR = REPO_ROOT / "native/winapp-patches"
PATCH_0004_SHA256 = "5e022e69d4652b751f05634bcdd3a2a771c5dd6400a8abdd0df1155088391bba"
EXACT_CONTRACT_SHA256 = "e138506eebc6d81faa89a24807dd706d88adbe8b20a75d91335229186619e908"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_patch_chunks(patch_path: Path) -> list[tuple[str, list[str]]]:
    lines = patch_path.read_text(encoding="utf-8").splitlines(keepends=True)
    starts = [idx for idx, line in enumerate(lines) if line.startswith("--- a/")]
    starts.append(len(lines))
    chunks = []
    for idx in range(len(starts) - 1):
        chunk = lines[starts[idx]:starts[idx + 1]]
        target = chunk[0].removeprefix("--- a/").rstrip("\n")
        chunks.append((target, chunk))
    return chunks


def extract_old_hunks(chunk: list[str]) -> list[tuple[int, list[str]]]:
    hunks = []
    index = 2
    while index < len(chunk):
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n", chunk[index])
        if not match:
            raise AssertionError(f"unexpected hunk header: {chunk[index]!r}")
        start = int(match.group(1))
        index += 1
        old_lines = []
        while index < len(chunk) and not chunk[index].startswith("@@"):
            if chunk[index][0] in (" ", "-"):
                old_lines.append(chunk[index][1:])
            index += 1
        hunks.append((start, old_lines))
    return hunks


def build_lines_from_hunks(hunks: list[tuple[int, list[str]]]) -> str:
    placed: dict[int, str] = {}
    max_line = 0
    for start, old_lines in hunks:
        for offset, text in enumerate(old_lines):
            lineno = start + offset
            if lineno in placed and placed[lineno] != text:
                raise AssertionError(f"conflicting synthetic line {lineno}: {placed[lineno]!r} != {text!r}")
            placed[lineno] = text
            max_line = max(max_line, lineno)
    return "".join(placed.get(n, f"// filler line {n}\n") for n in range(1, max_line + 1))


def synthesize_upstream_files() -> dict[str, str]:
    """Build minimal upstream files whose lines match the real 0001..0004 hunks."""
    files: dict[str, str] = {}
    p1 = dict(parse_patch_chunks(PATCHES_DIR / "0001-passive-screenshot.patch"))
    p2 = dict(parse_patch_chunks(PATCHES_DIR / "0002-background-post-message.patch"))
    p3 = dict(parse_patch_chunks(PATCHES_DIR / "0003-background-uia-autofocus.patch"))
    p4 = dict(parse_patch_chunks(PATCHES_DIR / "0004-exact-passive-window.patch"))

    # Files touched by a single patch.
    for mapping in (p2, p3, p4):
        for target, chunk in mapping.items():
            if target in {
                "src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.Screenshot.cs",
                "src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs",
                "src/winapp-CLI/WinApp.Cli/Services/IUiAutomationService.cs",
            }:
                continue
            files[target] = build_lines_from_hunks(extract_old_hunks(chunk))

    # UiAutomationService.Screenshot.cs: 0001 adds +4 lines at line 63; 0004 runs after 0001.
    ss_hunks = list(extract_old_hunks(p1["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.Screenshot.cs"]))
    for start, old_lines in extract_old_hunks(p4["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.Screenshot.cs"]):
        adjusted = start - 4 if start >= 72 else start
        ss_hunks.append((adjusted, old_lines))
    files["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.Screenshot.cs"] = build_lines_from_hunks(ss_hunks)

    # UiAutomationService.cs: 0002 adds +14 lines at line 874; 0003 touches lines 24 & 62 (before 874).
    uas_hunks = (
        extract_old_hunks(p2["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs"])
        + extract_old_hunks(p3["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs"])
    )
    files["src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs"] = build_lines_from_hunks(uas_hunks)

    # IUiAutomationService.cs: 0002 adds +2 lines at line 51; 0003 touches line 12 (before 51).
    iuas_hunks = (
        extract_old_hunks(p2["src/winapp-CLI/WinApp.Cli/Services/IUiAutomationService.cs"])
        + extract_old_hunks(p3["src/winapp-CLI/WinApp.Cli/Services/IUiAutomationService.cs"])
    )
    files["src/winapp-CLI/WinApp.Cli/Services/IUiAutomationService.cs"] = build_lines_from_hunks(iuas_hunks)

    files["src/winapp-CLI/WinApp.Cli/WinApp.Cli.csproj"] = '<Project Sdk="Microsoft.NET.Sdk"/>\n'
    files["LICENSE"] = "MIT License fixture\n"
    return files


class WinAppProvenanceInputTests(unittest.TestCase):
    def test_committed_provenance_matches_the_tracked_build_inputs(self):
        # Each pinned input of the committed WinApp build must have the same
        # bytes in every checkout and in the source archive.
        provenance = json.loads((REPO_ROOT / "native/agent-bridge-native/notices/WINAPP-BUILD-PROVENANCE.json")
                                .read_text(encoding="utf-8"))
        tests = PATCHES_DIR / "tests"
        sources = {"Program.cs": "PassiveCaptureContract.cs"}
        inputs = {"build_script": (provenance["build_script"], SCRIPT)}
        inputs.update({"patches/" + name: (record, PATCHES_DIR / name) for name, record in provenance["patches"].items()})
        inputs.update({"contract_sources/" + name: (record, tests / sources.get(name, name))
                       for name, record in provenance["contract_sources"].items()})
        self.assertGreaterEqual(len(inputs), 7)
        for label, (record, path) in inputs.items():
            data = path.read_bytes()
            with self.subTest(label):
                self.assertEqual({"sha256": sha256_bytes(data), "size": len(data)},
                                 {"sha256": record["sha256"], "size": record["size"]})


class WinAppExactPassiveBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ab-winapp-build-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_derivative_version_and_exact_passive_targets_match_patch_0004(self):
        self.assertEqual(BUILD.PROFILES["exact-passive"], {"version": "0.5.0-agentbridge.3", "exact_passive": True})
        self.assertEqual(BUILD.PROFILES["stable"], {"version": "0.5.0-agentbridge.2", "exact_passive": False})
        self.assertEqual(
            BUILD.EXACT_PASSIVE_SOURCES,
            (
                "src/winapp-CLI/WinApp.Cli/Commands/UiScreenshotCommand.cs",
                BUILD.TARGET,
            ),
        )

    def test_patch_0004_applies_cleanly_after_0001_and_preserves_target_allowlist(self):
        source = self.root / "source"
        for rel, content in synthesize_upstream_files().items():
            path = source / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")

        screenshot = source / BUILD.TARGET
        before_0001 = BUILD.file_record(screenshot)
        BUILD.apply_patch(screenshot, PATCHES_DIR / "0001-passive-screenshot.patch")
        after_0001 = BUILD.file_record(screenshot)
        self.assertNotEqual(before_0001["sha256"], after_0001["sha256"])

        changes = BUILD.apply_patch_set(
            source,
            PATCHES_DIR / "0004-exact-passive-window.patch",
            BUILD.EXACT_PASSIVE_SOURCES,
        )
        self.assertEqual(set(changes), set(BUILD.EXACT_PASSIVE_SOURCES))
        self.assertEqual(changes[BUILD.TARGET]["before"], after_0001)
        self.assertNotEqual(changes[BUILD.TARGET]["after"], after_0001)

        command_text = (source / "src/winapp-CLI/WinApp.Cli/Commands/UiScreenshotCommand.cs").read_text(encoding="utf-8")
        screenshot_text = screenshot.read_text(encoding="utf-8")
        self.assertIn("ExactPassiveOption", command_text)
        self.assertIn('new("--exact-passive")', command_text)
        self.assertIn("VerifyExactPassiveTarget", screenshot_text)
        self.assertIn("Passive window capture is unavailable while the window is minimized", screenshot_text)

        unreviewed = source / "src/winapp-CLI/WinApp.Cli/Program.cs"
        unreviewed.write_text("class Program {}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reviewed upstream source paths"):
            BUILD.apply_lines(
                unreviewed,
                [
                    "--- a/src/winapp-CLI/WinApp.Cli/Program.cs\n",
                    "+++ b/src/winapp-CLI/WinApp.Cli/Program.cs\n",
                ],
                "src/winapp-CLI/WinApp.Cli/Program.cs",
            )

    def test_exact_passive_contract_project_is_isolated_with_internals_access(self):
        work = self.root / "work"
        work.mkdir()
        winapp_csproj = self.root / "source/src/winapp-CLI/WinApp.Cli/WinApp.Cli.csproj"
        winapp_csproj.parent.mkdir(parents=True)
        winapp_csproj.write_text("<Project/>\n", encoding="utf-8")

        projects = BUILD.prepare_contract_projects(work, REPO_ROOT, winapp_csproj)
        self.assertEqual(set(projects), {"main", "exact_passive"})

        main_dir = projects["main"].parent
        exact_dir = projects["exact_passive"].parent
        self.assertNotEqual(main_dir, exact_dir)
        self.assertEqual(
            sorted(p.name for p in main_dir.glob("*.cs")),
            ["BackgroundMessageContract.cs", "BackgroundUiaContract.cs", "Program.cs"],
        )
        self.assertEqual(
            sorted(p.name for p in exact_dir.glob("*.cs")),
            ["ExactPassiveContract.cs"],
        )
        self.assertEqual(
            BUILD.file_record(exact_dir / "ExactPassiveContract.cs")["sha256"],
            EXACT_CONTRACT_SHA256,
        )
        exact_xml = projects["exact_passive"].read_text(encoding="utf-8")
        self.assertIn("<AssemblyName>WinApp.Cli.Tests</AssemblyName>", exact_xml)
        self.assertIn("<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework>", exact_xml)
        self.assertIn("<UseWindowsForms>true</UseWindowsForms>", exact_xml)
        self.assertIn("<UseWPF>true</UseWPF>", exact_xml)
        self.assertIn(str(winapp_csproj.absolute()), exact_xml)

    def test_plain_accepts_posix_stat_without_file_attributes_and_refuses_reparse(self):
        sample = self.root / "regular.txt"
        sample.write_text("fixture\n", encoding="utf-8")

        class PosixStat:
            st_mode = stat.S_IFREG | 0o644

        class ReparseStat:
            st_mode = stat.S_IFREG | 0o644
            st_file_attributes = 0x400

        with mock.patch.object(Path, "stat", return_value=PosixStat()):
            self.assertEqual(BUILD.plain(sample), sample)
        with mock.patch.object(Path, "stat", return_value=ReparseStat()):
            with self.assertRaisesRegex(ValueError, "non-reparse"):
                BUILD.plain(sample)

    @unittest.skipIf(os.name == "nt", "non-Windows host refusal fixture")
    def test_main_refuses_non_windows_host_without_creating_work_or_output(self):
        archive = self.root / "winapp.zip"
        archive.write_bytes(b"placeholder")
        dotnet = self.root / "dotnet"
        dotnet.write_bytes(b"placeholder")
        vcvars = self.root / "vcvars64.bat"
        vcvars.write_bytes(b"placeholder")
        cache = self.root / "cache"
        cache.mkdir()
        work = self.root / "work-must-not-exist"
        output = self.root / "out-must-not-exist"
        argv = [
            "build-winapp-passive.py",
            "--source-archive", str(archive),
            "--dotnet", str(dotnet),
            "--vcvars", str(vcvars),
            "--work", str(work),
            "--output", str(output),
            "--cache", str(cache),
        ]
        with mock.patch("sys.argv", argv):
            with self.assertRaisesRegex(ValueError, r"requires Windows x64"):
                BUILD.main()
        self.assertFalse(work.exists())
        self.assertFalse(output.exists())

    def _run_synthetic_pipeline(self, exact_red_override: str | None = None, profile: str = "exact-passive"):
        prefix = "winappCli-" + BUILD.COMMIT
        archive_path = self.root / "winapp-source.zip"
        upstream = synthesize_upstream_files()
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel, content in upstream.items():
                zf.writestr(f"{prefix}/{rel}", content.encode("utf-8"))
        archive_sha = BUILD.digest(archive_path).hex()

        fake_dotnet = self.root / "dotnet.exe"
        fake_dotnet.write_bytes(b"fake-dotnet-host")
        fake_vcvars = self.root / "vcvars64.bat"
        fake_vcvars.write_text("@echo off\r\n", encoding="utf-8")

        cache = self.root / "nuget-cache"
        pins_file = self.root / "build-package-pins.json"
        pack_names = list(BUILD.PACK_PINS.keys())
        pin_files = {}
        pack_pins = {}
        for idx, nupkg_name in enumerate(pack_names):
            pkg_id = nupkg_name[: -(len("." + BUILD.RUNTIME + ".nupkg"))]
            pkg_dir = cache / pkg_id / BUILD.RUNTIME
            pkg_dir.mkdir(parents=True)
            nupkg = pkg_dir / nupkg_name
            with zipfile.ZipFile(nupkg, "w") as zf:
                zf.writestr("LICENSE.TXT", f"MIT license for {pkg_id}\n")
                zf.writestr("THIRD-PARTY-NOTICES.TXT", f"Notices for {pkg_id}\n")
            sha256 = BUILD.digest(nupkg).hex()
            sha512 = base64.b64encode(BUILD.digest(nupkg, "sha512")).decode()
            Path(str(nupkg) + ".sha512").write_text(sha512 + "\n", encoding="utf-8")
            pin_files[nupkg_name] = {"sha256": sha256, "size": nupkg.stat().st_size, "sha512": sha512}
            pack_pins[nupkg_name] = sha256

        # Copy native/winapp-patches into a synthetic repo root so real patches and
        # contracts are exercised while using the synthetic build-package-pins.json.
        fake_repo = self.root / "repo"
        shutil.copytree(PATCHES_DIR, fake_repo / "native/winapp-patches")
        (fake_repo / "native/winapp-patches/build-package-pins.json").write_text(
            json.dumps({
                "schema": 1,
                "upstream_commit": BUILD.COMMIT,
                "sdk_version": BUILD.SDK,
                "runtime_version": BUILD.RUNTIME,
                "files": pin_files,
            }),
            encoding="utf-8",
        )
        fake_script = fake_repo / "scripts/rust/build-winapp-passive.py"
        fake_script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, fake_script)

        skia_bytes = b"synthetic-skia-dll"
        skia_sha = sha256_bytes(skia_bytes)
        work = self.root / "work"
        output = self.root / "out"

        def fake_subprocess_run(command, cwd=None, env=None, stdout=None, stderr=None, creationflags=0):
            cmd = [str(c) for c in command]
            src_root = work / "source"
            ss_text = (src_root / BUILD.TARGET).read_text(encoding="utf-8")
            keys_text = (src_root / BUILD.MESSAGE_TARGET).read_text(encoding="utf-8")
            uas_text = (src_root / "src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs").read_text(encoding="utf-8")
            cmd_text = (src_root / "src/winapp-CLI/WinApp.Cli/Commands/UiScreenshotCommand.cs").read_text(encoding="utf-8")

            def emit(text: str, code: int):
                stdout.write(text)
                return mock.Mock(returncode=code)

            if cmd[1:] == ["--version"]:
                return emit(BUILD.SDK + "\n", 0)
            if len(cmd) >= 2 and cmd[1] == "build":
                out_dir = Path(cmd[cmd.index("-o") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "WinApp.Cli.Tests.dll").write_bytes(b"built-harness")
                return emit("Build succeeded.\n", 0)
            if len(cmd) >= 2 and cmd[1].endswith("contract-run\\WinApp.Cli.Tests.dll") or (len(cmd) >= 2 and cmd[1].endswith("contract-run/WinApp.Cli.Tests.dll")):
                mode = cmd[2] if len(cmd) > 2 else ""
                if mode == "":
                    ok = "minimized; it was not restored" in ss_text and "focus was not changed" in ss_text
                    return emit("RESULT failures=0\n" if ok else "RESULT failures=3\n", 0 if ok else 1)
                if mode == "--background":
                    ok = 'new("--no-focus")' in keys_text
                    return emit("RESULT failures=0\n" if ok else "RESULT failures=1\n", 0 if ok else 1)
                if mode == "--uia-background":
                    ok = "void DisableAutoFocus()" in uas_text
                    return emit("RESULT failures=0\n" if ok else "RESULT failures=3\n", 0 if ok else 1)
            if len(cmd) >= 2 and (cmd[1].endswith("exact-passive-run\\WinApp.Cli.Tests.dll") or cmd[1].endswith("exact-passive-run/WinApp.Cli.Tests.dll")):
                ok = 'new("--exact-passive")' in cmd_text and "VerifyExactPassiveTarget" in ss_text
                if not ok and exact_red_override is not None:
                    return emit(exact_red_override, 1)
                return emit("RESULT failures=0\n" if ok else "RESULT failures=2\n", 0 if ok else 1)
            if cmd[-1].endswith("publish-hidden.cmd"):
                publish = work / "publish"
                publish.mkdir(parents=True, exist_ok=True)
                (publish / "winapp.exe").write_bytes(b"synthetic-winapp-aot-3")
                (publish / "libSkiaSharp.dll").write_bytes(skia_bytes)
                # Populate restored NuGet packages and project.assets.json.
                libraries = {}
                downloads = []
                for nupkg_name, rec in pin_files.items():
                    pkg_id = nupkg_name[: -(len("." + BUILD.RUNTIME + ".nupkg"))]
                    dst = work / "packages" / pkg_id / BUILD.RUNTIME / nupkg_name
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(work / "feed" / nupkg_name, dst)
                    if pkg_id.startswith("microsoft.netcore"):
                        downloads.append({"name": pkg_id, "version": f"[{BUILD.RUNTIME}, {BUILD.RUNTIME}]"})
                    else:
                        libraries[f"{pkg_id}/{BUILD.RUNTIME}"] = {"type": "package", "sha512": rec["sha512"]}
                assets_path = src_root / "src/winapp-CLI/WinApp.Cli/obj/project.assets.json"
                assets_path.parent.mkdir(parents=True, exist_ok=True)
                assets_path.write_text(
                    json.dumps({
                        "libraries": libraries,
                        "project": {"frameworks": {"net10.0-windows10.0.19041.0": {"downloadDependencies": downloads}}},
                    }),
                    encoding="utf-8",
                )
                return emit("Published synthetic NativeAOT binary.\n", 0)
            raise AssertionError(f"unexpected subprocess command: {cmd}")

        argv = [
            "build-winapp-passive.py",
            "--source-archive", str(archive_path),
            "--dotnet", str(fake_dotnet),
            "--vcvars", str(fake_vcvars),
            "--work", str(work),
            "--output", str(output),
            "--cache", str(cache),
            "--profile", profile,
        ]
        with (
            mock.patch.object(BUILD, "__file__", str(fake_script)),
            mock.patch.object(BUILD, "ARCHIVE_SHA256", archive_sha),
            mock.patch.object(BUILD, "SKIA_SHA256", skia_sha),
            mock.patch.object(BUILD, "PACK_PINS", pack_pins),
            mock.patch.object(BUILD.subprocess, "run", side_effect=fake_subprocess_run),
            mock.patch("sys.argv", argv),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            BUILD.main()
        return work, output, upstream

    @unittest.skipUnless(os.name == "nt", "Windows NativeAOT build pipeline fixture")
    def test_main_runs_exact_passive_red_green_and_records_provenance(self):
        work, output, upstream = self._run_synthetic_pipeline()
        steps = json.loads((work / "steps.json").read_text(encoding="utf-8"))
        names = [step["name"] for step in steps]
        self.assertIn("exact-passive-build-red", names)
        self.assertIn("exact-passive-red", names)
        self.assertIn("exact-passive-build-green", names)
        self.assertIn("exact-passive-green", names)
        self.assertIn("final-contract-build-green", names)
        self.assertIn("autofocus-final-green", names)
        self.assertLess(names.index("exact-passive-red"), names.index("exact-passive-green"))
        self.assertLess(names.index("exact-passive-green"), names.index("final-contract-build-green"))
        self.assertLess(names.index("final-contract-build-green"), names.index("passive-final-green"))
        self.assertLess(names.index("passive-final-green"), names.index("native-aot-publish"))

        provenance = json.loads((output / "WINAPP-BUILD-PROVENANCE.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["derivative_version"], "0.5.0-agentbridge.3")
        self.assertEqual(provenance["patches"]["0004-exact-passive-window.patch"]["sha256"], PATCH_0004_SHA256)
        self.assertEqual(provenance["contract_sources"]["ExactPassiveContract.cs"]["sha256"], EXACT_CONTRACT_SHA256)
        self.assertEqual(provenance["tests"]["exact_passive_red_failures"], 2)
        self.assertEqual(provenance["tests"]["green_failures"], 0)
        self.assertIn("0004-exact-passive-window.patch", provenance["patch_source_changes"])
        self.assertEqual(
            set(provenance["patch_source_changes"]["0004-exact-passive-window.patch"]),
            set(BUILD.EXACT_PASSIVE_SOURCES),
        )
        # Combined screenshot delta must span pre-0001 -> post-0004.
        pre_0001_sha = sha256_bytes(upstream[BUILD.TARGET].encode("utf-8"))
        post_0004_sha = provenance["patch_source_changes"]["0004-exact-passive-window.patch"][BUILD.TARGET]["after"]["sha256"]
        self.assertEqual(provenance["patched_sources"][BUILD.TARGET]["before"]["sha256"], pre_0001_sha)
        self.assertEqual(provenance["patched_sources"][BUILD.TARGET]["after"]["sha256"], post_0004_sha)
        self.assertIn("-p:Version=0.5.0-agentbridge.3", provenance["build_flags"])
        self.assertIn("-p:NativeDebugSymbols=false", provenance["build_flags"])

    @unittest.skipUnless(os.name == "nt", "Windows NativeAOT build pipeline fixture")
    def test_stable_profile_builds_qualified_derivative_without_native_pdb_reference(self):
        work, output, _ = self._run_synthetic_pipeline(profile="stable")
        names = [step["name"] for step in json.loads((work / "steps.json").read_text(encoding="utf-8"))]
        self.assertFalse([name for name in names if name.startswith("exact-passive")])
        self.assertFalse((work / "inputs/0004-exact-passive-window.patch").exists())
        self.assertLess(names.index("passive-final-green"), names.index("native-aot-publish"))
        provenance = json.loads((output / "WINAPP-BUILD-PROVENANCE.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["derivative_version"], "0.5.0-agentbridge.2")
        self.assertEqual(provenance["build_profile"], "stable")
        self.assertEqual(set(provenance["patches"]), set(BUILD.STABLE_PATCHES))
        self.assertNotIn("exact_passive_red_failures", provenance["tests"])
        self.assertNotIn("ExactPassiveContract.cs", provenance["contract_sources"])
        self.assertIn("-p:Version=0.5.0-agentbridge.2", provenance["build_flags"])
        self.assertIn("-p:NativeDebugSymbols=false", provenance["build_flags"])
        publish_batch = (work / "publish-hidden.cmd").read_text(encoding="utf-8")
        self.assertIn("-p:NativeDebugSymbols=false", publish_batch)

    @unittest.skipUnless(os.name == "nt", "Windows NativeAOT build pipeline fixture")
    def test_main_refuses_when_exact_passive_red_failure_count_is_wrong(self):
        with self.assertRaisesRegex(ValueError, "exact-passive"):
            self._run_synthetic_pipeline(exact_red_override="RESULT failures=1\n")
        self.assertFalse((self.root / "out").exists())


if __name__ == "__main__":
    unittest.main()
