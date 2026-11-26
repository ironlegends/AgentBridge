#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the native application with verified, autonomous automation resources."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import release_components as resources

APP = "agent-bridge-desktop-app"
TARGET = "x86_64-pc-windows-msvc"
ZIP_DATE = (2026, 1, 1, 0, 0, 0)
SPEC = importlib.util.spec_from_file_location("agent_bridge_release_common", Path(__file__).with_name("package-rust.py"))
COMMON = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMMON
SPEC.loader.exec_module(COMMON)


def git_identity(repo: Path) -> dict:
    def git(*args):
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)
        return result.stdout
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("release requires a clean committed source tree")
    identity = {"commit": git("rev-parse", "HEAD").decode().strip(),
                "tree": git("rev-parse", "HEAD^{tree}").decode().strip()}
    if any(not re.fullmatch("[0-9a-f]{40}", value) for value in identity.values()):
        raise ValueError("release source identity is invalid")
    return identity


def stage_records(stage: Path) -> list[dict]:
    records, folded = [], set()
    for name in sorted(resources.inventory(stage)):
        resources.relative_path(name)
        if name.lower() in folded:
            raise ValueError("application package contains a case collision")
        folded.add(name.lower())
        source = stage / name
        records.append({"path": name, "bytes": resources.plain(source, False).st_size, "sha256": resources.digest(source)})
    return records


def write_archive(stage: Path, destination: Path, records: list[dict]) -> str:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("release archive already exists")
    resources.plain_root(destination.parent)
    resources.relative_path(stage.name)
    if resources.inventory(stage) != {r["path"] for r in records}:
        raise ValueError("application files changed after qualification")
    with tempfile.TemporaryDirectory(prefix=".ab-desktop-archive-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "release.zip"
        with staged.open("xb") as raw:
            with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for record in records:
                    relative = resources.relative_path(record["path"])
                    source = stage / relative
                    resources.plain_root(source.parent)
                    before = resources.plain(source, False)
                    info = zipfile.ZipInfo(stage.name + "/" + relative, ZIP_DATE)
                    info.create_system = 3
                    info.external_attr = (0o100755 if relative.endswith(".exe") else 0o100644) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    digest, count = hashlib.sha256(), 0
                    with source.open("rb") as reader, archive.open(info, "w", force_zip64=True) as writer:
                        if not os.path.samestat(before, os.fstat(reader.fileno())):
                            raise ValueError("archive source changed before reading")
                        while chunk := reader.read(64 * 1024):
                            count += len(chunk)
                            if count > record["bytes"]:
                                raise ValueError("archive input size changed")
                            digest.update(chunk)
                            writer.write(chunk)
                    if count != record["bytes"] or digest.hexdigest() != record["sha256"]:
                        raise ValueError("archive input digest changed")
            raw.flush()
            os.fsync(raw.fileno())
        digest = resources.digest(staged)
        os.link(staged, destination)
    return digest


def frontend_files(repo: Path, env: dict[str, str]) -> list[Path]:
    # Tauri compresses these files into the executable, out of reach of the
    # byte scan of the staged files, so their sources are scanned instead.
    # tauri-build merges TAURI_CONFIG and platform configuration files, which
    # could embed another frontend; only the base configuration is admitted.
    if any(key.upper() == "TAURI_CONFIG" for key in env):
        raise ValueError("TAURI_CONFIG is not admitted for release packaging")
    others = [path.name for path in (repo / "app/src-tauri").iterdir()
              if path.name.lower().startswith("tauri") and path.name != "tauri.conf.json"]
    if others:
        raise ValueError("only app/src-tauri/tauri.conf.json is admitted as Tauri configuration")
    config = json.loads((repo / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    frontend = (repo / "app/src-tauri" / config["build"]["frontendDist"]).resolve()
    if not frontend.is_dir() or not frontend.is_relative_to(repo.resolve()):
        raise ValueError("Tauri frontendDist must be a directory of the checkout")
    return sorted(path for path in frontend.rglob("*") if path.is_file())


def assert_no_private_paths(stage: Path, records: list[dict], roots: list[Path], embedded: list[Path] = ()) -> None:
    staged = ((record["path"], (stage / resources.relative_path(record["path"])).read_bytes()) for record in records)
    sources = (("embedded " + path.name, path.read_bytes()) for path in embedded)
    COMMON.assert_no_private_content(itertools.chain(staged, sources), roots)


def write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as writer:
        json.dump(value, writer, indent=2, sort_keys=True, ensure_ascii=False)
        writer.write("\n")


def publish_stage(source: Path, destination: Path) -> None:
    destination.mkdir()
    try:
        for item in source.iterdir():
            item.rename(destination / item.name)
    except BaseException:
        shutil.rmtree(destination)
        raise


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--browser-bundle", type=Path, required=True)
    parser.add_argument("--browser-manifest-sha256", required=True)
    parser.add_argument("--native-bundle", type=Path, required=True)
    parser.add_argument("--native-manifest-sha256", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True, help="New isolated Cargo target directory; an existing directory is refused.")
    parser.add_argument("--rust-stdlib-notice")
    parser.add_argument("--release-channel", choices=COMMON.RELEASE_CHANNELS, default="development",
                        help="Channel compiled into the status tools; only signed releases use stable.")
    parser.add_argument("--ack-review", action="append", default=[])
    args = parser.parse_args(argv)
    repo, output = args.repo.absolute(), args.out_dir.absolute()
    resources.plain_root(repo)
    resources.plain_root(output)
    resources.plain_root(args.build_dir.absolute().parent)
    manifest = repo / "app/src-tauri/Cargo.toml"
    resources.plain(manifest, False)
    source = git_identity(repo)
    for kind in ("browser", "native"):
        resources.component_files(getattr(args, kind + "_bundle"), getattr(args, kind + "_manifest_sha256"), kind)
    cargo, rustc, env = COMMON.configured_tools()
    workspace, package_id, version = COMMON.cargo_workspace_package(manifest, cargo, env, APP)
    if workspace != manifest.parent.resolve():
        raise ValueError("selected application workspace is unexpected")
    compiler, sysroot = COMMON.rustc_identity(rustc, env)
    frontend = frontend_files(repo, env)
    name = f"agent-bridge-{version}-windows-x64-{source['commit'][:12]}"
    folder, archive_path = output / name, output / (name + ".zip")
    config_path = output / (name + ".tauri-resources.json")
    if any(path.exists() or path.is_symlink() for path in (folder, archive_path, config_path, args.build_dir)):
        raise FileExistsError("release destination or build directory already exists")
    diagnostics = Path(tempfile.mkdtemp(prefix=name + "-diagnostics-", dir=output))
    write_json(diagnostics / "source.json", source)
    with tempfile.TemporaryDirectory(prefix=".ab-desktop-stage-", dir=output) as temporary:
        temporary = Path(temporary)
        notice_stage = temporary / "rust-notices"
        index = COMMON.run_release_notices(manifest, TARGET, notice_stage, env, APP, repo, diagnostics)
        write_json(diagnostics / "notices-index.json", index)
        if (index.get("package"), index.get("version"), index.get("target")) != (APP, version, TARGET):
            raise ValueError("notice collector differs from application metadata")
        root_files = {filename: COMMON.require_regular_file(repo / filename, filename, COMMON.MAX_TEXT_FILE_BYTES)
                      for filename in ("LICENSE", "NOTICE", "README.md")}
        if b"Apache License" not in root_files["LICENSE"] or b"Version 2.0" not in root_files["LICENSE"]:
            raise ValueError("application license is not Apache-2.0")
        blocking, unacknowledged, acknowledged = COMMON.evaluate_anomalies(index, root_files["NOTICE"].decode("utf-8"), set(args.ack_review))
        if blocking or unacknowledged:
            print(json.dumps({"status": "refused", "blocking": blocking, "unacknowledged_review": unacknowledged,
                              "diagnostics": str(diagnostics)}, indent=2))
            return 2
        flags = env.get("CARGO_ENCODED_RUSTFLAGS", "").split(chr(31)) if env.get("CARGO_ENCODED_RUSTFLAGS") else env.get("RUSTFLAGS", "").split()
        COMMON.remap_source_root(flags, repo, TARGET, "agent-bridge")
        env["CARGO_ENCODED_RUSTFLAGS"] = chr(31).join(flags)
        artifact = COMMON.cargo_build_artifact(manifest, TARGET, cargo, env, package_id, args.build_dir.absolute(), False, APP, diagnostics / "build",
                                              release_channel=args.release_channel)
        if git_identity(repo) != source or COMMON.rustc_identity(rustc, env) != (compiler, sysroot):
            raise ValueError("source or compiler identity changed during build")
        binary_name, binary = COMMON.verify_binary(artifact, TARGET, APP)
        resources.verify_gui_image(binary)
        stdlib, stdlib_source = COMMON.runtime_notice(sysroot, args.rust_stdlib_notice)
        stage = temporary / name
        components = resources.stage_resources(args.browser_bundle, args.browser_manifest_sha256,
                                              args.native_bundle, args.native_manifest_sha256, stage)
        (stage / binary_name).write_bytes(binary)
        for filename, contents in root_files.items():
            (stage / filename).write_bytes(contents)
        notices, packages = COMMON.collect_notice_entries(notice_stage, index, name)
        for entry in notices:
            relative = resources.relative_path(entry.arcname.removeprefix(name + "/"))
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as writer:
                writer.write(entry.data)
        stdlib_path = stage / COMMON.RUST_STDLIB_NOTICE_ARCNAME
        stdlib_path.parent.mkdir(parents=True, exist_ok=True)
        stdlib_path.write_bytes(stdlib)
        build = {"command": "cargo build", "profile": "release", "locked": True, "offline": True,
                 "isolated_target": True, "target": TARGET, "rustc": compiler,
                 "release_channel": args.release_channel}
        rust_notices = {"package": APP, "package_id": f"{APP}@{version}", "version": version, "target": TARGET,
                        "build": build, "rustc": compiler, "packages": packages, "sqlite": index.get("sqlite", []),
                        "acknowledged_reviews": acknowledged,
                        "binary": {"name": binary_name, "sha256": hashlib.sha256(binary).hexdigest()},
                        "rust_stdlib_notice": {"packaged": COMMON.RUST_STDLIB_NOTICE_ARCNAME,
                                               "sha256": hashlib.sha256(stdlib).hexdigest(),
                                               "size": len(stdlib), "resolution": stdlib_source}}
        write_json(stage / "notices/index.json", rust_notices)
        release = {"schema": 1, "application": APP, "version": version, "source": source, "build": build,
                   "binary": {"path": binary_name, "sha256": hashlib.sha256(binary).hexdigest(), "subsystem": "windows-gui"},
                   "components": components,
                   "rust_notices": {"path": "notices/index.json", "sha256": resources.digest(stage / "notices/index.json")},
                   "files": stage_records(stage)}
        write_json(stage / "release-manifest.json", release)
        records = stage_records(stage)
        assert_no_private_paths(stage, records, [Path.home(), repo, args.build_dir.absolute(), output,
                                                 Path(env.get("CARGO_HOME", Path.home() / ".cargo")), sysroot,
                                                 args.browser_bundle, args.native_bundle],
                                frontend)
        if git_identity(repo) != source:
            raise ValueError("source identity changed before publication")
        digest = write_archive(stage, archive_path, records)
        publish_stage(stage, folder)
    config = resources.tauri_resources(folder)
    mappings = config["bundle"]["resources"]
    for filename in ("LICENSE", "NOTICE", "README.md", "release-manifest.json"):
        mappings[(folder / filename).as_posix()] = filename
    mappings[(folder / "notices").as_posix() + "/"] = "notices/"
    write_json(config_path, config)
    print(json.dumps({"status": "packaged", "application": str(folder / binary_name), "archive": str(archive_path),
                      "sha256": digest, "source": source, "manifest_sha256": resources.digest(folder / "release-manifest.json"),
                      "tauri_resources_config": str(config_path), "diagnostics": str(diagnostics)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as error:
        print(json.dumps({"status": "error", "detail": str(error)}), file=sys.stderr)
        raise SystemExit(1)
