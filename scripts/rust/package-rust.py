#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and package the exact offline Cargo artifact for the Rust `agent-bridge` CLI.

Reuses
`scripts/rust/release-notices.py` to collect offline Cargo dependency notices
and refuses to emit an archive whenever blocking notice issues or
unacknowledged review items remain.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PACKAGE_NAME = "agent-bridge"
FIXED_MTIME = 1767225600  # 2026-01-01T00:00:00Z
ZIP_FIXED_DATETIME = (2026, 1, 1, 0, 0, 0)
MAX_TEXT_FILE_BYTES = 512 * 1024
# The official Rust standard-library attribution HTML is about 1.5 MiB;
# it must not be subjected to the smaller crate-notice text limit.
MAX_RUST_STDLIB_NOTICE_BYTES = 4 * 1024 * 1024
RUST_STDLIB_NOTICE_ARCNAME = "notices/rust-std/COPYRIGHT-library.html"

TARGET_RE = re.compile(r"^[A-Za-z0-9_]+-[A-Za-z0-9_]+-[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)?$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")

BLOCKING_CODES = {
    "missing_cached_source",
    "oversized_notice_skipped",
    "missing_license_metadata",
    "no_notice_file_found",
}
REVIEW_CODES = {
    "custom_license_file",
    "license_exception_present",
    "non_registry_source",
    "sqlite_native_check",
    "native_links_check",
}

PE_TARGETS = {
    "x86_64": (0x8664, 0x020B),
    "aarch64": (0xAA64, 0x020B),
    "i686": (0x014C, 0x010B),
    "i586": (0x014C, 0x010B),
}
ELF_TARGETS = {
    "x86_64": (2, 1, 62),
    "aarch64": (2, 1, 183),
    "i686": (1, 1, 3),
    "i586": (1, 1, 3),
    "armv7": (1, 1, 40),
    "arm": (1, 1, 40),
    "riscv64gc": (2, 1, 243),
    "riscv64": (2, 1, 243),
}
MACHO_TARGETS = {
    "x86_64": 0x01000007,
    "aarch64": 0x0100000C,
}


@dataclass(frozen=True)
class ArchiveEntry:
    arcname: str
    data: bytes
    mode: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_target(target: str) -> tuple[str, str]:
    if not TARGET_RE.match(target):
        raise ValueError(f"invalid Rust target triple: {target!r}")
    parts = target.split("-")
    arch, os_name = parts[0], parts[2]
    if os_name == "windows":
        if arch not in PE_TARGETS:
            raise ValueError(f"unsupported Windows target architecture: {arch!r}")
        return arch, "windows"
    if os_name == "darwin":
        if arch not in MACHO_TARGETS:
            raise ValueError(f"unsupported Darwin target architecture: {arch!r}")
        return arch, "darwin"
    if os_name in {"linux", "freebsd", "netbsd", "openbsd"}:
        if arch not in ELF_TARGETS:
            raise ValueError(f"unsupported ELF target architecture: {arch!r}")
        return arch, "elf"
    raise ValueError(f"unsupported target OS family in triple: {target!r}")


def require_regular_file(path: Path, label: str, max_bytes: int | None = None) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be an existing regular non-symlink file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise ValueError(f"{label} must not be empty: {path}")
    if max_bytes is not None and size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes: {path}")
    return path.read_bytes()


def read_rust_stdlib_notice(raw_path: str | Path) -> bytes:
    """Read the official Rust toolchain attribution document provided by the operator.

    The path comes from the compiler sysroot, or an explicit operator override
    that is checked against the sysroot copy when that copy is available.
    """
    source = Path(raw_path)
    if not source.is_absolute() or source.parts[-4:] != (
        "share", "doc", "rust", "COPYRIGHT-library.html"
    ):
        raise ValueError(
            "--rust-stdlib-notice requires an absolute toolchain "
            "share/doc/rust/COPYRIGHT-library.html path"
        )
    if source.is_symlink():
        raise ValueError("--rust-stdlib-notice must not be a symbolic link")
    data = require_regular_file(
        source, "Rust standard-library copyright HTML", MAX_RUST_STDLIB_NOTICE_BYTES
    )
    # A 1.5 MiB HTML page must be read in full, not truncated to the
    # 512 KiB limit used by ordinary crate license/notice text.
    if len(data) < 512 * 1024:
        raise ValueError("Rust standard-library copyright HTML is unexpectedly short")
    try:
        html = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Rust standard-library copyright HTML is not UTF-8") from exc
    if "<html" not in html[:4096].lower():
        raise ValueError("Rust standard-library copyright source is not HTML")
    if sha256_file(source) != sha256_bytes(data):
        raise RuntimeError("Rust standard-library copyright changed while being read")
    return data


def verify_binary(binary_path: Path, target: str, package_name: str = PACKAGE_NAME) -> tuple[str, bytes]:
    """Read exactly one Cargo-emitted executable and validate that SAME image."""
    arch, os_family = parse_target(target)
    if binary_path.is_symlink() or not binary_path.is_file():
        raise ValueError("Cargo executable is missing or is a symbolic link")

    expected_name = f"{package_name}.exe" if os_family == "windows" else package_name
    matches_name = (
        binary_path.name.lower() == expected_name
        if os_family == "windows" else binary_path.name == expected_name
    )
    if not matches_name:
        raise ValueError("Cargo artifact filename does not match target binary")

    # This is the only read of the executable. Header validation, SHA-256
    # and archive packaging all use these identical, immutable in-memory bytes.
    binary = binary_path.read_bytes()
    if len(binary) < 64:
        raise ValueError("Cargo executable is too short")
    if os_family == "windows":
        dos = binary[:64]
        if dos[:2] != b"MZ":
            raise ValueError("Cargo executable lacks Windows MZ header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 26 > len(binary):
            raise ValueError("Cargo executable has invalid PE header offset")
        pe = binary[pe_offset:pe_offset + 26]
        if pe[:4] != b"PE\x00\x00":
            raise ValueError("Cargo executable lacks PE signature")
        machine, _, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", pe, 4)
        if (characteristics & 0x0002) == 0 or (characteristics & 0x2000) != 0:
            raise ValueError("Cargo PE artifact is not a standalone executable")
        if opt_size < 2:
            raise ValueError("Cargo PE artifact lacks optional header")
        opt_magic = struct.unpack_from("<H", pe, 24)[0]
        if (machine, opt_magic) != PE_TARGETS[arch]:
            raise ValueError("Cargo executable does not match target PE architecture")
    elif os_family == "elf":
        hdr = binary[:20]
        if hdr[:4] != b"\x7fELF":
            raise ValueError("Cargo artifact lacks ELF magic")
        ei_class, ei_data = hdr[4], hdr[5]
        endian = "<" if ei_data == 1 else ">" if ei_data == 2 else ""
        if not endian:
            raise ValueError("Cargo ELF artifact has invalid endianness")
        e_type, e_machine = struct.unpack_from(f"{endian}HH", hdr, 16)
        if e_type not in (2, 3) or (ei_class, ei_data, e_machine) != ELF_TARGETS[arch]:
            raise ValueError("Cargo ELF artifact does not match target architecture")
    else:
        hdr = binary[:16]
        magic_be = struct.unpack_from(">I", hdr, 0)[0]
        if magic_be == 0xFEEDFACF:
            endian = ">"
        elif magic_be == 0xCFFAEDFE:
            endian = "<"
        else:
            raise ValueError("Cargo artifact is not thin 64-bit Mach-O")
        cputype, _, filetype = struct.unpack_from(f"{endian}III", hdr, 4)
        if filetype != 2 or cputype != MACHO_TARGETS[arch]:
            raise ValueError("Cargo Mach-O artifact does not match target architecture")
    return expected_name, binary


def configured_tools() -> tuple[str, str, dict[str, str]]:
    """Choose exactly the local cargo/rustc commands used throughout packaging."""
    env = os.environ.copy()
    cargo = env.get("CARGO") or "cargo"
    rustc = env.get("RUSTC") or "rustc"
    for label, command in (("CARGO", cargo), ("RUSTC", rustc)):
        if not command or any(ch in command for ch in "\r\n\x00"):
            raise ValueError(f"invalid {label} executable")
        if any(ch in command for ch in ("/", "\\")):
            if not Path(command).is_absolute() or not Path(command).is_file():
                raise ValueError(f"{label} must be a local absolute executable path")
        elif command != label.lower():
            raise ValueError(f"{label} must be a command name or absolute path")

    # The existing first-party notice collector invokes the executable named
    # 'cargo'. Require the same configured executable for both invocations.
    if Path(cargo).is_absolute():
        if Path(cargo).name.lower() not in {"cargo", "cargo.exe"}:
            raise ValueError("configured CARGO must name the cargo executable")
        env["PATH"] = str(Path(cargo).parent) + os.pathsep + env.get("PATH", "")
        helper_cargo = shutil.which("cargo", path=env["PATH"])
        if helper_cargo is None or not os.path.samefile(helper_cargo, cargo):
            raise ValueError("notice collector would use a different Cargo executable")
    if env.get("RUSTC_WRAPPER") or env.get("RUSTC_WORKSPACE_WRAPPER"):
        raise ValueError("compiler wrappers are not admitted for release provenance")
    env["RUSTC"] = rustc
    return cargo, rustc, env


def cargo_workspace_package(
    manifest_path: Path, cargo: str, env: dict[str, str], package_name: str = PACKAGE_NAME,
) -> tuple[Path, str, str]:
    cmd = [
        cargo, "metadata", "--no-deps", "--format-version", "1",
        "--locked", "--offline", "--manifest-path", str(manifest_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                         errors="replace", env=env)
    if res.returncode != 0:
        raise RuntimeError("offline, locked Cargo metadata failed")
    meta = json.loads(res.stdout)
    root = Path(meta["workspace_root"]).resolve()
    if not root.is_dir():
        raise RuntimeError("Cargo workspace root is unavailable")
    members = set(meta["workspace_members"])
    selected = [
        item for item in meta["packages"]
        if item.get("id") in members and item.get("name") == package_name
        and any(
            target.get("name") == package_name and target.get("kind") == ["bin"]
            for target in item.get("targets", [])
        )
    ]
    if len(selected) != 1:
        raise RuntimeError("workspace has no unique agent-bridge binary package")
    selected_package = selected[0]
    version = selected_package["version"]
    if not SEMVER_RE.fullmatch(version):
        raise RuntimeError("Cargo selected package version is invalid")
    # Retain the complete id ONLY for in-memory comparison to Cargo's artifact.
    # The published portable package_id is 'agent-bridge@<version>'.
    return root, selected_package["id"], version


def rustc_identity(rustc: str, env: dict[str, str]) -> tuple[dict[str, str], Path]:
    version_result = subprocess.run(
        [rustc, "-vV"], capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )
    if version_result.returncode != 0:
        raise RuntimeError("configured rustc version query failed")
    lines = version_result.stdout.splitlines()
    version = next(
        (line.removeprefix("release: ").strip()
         for line in lines if line.startswith("release: ")), None
    )
    commit = next(
        (line.removeprefix("commit-hash: ").strip()
         for line in lines if line.startswith("commit-hash: ")), None
    )
    host = next(
        (line.removeprefix("host: ").strip()
         for line in lines if line.startswith("host: ")), None
    )
    if not version or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
        raise RuntimeError("rustc release version cannot be established")
    if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("rustc commit hash cannot be established")
    if not host or not TARGET_RE.fullmatch(host):
        raise RuntimeError("rustc host target cannot be established")
    sysroot_result = subprocess.run(
        [rustc, "--print", "sysroot"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    if sysroot_result.returncode != 0:
        raise RuntimeError("configured rustc sysroot query failed")
    sysroot_text = sysroot_result.stdout.strip()
    if len(sysroot_text.splitlines()) != 1 or not Path(sysroot_text).is_absolute():
        raise RuntimeError("rustc sysroot must resolve to one absolute directory")
    sysroot = Path(sysroot_text).resolve()
    if not sysroot.is_dir():
        raise RuntimeError("rustc sysroot directory does not exist")
    return {"version": version, "commit": commit, "host": host}, sysroot


def runtime_notice(
    sysroot: Path, override: str | None
) -> tuple[bytes, str]:
    derived = sysroot / "share" / "doc" / "rust" / "COPYRIGHT-library.html"
    if override is None:
        if not derived.is_file():
            raise ValueError(
                "rustc sysroot has no standard-library notice; "
                "supply an explicit --rust-stdlib-notice"
            )
        return read_rust_stdlib_notice(derived), "rustc_sysroot"

    explicit = Path(override)
    data = read_rust_stdlib_notice(explicit)
    if derived.is_file():
        # An override must not silently substitute another compiler's notices
        # when this sysroot supplies an authoritative document.
        if sha256_file(derived) != sha256_bytes(data):
            raise ValueError("explicit Rust standard-library notice differs from rustc sysroot")
        return data, "explicit_matches_sysroot"
    # Where a minimal sysroot omits the HTML, the operator must explicitly
    # select its toolchain document; the index records this provenance limit.
    return data, "operator_supplied"


def virtual_source_root(target: str, name: str) -> str:
    # A slash-only remap destination is not an absolute Windows path. Some
    # macros normalize file!() paths against the manifest directory, restoring
    # the private checkout prefix. Use an absolute virtual drive path there.
    if "-windows-" in target:
        return "C:/agent-bridge-build/" + name
    return "/" + name


def remap_source_root(flags: list[str], path: Path, target: str, name: str) -> None:
    original = path.resolve()
    for spelling in sorted({str(original), original.as_posix()}):
        flags.append(f"--remap-path-prefix={spelling}={virtual_source_root(target, name)}")


def cargo_build_artifact(
    manifest_path: Path, target: str, cargo: str, env: dict[str, str],
    cargo_package_id: str, target_dir: Path, zigbuild: bool,
    package_name: str = PACKAGE_NAME,
    diagnostics: Path | None = None,
) -> Path:
    """Run one clean, offline release build and bind its compiler-artifact."""
    cmd = [
        cargo, "zigbuild" if zigbuild else "build",
        "--locked", "--offline", "--release",
        "--manifest-path", str(manifest_path),
        "--target", target, "-p", package_name,
        "--message-format=json",
    ]
    build_env = env.copy()
    # Never reuse a pre-existing target/release binary or an arbitrary
    # CARGO_TARGET_DIR supplied by the environment.
    build_env["CARGO_TARGET_DIR"] = str(target_dir)
    # Panic locations can include absolute source paths from Cargo's registry.
    # Use stable release paths in the delivered executable on every platform.
    existing = build_env.get("CARGO_ENCODED_RUSTFLAGS")
    flags = existing.split(chr(31)) if existing else build_env.get("RUSTFLAGS", "").split()
    roots = (
        (Path(build_env.get("CARGO_HOME", Path.home() / ".cargo")), "cargo"),
        (manifest_path.parent, "agent-bridge"),
        (target_dir, "build"),
    )
    for root, name in roots:
        remap_source_root(flags, root, target, name)
    build_env["CARGO_ENCODED_RUSTFLAGS"] = chr(31).join(flags)
    if target_dir.exists():
        raise RuntimeError("Cargo build staging directory already exists")
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=build_env,
    )
    if diagnostics is not None:
        diagnostics.mkdir(parents=True, exist_ok=False)
        (diagnostics / "cargo-build.jsonl").write_text(res.stdout, encoding="utf-8")
        (diagnostics / "cargo-build.stderr.log").write_text(res.stderr, encoding="utf-8")
        (diagnostics / "cargo-build.exit.json").write_text(json.dumps({"exit_code": res.returncode}) + "\n", encoding="utf-8")
    if res.returncode != 0:
        raise RuntimeError("locked offline Cargo release build failed")
    if len(res.stdout) > 64 * 1024 * 1024:
        raise RuntimeError("Cargo JSON build output exceeds safe limit")

    artifacts: list[Path] = []
    finished = []
    expected_root = (target_dir / target / "release").resolve()
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Cargo build produced non-JSON machine output") from exc
        if not isinstance(message, dict):
            raise RuntimeError("Cargo build produced an invalid JSON message")
        reason = message.get("reason")
        if reason == "build-finished":
            finished.append(message.get("success") is True)
        elif reason == "compiler-artifact":
            if message.get("package_id") != cargo_package_id:
                continue
            unit = message.get("target")
            if not isinstance(unit, dict) or unit.get("name") != package_name:
                continue
            if unit.get("kind") != ["bin"] or unit.get("crate_types") != ["bin"]:
                raise RuntimeError("Cargo reported an unexpected agent-bridge target")
            if message.get("fresh") is not False:
                raise RuntimeError("clean Cargo release artifact was not freshly built")
            profile = message.get("profile")
            if not isinstance(profile, dict) or profile.get("opt_level") != "3":
                raise RuntimeError("Cargo artifact is not an optimized release binary")
            executable = message.get("executable")
            filenames = message.get("filenames")
            if not isinstance(executable, str) or not isinstance(filenames, list) or executable not in filenames:
                raise RuntimeError("Cargo binary artifact has no matching executable")
            source = Path(executable)
            if not source.is_absolute() or source.is_symlink() or not source.is_file():
                raise RuntimeError("Cargo executable path is absent or unqualified")
            resolved = source.resolve()
            if resolved.parent != expected_root:
                raise RuntimeError("Cargo executable is outside the isolated target release directory")
            artifacts.append(resolved)
    if finished != [True] or len(artifacts) != 1:
        raise RuntimeError("Cargo did not produce exactly one successful agent-bridge binary artifact")
    return artifacts[0]


def run_release_notices(
    manifest_path: Path,
    target: str,
    staging_dir: Path,
    env: dict[str, str],
    package_name: str = PACKAGE_NAME,
    project_root: Path | None = None,
    diagnostics: Path | None = None,
) -> dict[str, Any]:
    helper = Path(__file__).resolve().with_name("release-notices.py")
    if helper.is_symlink() or not helper.is_file():
        raise FileNotFoundError(f"required helper not found: {helper}")

    cmd = [
        sys.executable,
        str(helper),
        "--manifest-path",
        str(manifest_path),
        "--package",
        package_name,
        "--target",
        target,
        "--out-dir",
        str(staging_dir),
    ]
    if project_root is not None:
        cmd.extend(["--project-root", str(project_root)])
    res = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )
    if diagnostics is not None:
        (diagnostics / "notices.stdout.log").write_text(res.stdout, encoding="utf-8")
        (diagnostics / "notices.stderr.log").write_text(res.stderr, encoding="utf-8")
        (diagnostics / "notices.exit.json").write_text(json.dumps({"exit_code": res.returncode}) + "\n", encoding="utf-8")
    if res.returncode != 0:
        raise RuntimeError("offline Cargo license-notice collection failed")

    index_path = staging_dir / "index.json"
    if index_path.is_symlink() or not index_path.is_file():
        raise RuntimeError("release-notices.py did not produce index.json")
    return json.loads(index_path.read_text(encoding="utf-8"))


def evaluate_anomalies(
    index: dict[str, Any],
    rust_notice_text: str,
    acked_reviews: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    blocking: list[dict[str, Any]] = []
    unacked_review: list[dict[str, Any]] = []
    matched_acks: set[str] = set()
    ack_records: list[dict[str, Any]] = []

    for item in index.get("to_verify", []):
        code = str(item.get("code", ""))
        pkg = str(item.get("package", ""))
        key = f"{code}:{pkg}"
        if code in BLOCKING_CODES or code not in REVIEW_CODES:
            blocking.append(item)
        elif key in acked_reviews:
            matched_acks.add(key)
            ack_records.append(item)
        else:
            unacked_review.append(item)

    for sq in index.get("sqlite", []):
        if sq.get("sqlcipher_hint"):
            blocking.append(
                {
                    "package": sq.get("package", "sqlite"),
                    "code": "sqlcipher_detected",
                    "detail": "SQLCipher feature detected; separate BSD/crypto review required",
                }
            )
    if index.get("sqlite") and "sqlite" not in rust_notice_text.lower():
        blocking.append(
            {
                "package": PACKAGE_NAME,
                "code": "rust_notice_missing_sqlite",
                "detail": "SQLite dependency resolved but NOTICE does not mention SQLite",
            }
        )

    unused_acks = sorted(acked_reviews - matched_acks)
    for extra in unused_acks:
        blocking.append(
            {
                "package": extra,
                "code": "unmatched_ack_review",
                "detail": "acknowledged review key does not match any active review item",
            }
        )

    return blocking, unacked_review, ack_records


def collect_notice_entries(
    staging_dir: Path,
    index: dict[str, Any],
    root_prefix: str,
) -> tuple[list[ArchiveEntry], list[dict[str, Any]]]:
    staging_root = staging_dir.resolve()
    entries: list[ArchiveEntry] = []
    seen_arcnames: set[str] = set()
    clean_packages: list[dict[str, Any]] = []

    for pkg in index.get("packages", []):
        clean_notices: list[dict[str, Any]] = []
        for nf in pkg.get("notices", []):
            rel = str(nf["packaged"])
            src = (staging_root / rel).resolve()
            if not src.is_relative_to(staging_root) or src.is_symlink() or not src.is_file():
                raise RuntimeError(f"invalid notice artifact path from release-notices.py: {rel}")
            data = src.read_bytes()
            actual_sha = sha256_bytes(data)
            if actual_sha != nf.get("sha256"):
                raise RuntimeError(f"notice checksum mismatch for {rel}")
            arcname = f"{root_prefix}/{rel}"
            if arcname not in seen_arcnames:
                seen_arcnames.add(arcname)
                entries.append(ArchiveEntry(arcname=arcname, data=data, mode=0o644))
            clean_notices.append({"source": nf["source"], "packaged": rel, "sha256": actual_sha})

        clean_packages.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "workspace": bool(pkg.get("workspace")),
                "dep_kinds": list(pkg.get("dep_kinds", [])),
                "features": list(pkg.get("features", [])),
                "license": pkg.get("license"),
                "license_file": pkg.get("license_file"),
                "links": pkg.get("links"),
                "notices": clean_notices,
            }
        )

    return entries, clean_packages


def write_zip_archive(dest: Path, entries: list[ArchiveEntry]) -> None:
    with dest.open("xb") as raw_fh:
        with zipfile.ZipFile(raw_fh, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for entry in entries:
                info = zipfile.ZipInfo(filename=entry.arcname, date_time=ZIP_FIXED_DATETIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100000 | entry.mode) << 16
                zf.writestr(info, entry.data)
        raw_fh.flush()
        os.fsync(raw_fh.fileno())


def write_targz_archive(dest: Path, entries: list[ArchiveEntry]) -> None:
    with dest.open("xb") as raw_fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
                for entry in entries:
                    info = tarfile.TarInfo(name=entry.arcname)
                    info.size = len(entry.data)
                    info.mtime = FIXED_MTIME
                    info.mode = entry.mode
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tf.addfile(info, io_bytes(entry.data))
        raw_fh.flush()
        os.fsync(raw_fh.fileno())


def io_bytes(data: bytes):
    import io

    return io.BytesIO(data)


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Package the compiled Rust agent-bridge CLI with verified offline notices."
    )
    ap.add_argument(
        "--manifest-path",
        required=True,
        help="Explicit path to workspace or package Cargo.toml.",
    )
    ap.add_argument(
        "--target",
        required=True,
        help="Explicit Rust target triple (e.g. x86_64-pc-windows-msvc).",
    )
    ap.add_argument(
        "--zigbuild",
        action="store_true",
        help="Use cargo zigbuild instead of cargo build, with the same locked offline release inputs.",
    )
    ap.add_argument(
        "--out-dir",
        required=True,
        help="Destination directory for the new archive (must not overwrite an existing archive).",
    )
    ap.add_argument(
        "--rust-stdlib-notice",
        help="Optional absolute override for rustc sysroot's share/doc/rust/COPYRIGHT-library.html.",
    )
    ap.add_argument(
        "--format",
        choices=("auto", "zip", "tar.gz"),
        default="auto",
        help="Archive format (default: zip for Windows targets, tar.gz otherwise).",
    )
    ap.add_argument(
        "--ack-review",
        action="append",
        default=[],
        metavar="CODE:PACKAGE",
        help="Explicitly acknowledge one reviewed non-blocking item from release-notices.py.",
    )
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    manifest_raw = Path(args.manifest_path)
    if manifest_raw.is_symlink():
        raise ValueError("--manifest-path must not be a symlink")
    manifest_path = manifest_raw.resolve()
    if not manifest_path.is_file() or manifest_path.name != "Cargo.toml":
        raise ValueError("--manifest-path must resolve to an existing regular Cargo.toml")

    _, os_family = parse_target(args.target)
    out_raw = Path(args.out_dir)
    if out_raw.is_symlink():
        raise ValueError("--out-dir must not be a symlink")
    out_dir = out_raw.resolve()
    if not out_dir.is_dir():
        raise ValueError("--out-dir must be an existing directory")

    cargo, rustc, tool_env = configured_tools()
    workspace_root, cargo_package_id, version = cargo_workspace_package(
        manifest_path, cargo, tool_env,
    )
    rustc_info, sysroot = rustc_identity(rustc, tool_env)
    fmt = ("zip" if os_family == "windows" else "tar.gz") if args.format == "auto" else args.format
    root_prefix = f"{PACKAGE_NAME}-{version}-{args.target}"
    archive_path = out_dir / f"{root_prefix}.{fmt}"
    if archive_path.exists() or archive_path.is_symlink():
        raise FileExistsError("output archive already exists")

    license_bytes = require_regular_file(workspace_root / "LICENSE", "project LICENSE", MAX_TEXT_FILE_BYTES)
    license_text = license_bytes.decode("utf-8", errors="replace")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        raise ValueError("project LICENSE does not appear to be Apache License 2.0")

    rust_notice_bytes = require_regular_file(workspace_root / "NOTICE", "NOTICE", MAX_TEXT_FILE_BYTES)
    rust_notice_text = rust_notice_bytes.decode("utf-8", errors="strict")

    usage_bytes = require_regular_file(workspace_root / "README.md", "README.md", MAX_TEXT_FILE_BYTES)
    usage_bytes.decode("utf-8", errors="strict")

    acked_reviews = set(args.ack_review)
    for item in acked_reviews:
        if ":" not in item:
            raise ValueError(f"invalid --ack-review format (expected CODE:PACKAGE): {item!r}")

    with tempfile.TemporaryDirectory(prefix="agent-bridge-rust-pkg-") as tmp_root:
        # CARGO_TARGET_DIR is a fresh private directory for this invocation.
        # The exact executable path must be reported by its compiler-artifact.
        build_target_dir = Path(tmp_root) / "cargo-target"
        artifact_path = cargo_build_artifact(
            manifest_path, args.target, cargo, tool_env, cargo_package_id,
            build_target_dir, args.zigbuild,
        )
        after_rustc_info, after_sysroot = rustc_identity(rustc, tool_env)
        if after_rustc_info != rustc_info or after_sysroot != sysroot:
            raise RuntimeError("rustc identity changed during Cargo build")
        binary_name, binary_bytes = verify_binary(artifact_path, args.target)
        rust_stdlib_bytes, rust_stdlib_source = runtime_notice(
            sysroot, args.rust_stdlib_notice,
        )
        rust_stdlib_sha256 = sha256_bytes(rust_stdlib_bytes)

        notice_staging = Path(tmp_root) / "notices-out"
        index = run_release_notices(manifest_path, args.target, notice_staging, tool_env)
        if index.get("package") != PACKAGE_NAME or index.get("version") != version:
            raise RuntimeError("notice collector package/version differs from compiled artifact")
        if index.get("target") != args.target:
            raise RuntimeError("notice collector target differs from compiled artifact")

        blocking, unacked_review, ack_records = evaluate_anomalies(index, rust_notice_text, acked_reviews)
        if blocking or unacked_review:
            report = {
                "status": "refused",
                "package": PACKAGE_NAME,
                "version": version,
                "target": args.target,
                "blocking": blocking,
                "unacknowledged_review": unacked_review,
            }
            print(json.dumps(report, indent=2, ensure_ascii=False), file=sys.stderr)
            return 2

        notice_entries, clean_packages = collect_notice_entries(notice_staging, index, root_prefix)

        packaged_index = {
            "package": PACKAGE_NAME,
            # The Cargo package_id is a local file:// URI. Never serialize it.
            "package_id": f"{PACKAGE_NAME}@{version}",
            "version": version,
            "target": args.target,
            "build": {
                "command": "cargo zigbuild" if args.zigbuild else "cargo build",
                "profile": "release",
                "locked": True,
                "offline": True,
                "target": args.target,
            },
            "rustc": rustc_info,
            "binary": {"name": binary_name, "sha256": sha256_bytes(binary_bytes)},
            "license_sha256": sha256_bytes(license_bytes),
            "notice_sha256": sha256_bytes(rust_notice_bytes),
            "rust_stdlib_notice": {
                "source": "toolchain/share/doc/rust/COPYRIGHT-library.html",
                "resolution": rust_stdlib_source,
                "packaged": RUST_STDLIB_NOTICE_ARCNAME,
                "size": len(rust_stdlib_bytes),
                "sha256": rust_stdlib_sha256,
            },
            "usage_included": True,
            "usage_file": "README.md",
            "packages": clean_packages,
            "sqlite": index.get("sqlite", []),
            "acknowledged_reviews": ack_records,
        }
        index_bytes = (json.dumps(packaged_index, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

        entries: list[ArchiveEntry] = [
            ArchiveEntry(arcname=f"{root_prefix}/{binary_name}", data=binary_bytes, mode=0o755),
            ArchiveEntry(arcname=f"{root_prefix}/LICENSE", data=license_bytes, mode=0o644),
            ArchiveEntry(arcname=f"{root_prefix}/NOTICE", data=rust_notice_bytes, mode=0o644),
            ArchiveEntry(arcname=f"{root_prefix}/notices/index.json", data=index_bytes, mode=0o644),
            ArchiveEntry(
                arcname=f"{root_prefix}/{RUST_STDLIB_NOTICE_ARCNAME}",
                data=rust_stdlib_bytes, mode=0o644,
            ),
            *notice_entries,
        ]
        entries.append(ArchiveEntry(arcname=f"{root_prefix}/README.md", data=usage_bytes, mode=0o644))

        entries.sort(key=lambda e: e.arcname)

        # Build the *complete* archive on the same filesystem as the output.
        # Never open the final name for writing: that can leave a partial file,
        # and a failed exclusive open must not unlink another writer's archive.
        with tempfile.TemporaryDirectory(
            prefix=f".{PACKAGE_NAME}-archive-", dir=out_dir
        ) as archive_staging:
            temp_archive = Path(archive_staging) / archive_path.name
            if fmt == "zip":
                write_zip_archive(temp_archive, entries)
            else:
                write_targz_archive(temp_archive, entries)

            archive_sha256 = sha256_file(temp_archive)
            # Atomic exclusive publication on Windows (NTFS) and Unix: the
            # destination link is created only when absent. Unlike rename,
            # this cannot replace an archive that arrived during assembly.
            # A hard-link failure is a refusal, not a fallback to a copy or
            # destructive replacement. TemporaryDirectory removes only OUR
            # unpublished staging file, never the final archive.
            os.link(temp_archive, archive_path)

    summary = {
        "status": "packaged",
        "archive": str(archive_path),
        "sha256": archive_sha256,
        "format": fmt,
        "package": PACKAGE_NAME,
        "package_id": f"{PACKAGE_NAME}@{version}",
        "version": version,
        "target": args.target,
        "rustc": rustc_info,
        "entries": len(entries),
        "third_party_packages": sum(1 for p in clean_packages if not p["workspace"]),
        "usage_included": True,
        "acknowledged_reviews": len(ack_records),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
