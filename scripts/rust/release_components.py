#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verified native resources shared by portable and Tauri release packages."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import tempfile
from pathlib import Path

MAX_FILES = 20_000
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_FILE_BYTES = 768 * 1024**2
HASH = re.compile(r"[0-9a-f]{64}\Z")
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("unsafe resource path")
    for part in value.split("/"):
        if (not part or part in {".", ".."} or part.endswith((".", " "))
                or part.split(".")[0].upper() in RESERVED
                or any(ord(char) < 32 or char in '<>"|?*' for char in part)):
            raise ValueError("unsafe resource path")
    return value


def plain(path: Path, directory: bool) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("resource link or reparse point is not admitted")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("resource has an invalid file type")
    return info


def plain_root(root: Path) -> None:
    for parent in reversed((root, *root.parents)):
        plain(parent, True)


def inventory(root: Path) -> set[str]:
    plain_root(root)
    files = set()
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            plain(Path(parent) / name, True)
        for name in names:
            path = Path(parent) / name
            plain(path, False)
            files.add(path.relative_to(root).as_posix())
            if len(files) > MAX_FILES:
                raise ValueError("resource file count exceeds the package budget")
    return files


def component_files(root: Path, expected: str, kind: str) -> tuple[dict, list[dict]]:
    root = root.absolute()
    plain_root(root)
    if not isinstance(expected, str) or not HASH.fullmatch(expected):
        raise ValueError("invalid manifest digest")
    manifest_path = root / "manifest.json"
    if not 0 < plain(manifest_path, False).st_size <= 4 * 1024**2:
        raise ValueError("resource manifest size exceeds the budget")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != expected:
        raise ValueError("manifest digest mismatch")
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise ValueError("unsupported resource manifest schema")
    if kind == "browser":
        if ("schema" in manifest or type(manifest.get("schema_version")) is not int
                or manifest["schema_version"] != 1):
            raise ValueError("unsupported Browser resource manifest schema")
        if ("protocol" in manifest or type(manifest.get("protocol_version")) is not int
                or manifest["protocol_version"] != 2 or not isinstance(manifest.get("files"), list)):
            raise ValueError("unsupported Browser resource protocol")
        records = manifest["files"]
        size_key = "bytes"
    elif kind == "native":
        if (type(manifest.get("schema")) is not int or manifest["schema"] != 1
                or "schema_version" in manifest or "protocol_version" in manifest):
            raise ValueError("unsupported native resource manifest schema")
        if (type(manifest.get("protocol")) is not int or manifest["protocol"] != 1
                or manifest.get("platform") != "windows-x64"
                or not isinstance(manifest.get("files"), dict)
                or set(manifest["files"]) != {"native", "winapp", "skia", "vda"}
                or not isinstance(manifest.get("notices"), dict) or not manifest["notices"]):
            raise ValueError("unsupported native resource manifest")
        records = [*manifest["files"].values(), *manifest["notices"].values()]
        size_key = "size"
    else:
        raise ValueError("unknown resource component")
    if not 1 <= len(records) < MAX_FILES:
        raise ValueError("invalid resource record count")
    qualified, names, parents, total = [], set(), set(), 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("invalid resource record")
        path = relative_path(record.get("path"))
        low = path.lower()
        ancestors = {"/".join(low.split("/")[:i]) for i in range(1, len(low.split("/")))}
        if low == "manifest.json" or low in names or low in parents or ancestors & names:
            raise ValueError("duplicate resource path or file/directory collision")
        names.add(low)
        parents.update(ancestors)
        size, pinned = record.get(size_key), record.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES or not isinstance(pinned, str) or not HASH.fullmatch(pinned):
            raise ValueError("invalid resource size or digest")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("resource bytes exceed the package budget")
        qualified.append({"path": path, "bytes": size, "sha256": pinned})
    found = inventory(root)
    if found != {r["path"] for r in qualified} | {"manifest.json"}:
        raise ValueError("missing or unlisted resource files; private state cannot be packaged")
    for record in qualified:
        path = root / record["path"]
        if plain(path, False).st_size != record["bytes"]:
            raise ValueError("resource size mismatch")
        if digest(path) != record["sha256"]:
            raise ValueError("resource digest mismatch")
    qualified.append({"path": "manifest.json", "bytes": len(manifest_bytes), "sha256": expected})
    return manifest, qualified


def copy_verified(source: Path, target: Path, record: dict) -> None:
    plain_root(source.parent)
    before = plain(source, False)
    target.parent.mkdir(parents=True, exist_ok=True)
    actual, count = hashlib.sha256(), 0
    with source.open("rb") as reader, target.open("xb") as writer:
        if not os.path.samestat(before, os.fstat(reader.fileno())):
            raise ValueError("resource changed before copy")
        while chunk := reader.read(64 * 1024):
            count += len(chunk)
            if count > record["bytes"]:
                raise ValueError("resource size changed during copy")
            actual.update(chunk)
            writer.write(chunk)
    if count != record["bytes"] or actual.hexdigest() != record["sha256"]:
        raise ValueError("resource digest changed during copy")


def stage_resources(browser: Path, browser_sha: str, native: Path, native_sha: str, target: Path) -> dict:
    inputs = [("browser", browser.absolute(), browser_sha), ("native", native.absolute(), native_sha)]
    validated = [(kind, root, expected, *component_files(root, expected, kind)) for kind, root, expected in inputs]
    target = target.absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError("application stage already exists")
    plain_root(target.parent)
    with tempfile.TemporaryDirectory(prefix=".ab-resources-", dir=target.parent) as temporary:
        stage = Path(temporary)
        result = {}
        for kind, root, expected, manifest, records in validated:
            for record in records:
                copy_verified(root / record["path"], stage / "resources/automation" / kind / record["path"], record)
            result[kind] = {"path": f"resources/automation/{kind}", "manifest_sha256": expected,
                            "protocol": manifest["protocol_version" if kind == "browser" else "protocol"], "files": len(records), "bytes": sum(r["bytes"] for r in records)}
        # Exclusive directory creation protects another assembler's destination.
        target.mkdir()
        try:
            (stage / "resources").rename(target / "resources")
        except BaseException:
            target.rmdir()
            raise
    return result


def tauri_resources(target: Path) -> dict:
    plain_root(target / "resources")
    return {"bundle": {"resources": {(target / "resources").absolute().as_posix() + "/": "resources/"}}}


def verify_gui_image(data: bytes) -> None:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("application is not a Windows GUI executable")
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset < 64 or offset + 24 + 70 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("invalid application PE header")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    optional_size, flags, magic = struct.unpack_from("<HHH", data, offset + 20)
    if (machine != 0x8664 or magic != 0x20b or optional_size < 70
            or offset + 24 + optional_size > len(data) or not flags & 2 or flags & 0x2000):
        raise ValueError("application is not a Windows x64 executable")
    if struct.unpack_from("<H", data, offset + 24 + 68)[0] != 2:
        raise ValueError("application must use the Windows GUI subsystem to avoid a startup console")
