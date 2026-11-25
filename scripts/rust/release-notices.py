#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline Cargo notice packager and JSON index for agent-bridge."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections import deque
from pathlib import Path

NOTICE_PREFIXES = ("LICENSE", "LICENCE", "NOTICE", "COPYING", "UNLICENSE", "COPYRIGHT", "PATENT", "EXCEPTION", "THIRD_PARTY", "THIRD-PARTY")
SKIP_EXTS = {".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".toml", ".json", ".lock", ".py", ".sh", ".ps1"}
MAX_NOTICE_BYTES = 512 * 1024
SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")
# ring's root LICENSE explicitly refers to these vendored once_cell notices.
# Keep this list finite: do not follow arbitrary paths found in license text.
REFERENCED_NOTICES = {
    "ring": (
        "src/polyfill/once_cell/LICENSE-APACHE",
        "src/polyfill/once_cell/LICENSE-MIT",
    ),
}


# These files are checked-in copies of reviewed upstream legal notices, not
# modifications of Cargo's cache. The manifest digest binds exact packages,
# source archives, provenance, license bytes and native SDK identities.
PINNED_NOTICE_ROOT = "licenses/rust-fallbacks"
PINNED_NOTICE_MANIFEST_SHA256 = "48c5cf00252cdf66eb7f58419ac2022809ebb8fd22c3b48ade1ec972d01e9221"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


def pinned_notice_manifest(project: Path) -> dict:
    path = project / PINNED_NOTICE_ROOT / "pins.json"
    data = read_notice(project, path)
    if data is None or hashlib.sha256(data).hexdigest() != PINNED_NOTICE_MANIFEST_SHA256:
        raise ValueError("reviewed notice manifest digest mismatch")
    return json.loads(data)


def locked_registry_package(workspace: Path, pkg: dict) -> dict:
    raw = read_notice(workspace, workspace / "Cargo.lock")
    if raw is None:
        raise ValueError("Cargo lockfile exceeds the metadata budget")
    matches = [p for p in tomllib.loads(raw.decode("utf-8"))["package"]
               if (p.get("name"), p.get("version"), p.get("source")) ==
                  (pkg["name"], pkg["version"], pkg.get("source"))]
    if len(matches) != 1 or pkg.get("source") != CRATES_IO_SOURCE:
        raise ValueError("reviewed notice requires a unique locked crates.io package")
    checksum = matches[0].get("checksum", "")
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("missing locked crate checksum")
    return matches[0]


def checked_cached_blob(root: Path, relative: str, digest: str) -> None:
    source = root / relative
    before = notice_stat(root, source)
    if before.st_size > 64 * 1024 * 1024:
        raise ValueError("reviewed native SDK member exceeds its byte budget")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(source, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError("reviewed native SDK identity changed")
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != digest:
        raise ValueError("reviewed native SDK member digest mismatch")


def copy_reviewed_notices(project: Path, workspace: Path, pkg: dict, crate_dir: Path,
                          base: Path, out_dir: Path, pin: dict) -> list[dict]:
    locked = locked_registry_package(workspace, pkg)
    if (pin["registry"], pin["crate_sha256"], pin["license"]) != (
            pkg["source"], locked["checksum"], pkg.get("license")):
        raise ValueError("reviewed notice package identity changed")
    root = crate_dir.resolve()
    raw = read_notice(root, root / ".cargo_vcs_info.json")
    if raw is None:
        raise ValueError("reviewed crate provenance exceeds budget")
    vcs = json.loads(raw)
    if (vcs["git"]["sha1"], vcs["path_in_vcs"]) != (pin["source_revision"], pin["source_path"]):
        raise ValueError("reviewed notice upstream revision changed")
    for relative, digest in pin["native_files"].items():
        checked_cached_blob(root, relative, digest)
    copied = []
    for filename, digest in sorted(pin["notices"].items()):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", filename) or filename in {".", ".."}:
            raise ValueError("invalid reviewed notice filename")
        relative = f"{PINNED_NOTICE_ROOT}/{pkg['name']}-{pkg['version']}/{filename}"
        data = read_notice(project, project / relative)
        if data is None or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("reviewed upstream notice digest mismatch")
        dest = base / "reviewed-upstream" / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as handle:
            handle.write(data)
        copied.append({"source": relative, "packaged": dest.relative_to(out_dir).as_posix(),
                       "sha256": digest})
    if not copied:
        raise ValueError("empty reviewed notice selection")
    return copied


def copy_mpl_source_location(workspace: Path, pkg: dict, base: Path, out_dir: Path) -> dict:
    locked = locked_registry_package(workspace, pkg)
    name, version = pkg["name"], pkg["version"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("invalid registry package name or version")
    # MPL 2.0 section 3.2: provide recipients with the exact unchanged source.
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    text = (f"{name} {version} is available under MPL-2.0.\n"
            f"Source Code Form: {url}\n"
            f"Cargo.lock SHA-256: {locked['checksum']}\n"
            "License: https://www.mozilla.org/MPL/2.0/\n"
            "These terms continue to apply to the covered source.\n").encode("utf-8")
    dest = base / "SOURCE-AVAILABILITY.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as handle:
        handle.write(text)
    return {"source": "Cargo.lock (MPL source availability)",
            "packaged": dest.relative_to(out_dir).as_posix(), "sha256": hashlib.sha256(text).hexdigest()}


def safe(value: str) -> str:
    return SAFE_RE.sub("_", value.strip()).strip("._") or "item"


def cargo_metadata(manifest: Path, target: str) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--manifest-path", str(manifest), "--filter-platform", target]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        err = res.stderr.strip().splitlines()
        raise RuntimeError(err[-1] if err else f"cargo metadata failed ({res.returncode})")
    return json.loads(res.stdout)


def resolve_closure(meta: dict, root_name: str) -> tuple[dict, dict[str, dict]]:
    pkgs = {p["id"]: p for p in meta["packages"]}
    ws_ids = set(meta.get("workspace_members", []))
    roots = [pkgs[i] for i in ws_ids if i in pkgs and pkgs[i]["name"] == root_name]
    if len(roots) != 1:
        raise ValueError(f"workspace package '{root_name}' not uniquely found")
    root = roots[0]
    nodes = {n["id"]: n for n in (meta.get("resolve") or {}).get("nodes", [])}
    seen = {root["id"]: {"kinds": {"root"}, "features": sorted(nodes.get(root["id"], {}).get("features", []))}}
    queue = deque([root["id"]])
    while queue:
        for dep in nodes.get(queue.popleft(), {}).get("deps", []):
            kinds = {"normal" if dk.get("kind") is None else dk["kind"] for dk in (dep.get("dep_kinds") or [{"kind": None}])} & {"normal", "build"}
            if not kinds:
                continue
            did = dep["pkg"]
            if did not in seen:
                seen[did] = {"kinds": set(kinds), "features": sorted(nodes.get(did, {}).get("features", []))}
                queue.append(did)
            else:
                seen[did]["kinds"].update(kinds)
    return root, seen


def notice_stat(root: Path, source: Path) -> os.stat_result:
    parts = source.relative_to(root).parts
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError(f"invalid notice path: {source}")
    current = root
    for index, part in enumerate(parts):
        current = current / part
        info = current.lstat()
        reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        expected_type = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if reparse or stat.S_ISLNK(info.st_mode) or not expected_type(info.st_mode):
            raise ValueError(f"notice path is linked or has the wrong file type: {current}")
    return info


def read_notice(root: Path, source: Path) -> bytes | None:
    before = notice_stat(root, source)
    if before.st_size > MAX_NOTICE_BYTES:
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(source, flags), "rb") as reader:
        opened = os.fstat(reader.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError(f"notice changed before reading: {source}")
        data = reader.read(MAX_NOTICE_BYTES + 1)
    return data if len(data) <= MAX_NOTICE_BYTES else None


def local_license_path(root: Path, declared: str) -> Path | None:
    candidate = root / declared
    if not candidate.is_relative_to(root) or ".." in candidate.relative_to(root).parts:
        return None
    return candidate


def find_notices(crate_dir: Path, license_file: str | None, package_name: str = "") -> list[Path]:
    root, found = crate_dir.resolve(), {}
    if license_file:
        cand = local_license_path(root, license_file)
        if cand is not None:
            notice_stat(root, cand)
            found[cand.relative_to(root).as_posix()] = cand
    for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if item.is_symlink():
            continue
        if item.is_file() and item.suffix.lower() not in SKIP_EXTS and item.name.upper().startswith(NOTICE_PREFIXES):
            found[item.relative_to(root).as_posix()] = item
        elif item.is_dir() and item.name.lower() in {"licenses", "licence", "notices", "legal"}:
            for sub in sorted(item.iterdir(), key=lambda p: p.name.lower()):
                if sub.is_file() and not sub.is_symlink() and sub.suffix.lower() not in SKIP_EXTS:
                    found[sub.relative_to(root).as_posix()] = sub
    for relative in REFERENCED_NOTICES.get(package_name, ()):
        candidate = root / relative
        notice_stat(root, candidate)
        found[relative] = candidate
    return [found[k] for k in sorted(found)]


def detect_sqlite(pkg: dict, crate_dir: Path, features: list[str]) -> dict | None:
    links = pkg.get("links")
    amalg = crate_dir.is_dir() and any((crate_dir / p).is_file() for p in ("sqlite3/sqlite3.c", "sqlite3/sqlite3.h", "sqlcipher/sqlite3.c", "sqlite3.c", "sqlite3.h"))
    if links != "sqlite3" and "sqlite" not in pkg["name"].lower() and not amalg:
        return None
    return {"package": f"{pkg['name']}@{pkg['version']}", "links": links, "bundled_hint": amalg or any("bundled" in f or "sqlcipher" in f for f in features), "sqlcipher_hint": any("sqlcipher" in f for f in features), "features": features}


def attribution_context(meta: dict, project_root: str | None, target: str) -> tuple[Path, set[str]]:
    workspace = Path(meta["workspace_root"]).resolve()
    members = set(meta.get("workspace_members", []))
    if project_root is None:
        return workspace, members
    project = Path(project_root).absolute()
    info = project.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("project attribution root must be a plain directory")
    project = project.resolve()
    if not workspace.is_relative_to(project):
        raise ValueError("selected workspace is outside the attribution project")
    notice_stat(project, project / "Cargo.toml")
    enclosing = cargo_metadata(project / "Cargo.toml", target)
    if Path(enclosing["workspace_root"]).resolve() != project:
        raise ValueError("attribution project differs from the Cargo workspace")
    packages = {p["id"]: p for p in enclosing["packages"]}
    for ident in enclosing.get("workspace_members", []):
        package = packages.get(ident)
        if package is None or package.get("source") is not None:
            raise ValueError("project member has an external package source")
        manifest = Path(package["manifest_path"]).absolute()
        if not manifest.is_relative_to(project):
            raise ValueError("project member resides outside the attribution project")
        notice_stat(project, manifest)
        members.add(ident)
    return project, members


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Offline Rust notice packager.")
    ap.add_argument("--manifest-path", default="Cargo.toml")
    ap.add_argument("--package", default="agent-bridge")
    ap.add_argument("--project-root", help="Enclosing Cargo workspace supplying first-party attribution for the separate Tauri workspace.")
    ap.add_argument("--target", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()
    if out_dir.exists():
        raise FileExistsError(f"output directory already exists: {out_dir}")
    meta = cargo_metadata(Path(args.manifest_path).resolve(), args.target)
    attribution_root, ws_ids = attribution_context(meta, args.project_root, args.target)
    pkgs = {p["id"]: p for p in meta["packages"]}
    root, closure = resolve_closure(meta, args.package)
    out_dir.mkdir(parents=True, exist_ok=False)
    notices_dir = out_dir / "notices"
    notices_dir.mkdir()

    for name in ("LICENSE", "NOTICE"):
        data = read_notice(attribution_root, attribution_root / name)
        if data is None:
            raise ValueError("project attribution exceeds the notice budget")
        (notices_dir / name).write_bytes(data)
    packages_out, sqlite_hits, to_verify = [], [], []
    workspace = Path(meta["workspace_root"]).resolve()
    # Optional only for historical/test repositories that predate these pins;
    # without them missing crate notices remain blocking.
    pins_path = attribution_root / PINNED_NOTICE_ROOT / "pins.json"
    pins = pinned_notice_manifest(attribution_root) if pins_path.exists() else {}
    for pid in sorted(closure, key=lambda i: (pkgs[i]["name"], pkgs[i]["version"], i)):
        pkg, info = pkgs[pid], closure[pid]
        is_ws, label, crate_dir, copied = pid in ws_ids, f"{pkg['name']}@{pkg['version']}", Path(pkg["manifest_path"]).parent, []
        if not crate_dir.is_dir():
            to_verify.append({"package": label, "code": "missing_cached_source"})
        else:
            base = notices_dir / f"{safe(pkg['name'])}-{safe(pkg['version'])}"
            if base.exists():
                base = notices_dir / f"{base.name}-{hashlib.sha256(pid.encode()).hexdigest()[:8]}"
            for src in find_notices(crate_dir, pkg.get("license_file"), pkg["name"]):
                rel = src.relative_to(crate_dir.resolve()).as_posix()
                data = read_notice(crate_dir.resolve(), src)
                if data is None:
                    to_verify.append({"package": label, "code": "oversized_notice_skipped", "path": rel})
                    continue
                dst = base.joinpath(*(safe(p) for p in Path(rel).parts))
                dst.parent.mkdir(parents=True, exist_ok=True)
                with dst.open("xb") as wf:
                    wf.write(data)
                copied.append({"source": rel, "packaged": dst.relative_to(out_dir).as_posix(), "sha256": hashlib.sha256(data).hexdigest()})
            if label in pins:
                copied.extend(copy_reviewed_notices(attribution_root, workspace, pkg, crate_dir, base, out_dir, pins[label]))
                if pins[label]["native_files"]:
                    to_verify.append({"package": label, "code": "native_links_check",
                                      "links": "WebView2LoaderStatic / WebView2Loader.dll",
                                      "provenance": "reviewed-upstream/PROVENANCE.json"})
            if not is_ws and pkg.get("license") == "MPL-2.0":
                # A source link alone is not a substitute for a license notice.
                if copied:
                    copied.append(copy_mpl_source_location(workspace, pkg, base, out_dir))

        lic, lic_file = pkg.get("license"), pkg.get("license_file")
        if lic_file:
            candidate = local_license_path(crate_dir.resolve(), lic_file)
            lic_file = candidate.relative_to(crate_dir.resolve()).as_posix() if candidate is not None else "<external>"

        if not lic and not lic_file:
            to_verify.append({"package": label, "code": "missing_license_metadata"})
        if lic_file:
            to_verify.append({"package": label, "code": "custom_license_file", "file": lic_file})
        if lic and " WITH " in lic:
            to_verify.append({"package": label, "code": "license_exception_present", "license": lic})
        if not is_ws and not copied:
            to_verify.append({"package": label, "code": "no_notice_file_found", "license": lic})
        if not is_ws and not str(pkg.get("source") or "").startswith("registry+"):
            to_verify.append({"package": label, "code": "non_registry_source"})

        sq = detect_sqlite(pkg, crate_dir, info["features"])
        if sq:
            sqlite_hits.append(sq)
            to_verify.append({"package": label, "code": "sqlite_native_check", "bundled_hint": sq["bundled_hint"]})
        elif pkg.get("links"):
            to_verify.append({"package": label, "code": "native_links_check", "links": pkg["links"]})

        packages_out.append({"name": pkg["name"], "version": pkg["version"], "workspace": is_ws, "dep_kinds": sorted(info["kinds"]), "features": info["features"], "license": lic, "license_file": lic_file, "links": pkg.get("links"), "notices": copied})

    index = {"package": root["name"], "version": root["version"], "target": args.target, "packages": packages_out, "sqlite": sqlite_hits, "to_verify": to_verify}
    with (out_dir / "index.json").open("x", encoding="utf-8") as fh:
        fh.write(json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    for item in to_verify:
        print(json.dumps(item, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(json.dumps({"code": "fatal_error", "detail": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
