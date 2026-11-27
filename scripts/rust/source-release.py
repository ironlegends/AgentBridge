#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a deterministic CLI and Tauri source ZIP from the exact Git index."""

from __future__ import annotations

import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path

ZIP_DATE = (2026, 1, 1, 0, 0, 0)
RESERVED_WIN = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
MIGRATIONS = {
    "contracts/sqlite/001_initial.sql", "contracts/sqlite/002_execution.sql",
    "contracts/sqlite/003_collaboration.sql", "contracts/sqlite/004_scheduler.sql",
    "contracts/sqlite/005_legacy_import.sql", "contracts/sqlite/006_legacy_events.sql",
    "contracts/sqlite/007_legacy_mission_owners.sql",
}
DESKTOP_BUILD_INPUTS = {
    "app/src-tauri/Cargo.toml", "app/src-tauri/Cargo.lock", "app/src-tauri/build.rs",
    "app/src-tauri/tauri.conf.json", "app/src-tauri/capabilities/default.json",
    "app/src-tauri/src/lib.rs", "app/src-tauri/src/main.rs",
    "app/src-tauri/icons/32x32.png", "app/src-tauri/icons/128x128.png",
    "app/src-tauri/icons/128x128@2x.png", "app/src-tauri/icons/icon.png",
    "app/src-tauri/icons/icon.ico", "app/ui/index.html", "app/ui/app.js", "app/ui/styles.css",
}
DESKTOP_EXCLUDED_DIRS = {"target", "vendor", "node_modules", "__pycache__", "cache", "caches"}
DESKTOP_PRIVATE_FILES = {
    "operator-connection.json", "panel-settings.json", "oauth.json", "oauth-workstation.json",
    "enrollment.json", "enrollment-workstation.json", "workstation-scope.json",
    "secrets.json", "tokens.json", "credentials.json", "unified-v1.json",
}
UNIFIED_BUILD_INPUTS = {
    "contracts/browser-tools-v1.json", "contracts/windows-tools-v1.json",
    *(f"workers/browser-playwright/{name}" for name in (
        ".gitattributes", "worker.mjs", "protocol.mjs", "validation.mjs", "session.mjs", "driver.mjs",
        "capture-credits.mjs", "package.json", "package-lock.json", "README.md", "NOTICE",
        "notices/DeskMCP-LICENSE")),
    *(f"native/agent-bridge-native/{name}" for name in (
        "AgentBridge.Native.csproj", "app.manifest", "Program.cs", "NativeApi.cs", "Hud.cs",
        "THIRD-PARTY-NOTICES.md", "notices/DESKMCP-APACHE-2.0.txt",
        "notices/WINAPP-THIRD-PARTY-NOTICES.txt", "notices/WINAPP-DEPENDENCIES.json")),
    "scripts/rust/package-browser-worker.py", "scripts/rust/test_package_browser_worker.py",
    "scripts/rust/package-native-tools.py",
    "scripts/rust/package-desktop.py", "scripts/rust/release_components.py",
    "scripts/rust/test_package_desktop.py", "scripts/rust/test_release_components.py",
    "scripts/rust/test_desktop_notices.py",
    "scripts/rust/repository_hygiene.py", "scripts/rust/test_repository_hygiene.py",
    "scripts/rust/legacy-reference-allowlist.json",
    "native/winapp-patches/0001-passive-screenshot.patch", "scripts/rust/build-winapp-passive.py",
    "native/winapp-patches/tests/PassiveCaptureContract.cs",
    "native/winapp-patches/0002-background-post-message.patch",
    "native/winapp-patches/tests/BackgroundMessageContract.cs",
}
REVIEWED_RELEASE_INPUTS = {
    ".gitattributes",
    "licenses/rust-fallbacks/alloc-stdlib-0.3.0/LICENSE",
    "licenses/rust-fallbacks/alloc-stdlib-0.3.0/PROVENANCE.json",
    "licenses/rust-fallbacks/pins.json",
    "licenses/rust-fallbacks/selectors-0.38.0/LICENSE-MPL-2.0",
    "licenses/rust-fallbacks/selectors-0.38.0/PROVENANCE.json",
    "licenses/rust-fallbacks/tauri-plugin-2.7.4/LICENSE-APACHE-2.0",
    "licenses/rust-fallbacks/tauri-plugin-2.7.4/LICENSE-MIT",
    "licenses/rust-fallbacks/tauri-plugin-2.7.4/PROVENANCE.json",
    "licenses/rust-fallbacks/webview2-com-0.39.1/LICENSE",
    "licenses/rust-fallbacks/webview2-com-0.39.1/PROVENANCE.json",
    "licenses/rust-fallbacks/webview2-com-macros-0.8.1/LICENSE",
    "licenses/rust-fallbacks/webview2-com-macros-0.8.1/PROVENANCE.json",
    "licenses/rust-fallbacks/webview2-com-sys-0.39.1/LICENSE",
    "licenses/rust-fallbacks/webview2-com-sys-0.39.1/PROVENANCE.json",
    "licenses/rust-fallbacks/webview2-com-sys-0.39.1/WEBVIEW2-SDK-LICENSE.txt",
    "licenses/rust-fallbacks/webview2-com-sys-0.39.1/WEBVIEW2-SDK-NOTICE.txt",
    "native/agent-bridge-native/.gitattributes",
    "native/agent-bridge-native/notices/WINAPP-BUILD-PROVENANCE.json",
    "native/agent-bridge-native/tests/fixture/NativeFixture.csproj",
    "native/winapp-patches/.gitattributes",
    "native/winapp-patches/0003-background-uia-autofocus.patch",
    "native/winapp-patches/0004-exact-passive-window.patch",
    "native/winapp-patches/build-package-pins.json",
    "native/winapp-patches/tests/BackgroundUiaContract.cs",
    "native/winapp-patches/tests/ExactPassiveContract.cs",
    "scripts/rust/ci_scope.py",
    "scripts/rust/qualification_inventory.py",
    "scripts/rust/test_build_winapp_passive.py",
    "scripts/rust/test_ci_scope.py",
    "scripts/rust/test_qualification_inventory.py",
}
EXACT = {*REVIEWED_RELEASE_INPUTS, "Cargo.toml", "Cargo.lock", "LICENSE", "NOTICE", "README.md", "CONTRIBUTING.md", "SECURITY.md", "contracts/mission-tools-v1.json",
         "contracts/stdio-workspace-tool-docs.json", "contracts/workstation-tool-docs.json",
         "contracts/task-room-v1.json",
         "docs/images/desktop-guide.png", "docs/images/desktop-views.png",
         "rust/cli/windows/agent-bridge.manifest",
         "rust/cli/src/browser_docs/interaction_fixture.html",
         "rust/cli/src/browser_docs/transfer_witness.txt", "rust/cli/src/ui_assets.html",
         "scripts/rust/comment_ratchet.py", "scripts/rust/test_comment_ratchet.py",
         "scripts/rust/test_release_notices.py", "scripts/rust/test_source_release.py",
         "scripts/rust/prepare-native-chrome-fixture.py",
         "scripts/rust/test_prepare_native_chrome_fixture.py",
         "scripts/rust/prepare-linux-chrome-fixture.py",
         "scripts/rust/test_prepare_linux_chrome_fixture.py",
         "scripts/rust/comment-baseline.json",
         "licenses/agent-bridge-release-public.pem", "scripts/windows/sign-release.ps1", *MIGRATIONS, *DESKTOP_BUILD_INPUTS, *UNIFIED_BUILD_INPUTS}
REQUIRED = {*EXACT, "rust/cli/Cargo.toml", "scripts/rust/release-notices.py", "scripts/rust/package-rust.py"}
VERSION_RE = re.compile(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)"\s*$')


def is_allowed(path: str) -> bool:
    if path.startswith(("workers/browser-playwright/", "native/agent-bridge-native/")):
        parts = path.lower().split("/")
        excluded = DESKTOP_EXCLUDED_DIRS | {"bin", "obj", "state", "profiles", "downloads"}
        if any(part.startswith(".") or part in excluded for part in parts[:-1]):
            return False
        if parts[-1] in DESKTOP_PRIVATE_FILES:
            return False
    if path.startswith("app/"):
        parts = path.lower().split("/")
        if any(part.startswith(".") or part in DESKTOP_EXCLUDED_DIRS for part in parts[:-1]):
            return False
        if parts[-1] in DESKTOP_PRIVATE_FILES:
            return False
    if path in EXACT:
        return True
    if path.startswith("workers/browser-playwright/tests/") and path.endswith((".mjs", ".py")):
        return True
    if path.startswith("native/agent-bridge-native/") and path.endswith(".cs"):
        return True
    if path.startswith("native/agent-bridge-native/tests/") and path.endswith(".py"):
        return True
    if path.startswith("app/src-tauri/src/") and path.endswith(".rs"):
        return True
    if path.startswith("app/src-tauri/capabilities/") and path.endswith(".json"):
        return True
    if path.startswith("app/src-tauri/icons/") and path.endswith((".png", ".ico", ".icns")):
        return True
    if path.startswith("app/ui/") and path.endswith((".html", ".js", ".css", ".svg", ".png", ".ico", ".woff", ".woff2")):
        return True
    if path.startswith("app/tests/") and path.endswith(".cjs"):
        return True
    if path.startswith("docs/") and path.endswith(".md"):
        return True
    if path.startswith("rust/") and path.endswith((".rs", ".toml")):
        return "target" not in path.split("/")[:-1]
    return path in {"scripts/rust/release-notices.py", "scripts/rust/package-rust.py", "scripts/rust/source-release.py"}


def validate_relpath(path: str) -> None:
    if not path or path.startswith("/") or path.endswith("/") or "\\" in path or ":" in path:
        raise ValueError(f"unsafe path: {path!r}")
    for seg in path.split("/"):
        worker_attributes = (path == "workers/browser-playwright/.gitattributes" or path in REVIEWED_RELEASE_INPUTS) and seg == ".gitattributes"
        if not seg or seg in {".", ".."} or (seg.startswith(".") and not worker_attributes) or seg.endswith((" ", ".")):
            raise ValueError(f"unsafe path segment: {path!r}")
        if any(ord(c) < 32 or ord(c) == 127 for c in seg) or seg.split(".", 1)[0].upper() in RESERVED_WIN:
            raise ValueError(f"forbidden path component: {path!r}")


def read_index(repo: Path) -> list[tuple[str, str, str]]:
    res = subprocess.run(["git", "-C", str(repo), "ls-files", "--stage", "-z"], capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.decode("utf-8", "replace").strip() or "git ls-files failed")
    selected: list[tuple[str, str, str]] = []
    for raw in res.stdout.split(b"\x00"):
        if not raw:
            continue
        meta_b, sep, path_b = raw.partition(b"\t")
        if not sep:
            raise RuntimeError("malformed git ls-files output")
        mode, sha, stage = meta_b.decode("ascii").split(" ")
        path = path_b.decode("utf-8", "strict")
        if stage != "0":
            raise ValueError(f"unmerged index entry: {path} (stage {stage})")
        if mode not in ("100644", "100755"):
            raise ValueError(f"symlink, gitlink, or unsupported mode {mode}: {path}")
        if is_allowed(path):
            validate_relpath(path)
            selected.append((path, mode, sha))
    return selected


def cat_blobs(repo: Path, items: list[tuple[str, str, str]]) -> dict[str, bytes]:
    shas = sorted({sha for _, _, sha in items})
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=("\n".join(shas) + "\n").encode("ascii"),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip() or "git cat-file failed")
    buf, pos, blobs = proc.stdout, 0, {}
    for expected in shas:
        nl = buf.find(b"\n", pos)
        if nl < 0:
            raise RuntimeError("truncated git cat-file header")
        parts = buf[pos:nl].decode("ascii").split(" ")
        if len(parts) != 3 or parts[0] != expected or parts[1] != "blob":
            raise RuntimeError(f"missing or non-blob Git object: {expected}")
        end = nl + 1 + int(parts[2])
        if end >= len(buf) or buf[end:end + 1] != b"\n":
            raise RuntimeError(f"corrupt git cat-file payload: {expected}")
        blobs[expected] = buf[nl + 1:end]
        pos = end + 1
    if pos != len(buf):
        raise RuntimeError("unexpected trailing data from git cat-file")
    return blobs


def package_version(toml_bytes: bytes) -> str:
    in_pkg = False
    for line in toml_bytes.decode("utf-8", "strict").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_pkg = s == "[package]"
        elif in_pkg and (m := VERSION_RE.match(s)):
            return m.group(1)
    raise ValueError("missing [package].version in rust/cli/Cargo.toml")


def check_conflicts(paths: list[str]) -> None:
    files_ci, dirs_ci = set(), set()
    for path in paths:
        low = path.lower()
        if low in files_ci or low in dirs_ci:
            raise ValueError(f"conflicting archive path: {path}")
        parts = low.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            if parent in files_ci:
                raise ValueError(f"file/directory conflict: {path}")
            dirs_ci.add(parent)
        files_ci.add(low)


def write_zip(dest: Path, prefix: str, entries: list[tuple[str, str, bytes]]) -> str:
    if dest.is_symlink() or dest.exists():
        raise FileExistsError(f"output already exists: {dest}")
    if dest.parent.is_symlink() or not dest.parent.is_dir():
        raise ValueError(f"output parent directory missing: {dest.parent}")
    with tempfile.TemporaryDirectory(prefix="ab-rust-src-", dir=dest.parent) as tmp:
        staged = Path(tmp) / dest.name
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for rel, mode, data in sorted(entries, key=lambda e: e[0]):
                zi = zipfile.ZipInfo(f"{prefix}/{rel}", date_time=ZIP_DATE)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (0o100755 if mode == "100755" else 0o100644) << 16
                zf.writestr(zi, data)
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        os.link(staged, dest)
    return digest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Create a standalone CLI and Tauri source ZIP from the exact Git index.")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]), help="Git checkout path.")
    out = ap.add_mutually_exclusive_group(required=True)
    out.add_argument("--output", help="New destination .zip file path.")
    out.add_argument("--out-dir", help="Existing directory for agent-bridge-<version>-rust-src.zip.")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    items = read_index(repo)
    missing = sorted(REQUIRED - {p for p, _, _ in items})
    if missing:
        raise ValueError(f"missing required index files: {', '.join(missing)}")

    blobs = cat_blobs(repo, items)
    entries = [(p, m, blobs[s]) for p, m, s in items]
    by_path = {p: d for p, _, d in entries}

    lic = by_path["LICENSE"].decode("utf-8", "strict")
    if "Apache License" not in lic or "Version 2.0" not in lic:
        raise ValueError("root LICENSE must be Apache License 2.0")
    if not by_path["NOTICE"].decode("utf-8", "strict").strip():
        raise ValueError("NOTICE must not be empty")
    check_conflicts([p for p, _, _ in entries])

    prefix = f"agent-bridge-{package_version(by_path['rust/cli/Cargo.toml'])}-rust-src"
    dest = Path(args.output) if args.output else (Path(args.out_dir) / f"{prefix}.zip")
    if dest.suffix.lower() != ".zip":
        raise ValueError(f"output must end with .zip: {dest}")

    sha256 = write_zip(dest, prefix, entries)
    print(json.dumps({"status": "ok", "archive": str(dest.resolve()), "sha256": sha256, "files": len(entries)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
