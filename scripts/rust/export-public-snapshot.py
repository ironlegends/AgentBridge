#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plan and export a reviewed, history-free patch from two immutable Git trees."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def git(repo, *args, data=None, env=None):
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, env=env
    ).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree(repo, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Use a full, lowercase SHA-1 commit ID.")
    if git(repo, "rev-parse", commit + "^{commit}").decode().strip() != commit:
        raise ValueError("Revision is not an exact commit.")
    if git(repo, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("Only SHA-1 repositories are supported.")
    result = {}
    for item in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if item:
            meta, raw = item.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split()
            result[raw.decode("utf-8", "strict")] = (mode, kind, oid)
    return result


def validate_path(path):
    parts = path.split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if (not path or any(not p or p in (".", "..") or p.casefold() == ".git"
                       or p.split(".", 1)[0].casefold() in reserved
                       or p.endswith((".", " ")) for p in parts)
            or "\\" in path or ":" in path or any(ord(c) < 32 or ord(c) == 127 for c in path)):
        raise ValueError("Unsafe path: " + path)


def validate_paths(paths):
    seen = set()
    dirs = {}
    for path in sorted(paths):
        validate_path(path)
        lower = path.casefold()
        parents = ["/".join(path.split("/")[:i]) for i in range(1, len(path.split("/")))]
        if lower in seen or lower in dirs or any(p.casefold() in seen for p in parents):
            raise ValueError("Case or file/directory collision: " + path)
        for parent in parents:
            if dirs.setdefault(parent.casefold(), parent) != parent:
                raise ValueError("Case alias in directory: " + path)
        seen.add(lower)


def entry(repo, item):
    if item is None:
        return None
    mode, kind, oid = item
    if kind != "blob" or mode not in ("100644", "100755"):
        raise ValueError("Selected entries must be regular Git blobs.")
    return {"mode": mode, "oid": oid, "sha256": digest(git(repo, "cat-file", "blob", oid))}


def plan(private_repo, public_repo, source, base, additions):
    private, public = tree(private_repo, source), tree(public_repo, base)
    additions = sorted(set(additions))
    for path in additions:
        validate_path(path)
        if path in public or path not in private:
            raise ValueError("Explicit additions must be new paths in the source: " + path)
    selected = set(public) | set(additions)
    validate_paths(set(private) & selected)
    changes = []
    for path in sorted(selected):
        validate_path(path)
        old, new = public.get(path), private.get(path)
        for item in (old, new):
            if item and (item[0] not in ("100644", "100755") or item[1] != "blob"):
                raise ValueError("Non-regular selected path: " + path)
        if old != new:
            changes.append({"path": path, "before": entry(public_repo, old),
                            "after": entry(private_repo, new)})
    return {"schema": 1, "source": source, "base": base, "additions": additions,
            "excluded_new_path_count": len(set(private) - selected), "changes": changes}


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_new(path, data):
    with Path(path).open("xb") as output:
        output.write(data)


def make_tree(bare, index, rows, side, repo):
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(index)
    git(bare, "read-tree", "--empty", env=env)
    records = []
    for row in rows:
        item = row[side]
        if item is None:
            continue
        content = git(repo, "cat-file", "blob", item["oid"])
        if digest(content) != item["sha256"]:
            raise ValueError("Blob verification failed.")
        oid = git(bare, "hash-object", "-w", "--stdin", data=content).decode().strip()
        if oid != item["oid"]:
            raise ValueError("Blob identity changed.")
        records.append((item["mode"] + " " + oid + "\t" + row["path"]).encode("utf-8") + b"\0")
    if records:
        git(bare, "update-index", "-z", "--index-info", data=b"".join(records), env=env)
    return git(bare, "write-tree", env=env).decode().strip()


def export(private_repo, public_repo, reviewed, approved_hash):
    if digest(reviewed) != approved_hash:
        raise ValueError("The approved plan SHA-256 does not match.")
    data = json.loads(reviewed)
    actual = plan(private_repo, public_repo, data["source"], data["base"], data["additions"])
    if encode(actual) != reviewed:
        raise ValueError("The plan is not canonical or differs from immutable Git trees.")
    with tempfile.TemporaryDirectory(prefix="ab-public-patch-") as tmp:
        bare = Path(tmp) / "objects.git"
        subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
        before = make_tree(bare, Path(tmp) / "old.index", data["changes"], "before", public_repo)
        after = make_tree(bare, Path(tmp) / "new.index", data["changes"], "after", private_repo)
        return git(bare, "-c", "core.quotePath=true", "diff", "--binary", "--full-index",
                   "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color",
                   "--src-prefix=a/", "--dst-prefix=b/", before, after, "--")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-repo", required=True, type=Path)
    parser.add_argument("--public-repo", required=True, type=Path)
    actions = parser.add_subparsers(dest="action", required=True)
    p = actions.add_parser("plan")
    p.add_argument("--source", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--include", action="append", default=[])
    p.add_argument("--output", required=True, type=Path)
    e = actions.add_parser("export")
    e.add_argument("--plan", required=True, type=Path)
    e.add_argument("--approved-plan-sha256", required=True)
    e.add_argument("--output", required=True, type=Path)
    a = parser.parse_args()
    if a.action == "plan":
        result = plan(a.private_repo, a.public_repo, a.source, a.base, a.include)
        payload = encode(result)
    else:
        payload = export(a.private_repo, a.public_repo, a.plan.read_bytes(), a.approved_plan_sha256)
    write_new(a.output, payload)
    print(json.dumps({"action": a.action, "sha256": digest(payload), "bytes": len(payload)}))


if __name__ == "__main__":
    main()
