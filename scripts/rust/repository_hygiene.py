#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check committed binaries, secrets, and explicitly reviewed provenance lines."""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ALLOWANCES = "scripts/rust/legacy-reference-allowlist.json"
LEGACY = re.compile("desk" + ".?" + "mcp", re.I)
SECRET = re.compile("gh" + "p_|gh" + "o_|github" + "_pat_|sk-[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,}|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY")
FORBIDDEN = {".pdb", ".exe", ".dll", ".lib", ".obj", ".sqlite"}


def scan_files(root: Path, paths: list[str], allowances: dict) -> list[str]:
    errors, seen, tracked = [], {}, set(paths)
    if not isinstance(allowances, dict):
        raise ValueError("provenance allowances must be an object")
    for path, lines in allowances.items():
        if (not isinstance(path, str) or path not in tracked or path == ALLOWANCES
                or not isinstance(lines, list) or not lines
                or any(not isinstance(line, str) or not LEGACY.search(line) or line != line.strip() for line in lines)
                or len(set(lines)) != len(lines)):
            raise ValueError("invalid or untracked provenance allowance")
        seen[path] = set()
    for relative in paths:
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid tracked path")
        source = root / relative
        if source.suffix.lower() in FORBIDDEN:
            errors.append(f"Forbidden tracked binary/artifact: {relative}")
            continue
        if not source.is_file():
            continue
        for number, line in enumerate(source.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if relative != ALLOWANCES and LEGACY.search(line):
                if line.strip() in allowances.get(relative, []):
                    seen[relative].add(line.strip())
                else:
                    errors.append(f"Unreviewed provenance reference in {relative}:{number}")
            # Legal attribution is never an exemption from secret scanning.
            if SECRET.search(line):
                errors.append(f"Potential secret pattern in {relative}:{number}")
    for path, lines in allowances.items():
        if set(lines) != seen[path]:
            errors.append(f"Stale provenance allowance in {path}")
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    paths = subprocess.check_output(["git", "-C", str(args.repo), "ls-files", "-z"]).decode("utf-8").split("\0")
    paths = [path for path in paths if path]
    allowances = json.loads((args.repo / ALLOWANCES).read_text(encoding="utf-8"))
    errors = scan_files(args.repo, paths, allowances)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Hygiene OK across {len(paths)} tracked files; {sum(map(len, allowances.values()))} exact provenance lines reviewed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
