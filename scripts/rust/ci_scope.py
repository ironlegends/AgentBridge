"""Select economical CI feedback; never infer native release qualification."""
import os
from pathlib import PurePosixPath
import re
import subprocess

LIGHTWEIGHT = frozenset({
    "README.md",
    ".github/workflows/ci.yml",
    "scripts/rust/ci_scope.py",
    "scripts/rust/test_ci_scope.py",
})
SHA = re.compile(r"[0-9a-f]{40}")


def is_lightweight(path):
    parts = path.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        return False
    if path in LIGHTWEIGHT:
        return True
    return (len(parts) > 1 and parts[0] == "docs"
            and PurePosixPath(path).suffix == ".md")


def choose_lane(event, draft, requested, paths):
    if event == "workflow_dispatch":
        if requested not in {"quick", "full"}:
            raise ValueError("Unexpected explicit validation lane")
        return requested
    if event not in {"pull_request", "push"}:
        raise ValueError("Unsupported CI event")
    if event == "pull_request" and draft:
        return "hygiene"
    # Unknown change boundaries never count as documentation-only.
    if paths is not None and all(is_lightweight(path) for path in paths):
        return "hygiene"
    return "quick"


def changed_paths(base, head):
    if (not SHA.fullmatch(base) or not SHA.fullmatch(head)
            or base == "0" * 40 or head == "0" * 40):
        return None
    try:
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        if actual != head:
            return None
        raw = subprocess.check_output(
            ["git", "diff", "--no-renames", "--name-only", "-z", base, head, "--"],
            stderr=subprocess.DEVNULL,
        )
        return [name.decode("utf-8") for name in raw.split(b"\0") if name]
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        return None


def main():
    event = os.environ["CI_EVENT"]
    paths = None
    if event != "workflow_dispatch":
        paths = changed_paths(os.environ.get("CI_BASE_SHA", ""), os.environ.get("CI_HEAD_SHA", ""))
    lane = choose_lane(event, os.environ.get("CI_DRAFT", "").lower() == "true",
                       os.environ.get("CI_REQUESTED_LANE", ""), paths)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write(f"lane={lane}\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
        out.write(f"Validation lane: **{lane}**.\n\n")
        if lane != "full":
            out.write("Economical feedback only; this run is not full native release qualification.\n")
    print(f"Selected CI lane: {lane}")


if __name__ == "__main__":
    main()
