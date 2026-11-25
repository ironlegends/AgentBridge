#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy a CI browser into a private test installation; never repair the source."""
import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time

MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_ENTRIES = 30000
MAX_DEPTH = 32
MAX_SECONDS = 300


class FixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Fixture:
    root: Path
    executable: Path
    files: int
    bytes: int
    symlinks: int


@dataclass
class Budget:
    started: float
    entries: int = 0
    files: int = 0
    bytes: int = 0
    symlinks: int = 0

    def check(self):
        if self.entries > MAX_ENTRIES or self.bytes > MAX_TOTAL_BYTES:
            raise FixtureError("native browser fixture exceeds its copy budget")
        if time.monotonic() - self.started > MAX_SECONDS:
            raise FixtureError("native browser fixture copy timed out")


def trusted_output_parent(parent):
    for directory in (parent, *parent.parents):
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()):
            raise FixtureError("fixture output ancestor is not an owned directory")
        if metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise FixtureError("fixture output ancestor is writable by another account")


def copy_directory(source_fd, source_path, target, source_root, budget, depth=0):
    if depth > MAX_DEPTH:
        raise FixtureError("native browser fixture exceeds its directory depth")
    with os.scandir(source_fd) as entries:
        for entry in entries:
            budget.entries += 1
            budget.check()
            metadata = entry.stat(follow_symlinks=False)
            destination = target / entry.name
            original = source_path / entry.name
            if stat.S_ISLNK(metadata.st_mode):
                link = os.readlink(entry.name, dir_fd=source_fd)
                if len(os.fsencode(link)) > 4096:
                    raise FixtureError("native browser fixture has an oversized symlink")
                try:
                    resolved = (original.parent / link).resolve(strict=True)
                except (OSError, RuntimeError) as issue:
                    raise FixtureError("native browser fixture has an invalid symlink") from issue
                if not resolved.is_relative_to(source_root):
                    raise FixtureError("native browser fixture symlink escapes its source tree")
                if Path(link).is_absolute():
                    link = os.path.relpath(resolved, original.parent)
                os.symlink(link, destination)
                budget.symlinks += 1
            elif stat.S_ISDIR(metadata.st_mode):
                descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=source_fd)
                try:
                    held = os.fstat(descriptor)
                    if (held.st_dev, held.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise FixtureError("native browser source directory changed during copying")
                    destination.mkdir(mode=0o700)
                    copy_directory(descriptor, original, destination, source_root, budget, depth + 1)
                finally:
                    os.close(descriptor)
            elif stat.S_ISREG(metadata.st_mode):
                descriptor = os.open(entry.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=source_fd)
                with os.fdopen(descriptor, "rb", closefd=True) as source:
                    held = os.fstat(source.fileno())
                    if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise FixtureError("native browser source file changed during copying")
                    if budget.bytes + held.st_size > MAX_TOTAL_BYTES:
                        raise FixtureError("native browser fixture exceeds its copy budget")
                    mode = 0o700 if held.st_mode & 0o111 else 0o600
                    output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
                    copied = 0
                    with os.fdopen(output_fd, "wb", closefd=True) as output:
                        while chunk := source.read(1024 * 1024):
                            copied += len(chunk)
                            budget.bytes += len(chunk)
                            budget.check()
                            output.write(chunk)
                    after = os.fstat(source.fileno())
                    if copied != held.st_size or (held.st_size, held.st_mtime_ns, held.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns
                    ):
                        raise FixtureError("native browser source file mutated during copying")
                budget.files += 1
            else:
                raise FixtureError("native browser fixture contains a special file")


def prepare_fixture(source_root, relative_executable, output_parent):
    root = None
    root_identity = None
    try:
        source_root = Path(source_root).resolve(strict=True)
        output_parent = Path(output_parent).resolve(strict=True)
        relative_executable = Path(relative_executable)
        if relative_executable.is_absolute() or not relative_executable.parts or any(
            part in ("..", ".") for part in relative_executable.parts
        ):
            raise FixtureError("fixture executable must be inside its source tree")
        executable = source_root / relative_executable
        if executable.resolve(strict=True) != executable:
            raise FixtureError("fixture executable must be a physical regular file")
        metadata = executable.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            raise FixtureError("fixture executable must be a physical executable file")
        if output_parent.is_relative_to(source_root):
            raise FixtureError("fixture output cannot be inside its source tree")
        trusted_output_parent(output_parent)
        root = Path(tempfile.mkdtemp(prefix="native-chrome-", dir=output_parent))
        metadata = root.lstat()
        root_identity = (metadata.st_dev, metadata.st_ino)
        target = root / ("browser.app" if source_root.suffix == ".app" else "browser")
        target.mkdir(mode=0o700)
        descriptor = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        budget = Budget(time.monotonic())
        try:
            copy_directory(descriptor, source_root, target, source_root, budget)
        finally:
            os.close(descriptor)
        return Fixture(root, target / relative_executable, budget.files, budget.bytes, budget.symlinks)
    except (OSError, RuntimeError) as issue:
        if root is not None:
            current = root.lstat()
            if (current.st_dev, current.st_ino) == root_identity:
                shutil.rmtree(root)
        if isinstance(issue, FixtureError):
            raise
        raise FixtureError(f"native browser fixture copy failed: {type(issue).__name__}") from issue


def append_github_env(fixture, path):
    values = [
        ("AGENT_BRIDGE_TEST_PRIVATE_CHROME", str(fixture.executable)),
        ("AGENT_BRIDGE_TEST_CHROME_FIXTURE_ROOT", str(fixture.root)),
    ]
    if any("\n" in value or "\r" in value or "\0" in value or len(value) > 4096 for _, value in values):
        raise FixtureError("fixture path cannot be represented in a GitHub environment record")
    payload = "".join(f"{name}={value}\n" for name, value in values)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as output:
        metadata = os.fstat(output.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise FixtureError("GitHub environment destination must be a regular file")
        output.write(payload)


def system_source():
    if sys.platform == "darwin":
        candidates = [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        ]
        for executable in candidates:
            if executable.exists():
                root = executable.parents[2]
                return root, executable.relative_to(root)
    elif sys.platform.startswith("linux"):
        for executable in map(Path, [
            "/opt/google/chrome/chrome", "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
        ]):
            if executable.exists():
                return executable.parent, Path(executable.name)
    raise FixtureError("no supported system Chrome installation to copy")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-parent", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    try:
        source_root, relative_executable = system_source()
        fixture = prepare_fixture(source_root, relative_executable, args.output_parent)
        append_github_env(fixture, args.github_env)
    except FixtureError as issue:
        parser.exit(1, f"native browser fixture refused: {issue}\n")
    print(json.dumps(asdict(fixture), default=str, sort_keys=True))


if __name__ == "__main__":
    main()
