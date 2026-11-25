#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build one authenticated Chrome/SUID sandbox fixture in ephemeral Linux CI."""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

PACKAGE = "google-chrome-stable"
KEY_URL = "https://dl.google.com/linux/linux_signing_key.pub"
# Google's active primary key: https://www.google.com/linuxrepositories/
FINGERPRINT = "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
MAX_BYTES = 4 * 1024**3
MAX_PACKAGE_BYTES = 1024**3
MAX_ENTRIES = 30000
MAX_HELPER_BYTES = 8 * 1024**2
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
DIR_FLAGS = READ_FLAGS | os.O_DIRECTORY
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class FixtureError(RuntimeError):
    pass


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


@contextmanager
def held_regular(path, limit, root_owned=False):
    with ExitStack() as stack:
        parent = os.open("/", DIR_FLAGS)
        stack.callback(os.close, parent)
        for component in path.parts[1:-1]:
            parent = os.open(component, DIR_FLAGS, dir_fd=parent)
            stack.callback(os.close, parent)
            metadata = os.fstat(parent)
            if root_owned and (metadata.st_uid != 0 or (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX)):
                raise FixtureError("authenticated package ancestor is not protected")
        descriptor = os.open(path.name, READ_FLAGS, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise FixtureError("fixture input must be a bounded physical regular file")
            if root_owned and (before.st_uid != 0 or before.st_mode & 0o022):
                raise FixtureError("authenticated package input is not protected")
            yield source, before
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise FixtureError("fixture input changed while reading")


def held_file(path, limit, root_owned=False):
    with held_regular(path, limit, root_owned) as (source, before):
        data = source.read(limit + 1)
        if len(data) != before.st_size or len(data) > limit:
            raise FixtureError("fixture input changed while reading")
        return data, before


def file_digest(path, limit, root_owned=False):
    with held_regular(path, limit, root_owned) as (source, before):
        digest = hashlib.sha256()
        count = 0
        while chunk := source.read(1024**2):
            count += len(chunk)
            if count > limit:
                raise FixtureError("fixture input exceeds its size limit")
            digest.update(chunk)
        if count != before.st_size:
            raise FixtureError("fixture input changed while hashing")
        return digest.hexdigest()


def run_checked(arguments, stage, stdout=sys.stderr, limit=MAX_PACKAGE_BYTES, apt=False):
    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    return subprocess.run(
        ["/usr/bin/timeout", "--kill-after=5s", "180s", *map(str, arguments)],
        cwd=stage, env={**CLEAN_ENV, **({"APT_CONFIG": str(stage / "apt.conf")} if apt else {})},
        check=True, stdout=stdout, preexec_fn=bound_output,
    )


def apt_arguments(stage, architecture):
    if architecture not in ("amd64", "arm64"):
        raise FixtureError("unsupported Chrome package architecture")
    (stage / "sources.list").write_text(
        f"deb [arch={architecture} signed-by={stage / 'google.asc'},{FINGERPRINT}] "
        "https://dl.google.com/linux/chrome/deb/ stable main\n", encoding="ascii"
    )
    for directory in ("lists", "cache", "state", "empty"):
        (stage / directory).mkdir(mode=0o700)
    (stage / "status").touch(mode=0o600)
    # No inherited apt configuration, hooks, sources, or unauthenticated fallback.
    # APT helpers share this preparer's uid to keep acquisition in root-only staging.
    settings = {
        "Dir::Etc::main": "/dev/null", "Dir::Etc::parts": str(stage / "empty"),
        "Dir::Etc::sourcelist": str(stage / "sources.list"),
        "Dir::Etc::sourceparts": str(stage / "empty"),
        "Dir::State": str(stage / "state"), "Dir::State::status": str(stage / "status"),
        "Dir::State::lists": str(stage / "lists"), "Dir::Cache": str(stage / "cache"),
        "Dir::Log": str(stage), "APT::Architecture": architecture,
        "APT::Sandbox::User": "root",
        "Acquire::Languages": "none", "Acquire::Retries": "0",
        "APT::Update::Error-Mode": "any", "APT::Get::AllowUnauthenticated": "false",
        "Acquire::AllowInsecureRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false",
    }
    (stage / "apt.conf").write_text(
        "".join(f'{key} "{value}";\n' for key, value in settings.items()), encoding="ascii"
    )
    return [argument for key, value in settings.items() for argument in ("-o", f"{key}={value}")]


def require_google_primary(records):
    primary = []
    pending = False
    for line in records.splitlines():
        fields = line.split(":")
        if fields[0] in ("pub", "sub"):
            pending = fields[0] == "pub"
        elif fields[0] == "fpr" and pending:
            if len(fields) < 10:
                raise FixtureError("malformed Google signing-key fingerprint")
            primary.append(fields[9])
            pending = False
    if primary != [FINGERPRINT]:
        raise FixtureError("Google signing key does not match the pinned active primary")


def verified_key(stage):
    key = stage / "google.asc"
    run_checked(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location",
                 "--proto", "=https", "--proto-redir", "=https", "--max-time", "30",
                 "--max-filesize", str(1024**2), "--output", key, KEY_URL], stage, limit=1024**2)
    held_file(key, 1024**2, root_owned=True)
    (stage / "gnupg").mkdir(mode=0o700)
    records = subprocess.check_output(
        ["/usr/bin/gpg", "--no-options", "--batch", "--homedir", str(stage / "gnupg"),
         "--no-default-keyring", "--with-colons", "--show-keys", str(key)],
        env=CLEAN_ENV, timeout=15, text=True,
    )
    require_google_primary(records)


def authenticated_package(stage):
    verified_key(stage)
    architecture = subprocess.check_output(
        ["/usr/bin/dpkg", "--print-architecture"], env=CLEAN_ENV, timeout=10, text=True
    ).strip()
    arguments = apt_arguments(stage, architecture)
    run_checked(["/usr/bin/apt-get", *arguments, "update"], stage, apt=True)
    run_checked(["/usr/bin/apt-get", *arguments, "download", f"{PACKAGE}:{architecture}"], stage, apt=True)
    archives = list(stage.glob("*.deb"))
    if len(archives) != 1:
        raise FixtureError("authenticated APT download did not produce one package")
    archive = archives[0]
    package_hash = file_digest(archive, MAX_PACKAGE_BYTES, root_owned=True)
    fields = subprocess.check_output(
        ["/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", str(archive)],
        env=CLEAN_ENV, timeout=10, text=True,
    ).splitlines()
    if len(fields) != 3 or fields[0] != PACKAGE or fields[2] != architecture or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", fields[1]):
        raise FixtureError("downloaded Chrome package identity differs from the selected package")
    payload = stage / "payload.tar"
    with payload.open("xb") as output:
        run_checked(["/usr/bin/dpkg-deb", "--fsys-tarfile", archive], stage, output, MAX_BYTES)
    return payload, {"package": fields[0], "version": fields[1], "architecture": fields[2],
                     "package_sha256": package_hash, "signing_primary": FINGERPRINT}


def extract_browser(payload, fixture):
    browser = fixture / "browser"
    browser.mkdir(mode=0o755)
    seen = set()
    total = 0
    count = 0
    helper_hash = None
    helper_entry = None
    with tarfile.open(payload, "r:") as archive:
        for member in archive:
            count += 1
            total += max(0, member.size)
            if count > MAX_ENTRIES or total > MAX_BYTES:
                raise FixtureError("Chrome package exceeds extraction limits")
            name = member.name.removeprefix("./")
            if name.rstrip("/") == "opt/google/chrome":
                if not member.isdir():
                    raise FixtureError("Chrome package browser root must be a directory")
                continue
            if not name.startswith("opt/google/chrome/"):
                continue
            relative = name[len("opt/google/chrome/"):].rstrip("/")
            parts = relative.split("/")
            if not relative or len(parts) > 32 or any(part in ("", ".", "..") for part in parts):
                raise FixtureError("Chrome package contains an invalid browser path")
            if relative in seen or not (member.isdir() or member.isreg()):
                raise FixtureError("Chrome package has duplicate, linked, or special browser entries")
            seen.add(relative)
            target = browser.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            if member.isdir():
                target.mkdir(exist_ok=True, mode=0o755)
                continue
            if relative == "chrome-sandbox" and member.size > MAX_HELPER_BYTES:
                raise FixtureError("Chrome sandbox helper exceeds its size limit")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            digest = hashlib.sha256()
            copied = 0
            with os.fdopen(descriptor, "wb") as output, archive.extractfile(member) as source:
                while chunk := source.read(1024**2):
                    copied += len(chunk)
                    if copied > member.size:
                        raise FixtureError("Chrome package member exceeds its declared size")
                    digest.update(chunk)
                    output.write(chunk)
                if copied != member.size:
                    raise FixtureError("Chrome package member is truncated")
                output.flush()
                os.fchmod(output.fileno(), 0o600 if relative == "chrome-sandbox" else (0o755 if member.mode & 0o111 else 0o644))
            if relative == "chrome-sandbox":
                helper_hash = digest.hexdigest()
                helper_entry = {"type": "regular", "size": member.size, "uid": member.uid,
                                "gid": member.gid, "mode": oct(member.mode)}
    for directory, _, _ in os.walk(browser):
        os.chmod(directory, 0o755)
    for name in ("chrome", "chrome-sandbox"):
        with held_regular(browser / name, MAX_BYTES if name == "chrome" else MAX_HELPER_BYTES) as (source, metadata):
            if source.read(4) != b"\x7fELF" or (name == "chrome" and not metadata.st_mode & 0o111):
                raise FixtureError("Chrome and its sandbox must be physical native executables")
    if helper_hash is None:
        raise FixtureError("Chrome package does not contain its sandbox helper")
    return {"entries": len(seen), "bytes": total, "helper_sha256": helper_hash,
            "helper_package_entry": helper_entry}


def verify_parent(tmp_fd, parent_fd, name, uid):
    held = os.fstat(parent_fd)
    named = os.stat(name, dir_fd=tmp_fd, follow_symlinks=False)
    if identity(held) != identity(named) or not stat.S_ISDIR(held.st_mode) or held.st_uid != uid or stat.S_IMODE(held.st_mode) != 0o700:
        raise FixtureError("private fixture parent changed or is not privately owned")


def rename_new(source_fd, source, target_fd, target):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), 1) != 0:
        raise OSError(ctypes.get_errno(), "fixture publication refused")


def prepare(output_parent, uid, gid):
    completed = False
    if output_parent.parent != Path("/tmp") or not re.fullmatch(r"agent-bridge-browser-fixtures\.[A-Za-z0-9]{6,20}", output_parent.name):
        raise FixtureError("Linux fixture parent must be a fresh CI directory directly under /tmp")
    with ExitStack() as stack:
        tmp_fd = os.open("/tmp", DIR_FLAGS)
        stack.callback(os.close, tmp_fd)
        temporary = os.fstat(tmp_fd)
        if temporary.st_uid != 0 or (temporary.st_mode & 0o022 and not temporary.st_mode & stat.S_ISVTX):
            raise FixtureError("system temporary directory is not protected")
        parent_fd = os.open(output_parent.name, DIR_FLAGS, dir_fd=tmp_fd)
        stack.callback(os.close, parent_fd)
        verify_parent(tmp_fd, parent_fd, output_parent.name, uid)
        with tempfile.TemporaryDirectory(prefix="agent-bridge-authenticated-chrome-", dir="/tmp") as temporary:
            stage = Path(temporary)
            stage_fd = os.open(stage, DIR_FLAGS)
            stack.callback(os.close, stage_fd)
            payload, provenance = authenticated_package(stage)
            fixture = stage / "fixture"
            fixture.mkdir(mode=0o700)
            provenance.update(extract_browser(payload, fixture))
            helper = fixture / "browser/chrome-sandbox"
            descriptor = os.open(helper, READ_FLAGS)
            source = stack.enter_context(os.fdopen(descriptor, "rb"))
            metadata = os.fstat(source.fileno())
            data = source.read(MAX_HELPER_BYTES + 1)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or hashlib.sha256(data).hexdigest() != provenance["helper_sha256"]:
                raise FixtureError("new sandbox inode no longer matches the authenticated package")
            def revoke_unconfirmed_helper():
                if not completed:
                    os.fchmod(source.fileno(), 0o600)
            stack.callback(revoke_unconfirmed_helper)
            os.fchown(source.fileno(), 0, 0)
            os.fchmod(source.fileno(), 0o4755)
            installed = os.fstat(source.fileno())
            if installed.st_uid != 0 or installed.st_gid != 0 or stat.S_IMODE(installed.st_mode) != 0o4755:
                raise FixtureError("private sandbox helper permissions did not take effect")
            provenance["helper_identity"] = {"dev": installed.st_dev, "ino": installed.st_ino,
                                             "uid": installed.st_uid, "gid": installed.st_gid,
                                             "mode": oct(stat.S_IMODE(installed.st_mode)), "nlink": installed.st_nlink}
            fixture_fd = os.open(fixture, DIR_FLAGS)
            stack.callback(os.close, fixture_fd)
            os.fchown(fixture_fd, uid, gid)
            os.fchmod(fixture_fd, 0o700)
            verify_parent(tmp_fd, parent_fd, output_parent.name, uid)
            name = f"native-chrome-{uuid.uuid4().hex}"
            rename_new(stage_fd, "fixture", parent_fd, name)
            if identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != identity(os.fstat(fixture_fd)):
                raise FixtureError("published fixture identity changed")
            verify_parent(tmp_fd, parent_fd, output_parent.name, uid)
            provenance["fixture_root"] = str(output_parent / name)
            print(json.dumps(provenance, sort_keys=True), file=sys.stderr)
        completed = True
        return output_parent / name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-parent", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        uid = int(os.environ.get("SUDO_UID", "0"))
        gid = int(os.environ.get("SUDO_GID", "-1"))
        if sys.platform != "linux" or os.geteuid() != 0 or uid <= 0 or gid < 0:
            raise FixtureError("this preparation requires sudo from the Linux CI test user")
        os.umask(0o077)
        root = prepare(arguments.output_parent, uid, gid)
    except (FixtureError, OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as issue:
        parser.exit(1, f"authenticated Linux Chrome fixture refused: {issue}\n")
    print(f"AGENT_BRIDGE_TEST_PRIVATE_CHROME={root}/browser/chrome")
    print(f"AGENT_BRIDGE_TEST_CHROME_FIXTURE_ROOT={root}")


if __name__ == "__main__":
    main()
