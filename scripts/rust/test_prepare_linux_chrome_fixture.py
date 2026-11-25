# SPDX-License-Identifier: Apache-2.0
import hashlib
from contextlib import redirect_stderr
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

if sys.platform == "linux":
    SPEC = importlib.util.spec_from_file_location(
        "linux_chrome_fixture", Path(__file__).with_name("prepare-linux-chrome-fixture.py")
    )
    MODULE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MODULE)


@unittest.skipUnless(sys.platform == "linux", "isolated Linux package fixture")
class LinuxFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bridge-linux-package-test-")
        self.base = Path(self.temporary.name)
        self.fixture = self.base / "fixture"
        self.fixture.mkdir(mode=0o700)
        self.payload = self.base / "payload.tar"

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, extras=(), omit=()):
        entries = [
            ("./opt/google/chrome/", tarfile.DIRTYPE, b"", 0o7777, ""),
            ("./opt/google/chrome/chrome", tarfile.REGTYPE, b"\x7fELFbrowser", 0o6777, ""),
            ("./opt/google/chrome/chrome-sandbox", tarfile.REGTYPE, b"\x7fELFsandbox", 0o4777, ""),
            ("./opt/google/chrome/data/resource.pak", tarfile.REGTYPE, b"resource", 0o6666, ""),
        ]
        with tarfile.open(self.payload, "w") as archive:
            for name, kind, content, mode, link in [*entries, *extras]:
                if name in omit:
                    continue
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = mode
                member.uid = 1234
                member.gid = 5678
                member.linkname = link
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

    def test_authentic_subtree_is_separate_and_unprivileged_before_finalization(self):
        self.archive([("./usr/bin/google-chrome", tarfile.SYMTYPE, b"", 0o777, "/opt/google/chrome/chrome")])
        report = MODULE.extract_browser(self.payload, self.fixture)
        self.assertEqual((self.fixture / "browser/chrome").read_bytes(), b"\x7fELFbrowser")
        self.assertEqual(stat.S_IMODE((self.fixture / "browser/chrome").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.fixture / "browser/data/resource.pak").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((self.fixture / "browser/chrome-sandbox").stat().st_mode), 0o600)
        self.assertEqual((self.fixture / "browser/chrome-sandbox").stat().st_nlink, 1)
        self.assertFalse((self.fixture / "usr").exists())
        self.assertEqual(report["helper_sha256"], hashlib.sha256(b"\x7fELFsandbox").hexdigest())
        self.assertEqual(report["helper_package_entry"]["uid"], 1234)

    def test_directory_modes_do_not_depend_on_root_umask(self):
        self.archive()
        previous = os.umask(0o077)
        try:
            MODULE.extract_browser(self.payload, self.fixture)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE((self.fixture / "browser").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.fixture / "browser/data").stat().st_mode), 0o755)

    def test_symlinks_hardlinks_and_special_members_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                fixture = self.base / f"refuse-{kind.decode()}"
                fixture.mkdir()
                self.archive([("./opt/google/chrome/alias", kind, b"", 0o777, "chrome")])
                with self.assertRaises(MODULE.FixtureError):
                    MODULE.extract_browser(self.payload, fixture)
                self.assertFalse((fixture / "browser/alias").exists())

    def test_traversal_duplicate_and_non_directory_root_are_refused(self):
        for member in [
            ("./opt/google/chrome/../outside", tarfile.REGTYPE, b"escape", 0o755, ""),
            ("./opt/google/chrome/chrome", tarfile.REGTYPE, b"replace", 0o755, ""),
            ("./opt/google/chrome", tarfile.SYMTYPE, b"", 0o777, "../../.."),
        ]:
            with self.subTest(name=member[0]), tempfile.TemporaryDirectory(dir=self.base) as directory:
                self.archive([member])
                with self.assertRaises(MODULE.FixtureError):
                    MODULE.extract_browser(self.payload, Path(directory))
        self.assertFalse((self.base / "outside").exists())

    def test_archive_byte_entry_and_helper_budgets_are_enforced(self):
        self.archive()
        for setting, bound in [("MAX_BYTES", 8), ("MAX_ENTRIES", 1), ("MAX_HELPER_BYTES", 4)]:
            with self.subTest(setting=setting), tempfile.TemporaryDirectory(dir=self.base) as directory:
                with patch.object(MODULE, setting, bound), self.assertRaises(MODULE.FixtureError):
                    MODULE.extract_browser(self.payload, Path(directory))

    def test_missing_or_non_native_helper_is_refused(self):
        self.archive(omit=("./opt/google/chrome/chrome-sandbox",))
        with self.assertRaises(OSError):
            MODULE.extract_browser(self.payload, self.fixture)
        with tempfile.TemporaryDirectory(dir=self.base) as directory:
            self.archive(omit=("./opt/google/chrome/chrome-sandbox",))
            with tarfile.open(self.payload, "a") as archive:
                member = tarfile.TarInfo("opt/google/chrome/chrome-sandbox")
                member.size = 10
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(b"not-native"))
            with self.assertRaises(MODULE.FixtureError):
                MODULE.extract_browser(self.payload, Path(directory))

    def simulate_privileged_preparation(self, parent, wrong_digest=False, post_failure=False):
        self.archive()
        helper_identity = set()
        temporary_root_identity = MODULE.identity(Path("/tmp").stat())
        ownership_changes = []
        original_extract = MODULE.extract_browser
        original_fstat = os.fstat
        original_verify = MODULE.verify_parent
        validations = 0

        def extracted(payload, fixture):
            report = original_extract(payload, fixture)
            helper_identity.add(MODULE.identity((fixture / "browser/chrome-sandbox").stat()))
            if wrong_digest:
                report["helper_sha256"] = "0" * 64
            return report

        def pretend_root_owner(descriptor):
            metadata = original_fstat(descriptor)
            if MODULE.identity(metadata) in helper_identity or MODULE.identity(metadata) == temporary_root_identity:
                fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
                fields.update(st_uid=0, st_gid=0)
                return SimpleNamespace(**fields)
            return metadata

        def record_chown(descriptor, uid, gid):
            ownership_changes.append((MODULE.identity(original_fstat(descriptor)), uid, gid))

        def verify(*arguments):
            nonlocal validations
            validations += 1
            if post_failure and validations == 3:
                published, = parent.iterdir()
                (published / "browser").rename(published / "moved-browser")
                (published / "browser").mkdir()
                replacement = published / "browser/chrome-sandbox"
                replacement.write_bytes(b"unrelated replacement")
                replacement.chmod(0o755)
                raise MODULE.FixtureError("injected postpublication refusal")
            original_verify(*arguments)

        with patch.object(MODULE, "authenticated_package", return_value=(self.payload, {"package": MODULE.PACKAGE})), \
             patch.object(MODULE, "extract_browser", side_effect=extracted), \
             patch.object(MODULE.os, "fstat", side_effect=pretend_root_owner), \
             patch.object(MODULE, "verify_parent", side_effect=verify), \
             patch.object(MODULE.os, "fchown", side_effect=record_chown), redirect_stderr(io.StringIO()):
            if wrong_digest:
                with self.assertRaisesRegex(MODULE.FixtureError, "no longer matches the authenticated package"):
                    MODULE.prepare(parent, os.geteuid(), os.getegid())
                self.assertEqual(ownership_changes, [])
                self.assertEqual(list(parent.iterdir()), [])
                return
            if post_failure:
                with self.assertRaisesRegex(MODULE.FixtureError, "injected postpublication refusal"):
                    MODULE.prepare(parent, os.geteuid(), os.getegid())
                published, = parent.iterdir()
                self.assertEqual(stat.S_IMODE((published / "moved-browser/chrome-sandbox").stat().st_mode), 0o600)
                replacement = published / "browser/chrome-sandbox"
                self.assertEqual(replacement.read_bytes(), b"unrelated replacement")
                self.assertEqual(stat.S_IMODE(replacement.stat().st_mode), 0o755)
                return
            result = MODULE.prepare(parent, os.geteuid(), os.getegid())
        helper = result / "browser/chrome-sandbox"
        self.assertEqual(helper.read_bytes(), b"\x7fELFsandbox")
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o4755)
        self.assertEqual(ownership_changes[0], (MODULE.identity(helper.stat()), 0, 0))
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o700)
        self.assertEqual((result / "browser/data/resource.pak").read_bytes(), b"resource")

    def test_complete_publication_finalizes_only_the_new_helper_fd(self):
        parent = Path("/tmp") / f"agent-bridge-browser-fixtures.{uuid.uuid4().hex[:12]}"
        parent.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, parent)
        self.simulate_privileged_preparation(parent)

    def test_changed_helper_digest_refuses_privilege_and_publication(self):
        parent = Path("/tmp") / f"agent-bridge-browser-fixtures.{uuid.uuid4().hex[:12]}"
        parent.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, parent)
        self.simulate_privileged_preparation(parent, wrong_digest=True)

    def test_postpublication_failure_revokes_the_held_inode_after_rename(self):
        parent = Path("/tmp") / f"agent-bridge-browser-fixtures.{uuid.uuid4().hex[:12]}"
        parent.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, parent)
        self.simulate_privileged_preparation(parent, post_failure=True)

    def test_publication_never_replaces_an_existing_name(self):
        source = self.base / "source"
        target = self.base / "target"
        source.mkdir()
        target.mkdir()
        (source / "new").mkdir()
        (source / "new/sentinel").write_text("new fixture")
        (target / "existing").mkdir()
        source_fd = os.open(source, MODULE.DIR_FLAGS)
        target_fd = os.open(target, MODULE.DIR_FLAGS)
        try:
            before = (target / "existing").stat().st_ino
            with self.assertRaises(FileExistsError):
                MODULE.rename_new(source_fd, "new", target_fd, "existing")
            self.assertEqual((target / "existing").stat().st_ino, before)
            MODULE.rename_new(source_fd, "new", target_fd, "created")
            self.assertEqual((target / "created/sentinel").read_text(), "new fixture")
        finally:
            os.close(source_fd)
            os.close(target_fd)

    def test_replaced_or_shared_destination_parent_is_refused(self):
        parent = self.base / "parent"
        parent.mkdir(mode=0o700)
        base_fd = os.open(self.base, MODULE.DIR_FLAGS)
        parent_fd = os.open(parent, MODULE.DIR_FLAGS)
        try:
            MODULE.verify_parent(base_fd, parent_fd, "parent", os.geteuid())
            parent.chmod(0o777)
            with self.assertRaises(MODULE.FixtureError):
                MODULE.verify_parent(base_fd, parent_fd, "parent", os.geteuid())
            parent.chmod(0o700)
            parent.rename(self.base / "moved")
            parent.mkdir(mode=0o700)
            with self.assertRaises(MODULE.FixtureError):
                MODULE.verify_parent(base_fd, parent_fd, "parent", os.geteuid())
        finally:
            os.close(parent_fd)
            os.close(base_fd)

    def test_apt_uses_only_private_state_and_the_pinned_signed_google_source(self):
        options = MODULE.apt_arguments(self.base, "amd64")
        source = (self.base / "sources.list").read_text()
        self.assertIn("https://dl.google.com/linux/chrome/deb/ stable main", source)
        self.assertIn(f"signed-by={self.base / 'google.asc'},{MODULE.FINGERPRINT}", source)
        self.assertNotIn("trusted=yes", source)
        self.assertIn("APT::Get::AllowUnauthenticated=false", options)
        self.assertIn("APT::Sandbox::User=root", options)
        with patch.dict(os.environ, {"APT_CONFIG": "/untrusted/config", "LD_PRELOAD": "/untrusted/library"}):
            with patch.object(MODULE.subprocess, "run") as run:
                MODULE.run_checked(["/usr/bin/apt-get", *options, "update"], self.base, apt=True)
                environment = run.call_args.kwargs["env"]
                self.assertEqual(environment["APT_CONFIG"], str(self.base / "apt.conf"))
                self.assertNotIn("LD_PRELOAD", environment)
        config = (self.base / "apt.conf").read_text()
        self.assertIn(f'Dir::Etc::parts "{self.base / "empty"}";', config)
        self.assertIn('Dir::Etc::main "/dev/null";', config)
        with self.assertRaises(MODULE.FixtureError):
            MODULE.apt_arguments(self.base, "unsupported")

    def test_only_the_pinned_primary_key_is_accepted(self):
        fingerprint = f"fpr:::::::::{MODULE.FINGERPRINT}:\n"
        MODULE.require_google_primary("pub:::::::::\n" + fingerprint + "sub:::::::::\nfpr:::::::::OTHER_SUBKEY:\n")
        for records in ("", "pub:::::::::\nfpr:::::::::UNTRUSTED:\n",
                        "pub:::::::::\n" + fingerprint + "pub:::::::::\nfpr:::::::::OTHER_PRIMARY:\n",
                        "sub:::::::::\n" + fingerprint):
            with self.subTest(records=records), self.assertRaises(MODULE.FixtureError):
                MODULE.require_google_primary(records)

    def test_unprivileged_cli_refuses_before_network_or_publication(self):
        with patch.object(MODULE.os, "geteuid", return_value=1000), patch.object(MODULE, "prepare") as prepare:
            with patch.object(sys, "argv", ["fixture", "--output-parent", str(self.base)]), self.assertRaises(SystemExit):
                MODULE.main()
            prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
