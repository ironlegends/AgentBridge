# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "chrome_fixture", Path(__file__).with_name("prepare-native-chrome-fixture.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


@unittest.skipUnless(os.name == "posix", "Unix Chrome fixture")
class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="bridge-chrome-copy-test-")
        self.base = Path(self.scratch.name).resolve()
        self.source = self.base / "source"
        self.output = self.base / "output"
        self.source.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self.executable = self.source / "chrome"
        self.executable.write_bytes(b"fixture executable bytes")
        self.executable.chmod(0o777)

    def tearDown(self):
        self.scratch.cleanup()

    def prepare(self):
        return MODULE.prepare_fixture(self.source, Path("chrome"), self.output)

    def test_copy_is_private_preserves_executability_and_never_changes_source(self):
        self.source.chmod(0o777)
        (self.source / "resource.pak").write_bytes(b"resource")
        before = self.executable.stat()
        fixture = self.prepare()
        self.assertEqual(fixture.executable.read_bytes(), self.executable.read_bytes())
        self.assertNotEqual(fixture.executable.stat().st_ino, before.st_ino)
        self.assertEqual(fixture.executable.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(fixture.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(fixture.executable.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((fixture.root / "browser/resource.pak").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(self.executable.stat().st_mode), 0o777)
        self.assertEqual(self.executable.stat().st_ino, before.st_ino)

    def test_internal_bundle_symlinks_and_absolute_internal_link_stay_in_copy(self):
        version = self.source / "Versions/1/Resources"
        version.mkdir(parents=True)
        (version / "data").write_text("owned resource")
        (self.source / "Versions/Current").symlink_to("1", target_is_directory=True)
        (self.source / "Resources").symlink_to("Versions/Current/Resources", target_is_directory=True)
        (self.source / "Absolute").symlink_to(version / "data")
        fixture = self.prepare()
        self.assertEqual(os.readlink(fixture.root / "browser/Resources"), "Versions/Current/Resources")
        self.assertEqual((fixture.root / "browser/Resources/data").read_text(), "owned resource")
        absolute_copy = fixture.root / "browser/Absolute"
        self.assertFalse(Path(os.readlink(absolute_copy)).is_absolute())
        self.assertTrue(absolute_copy.resolve().is_relative_to(fixture.root))
        self.assertEqual(absolute_copy.read_text(), "owned resource")

    def test_app_bundle_keeps_an_app_directory_for_native_bundle_discovery(self):
        app = self.base / "Original.app"
        app.mkdir()
        executable = app / "Contents/MacOS/Fixture"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"bundle executable")
        executable.chmod(0o755)
        fixture = MODULE.prepare_fixture(app, Path("Contents/MacOS/Fixture"), self.output)
        self.assertEqual(fixture.executable.parents[2].suffix, ".app")
        self.assertEqual(fixture.executable.read_bytes(), b"bundle executable")

    def test_external_symlink_is_rejected_without_copying_or_removing_its_target(self):
        outside = self.base / "outside"
        outside.write_bytes(b"excluded sentinel")
        (self.source / "escape").symlink_to("../outside")
        with self.assertRaises(MODULE.FixtureError):
            self.prepare()
        self.assertEqual(outside.read_bytes(), b"excluded sentinel")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.source / "fifo", 0o600)
        started = time.monotonic()
        with self.assertRaises(MODULE.FixtureError):
            self.prepare()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_hardlinked_source_files_become_independent_private_files(self):
        os.link(self.executable, self.source / "linked")
        fixture = self.prepare()
        copied_link = fixture.root / "browser/linked"
        self.assertEqual(fixture.executable.stat().st_nlink, 1)
        self.assertEqual(copied_link.stat().st_nlink, 1)
        self.assertNotEqual(copied_link.stat().st_ino, fixture.executable.stat().st_ino)
        self.assertEqual(self.executable.stat().st_nlink, 2)

    def test_relative_executable_cannot_escape_or_be_a_symlink(self):
        with self.assertRaises(MODULE.FixtureError):
            MODULE.prepare_fixture(self.source, Path("../outside"), self.output)
        (self.source / "alias").symlink_to("chrome")
        with self.assertRaises(MODULE.FixtureError):
            MODULE.prepare_fixture(self.source, Path("alias"), self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_copy_budget_failure_cleans_only_the_new_fixture(self):
        untouched = self.output / "existing"
        untouched.mkdir()
        (untouched / "sentinel").write_text("retain")
        with patch.object(MODULE, "MAX_TOTAL_BYTES", 8):
            with self.assertRaises(MODULE.FixtureError):
                self.prepare()
        self.assertEqual(list(self.output.iterdir()), [untouched])
        self.assertEqual((untouched / "sentinel").read_text(), "retain")

    def test_untrusted_nonsticky_output_ancestor_is_refused(self):
        self.output.chmod(0o777)
        with self.assertRaises(MODULE.FixtureError):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_github_environment_records_are_literal_and_bounded(self):
        fixture = self.prepare()
        environment = self.base / "github-env"
        MODULE.append_github_env(fixture, environment)
        self.assertEqual(environment.read_text().splitlines(), [
            f"AGENT_BRIDGE_TEST_PRIVATE_CHROME={fixture.executable}",
            f"AGENT_BRIDGE_TEST_CHROME_FIXTURE_ROOT={fixture.root}",
        ])
        invalid = MODULE.Fixture(Path("/tmp/invalid\nINJECTED=yes"), fixture.executable, 0, 0, 0)
        before = environment.read_bytes()
        with self.assertRaises(MODULE.FixtureError):
            MODULE.append_github_env(invalid, environment)
        self.assertEqual(environment.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
