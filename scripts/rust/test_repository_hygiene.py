#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import tempfile
import unittest
from pathlib import Path
import repository_hygiene as hygiene


class HygieneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reference = "Adapted from " + "Desk" + "MCP under Apache-2.0."

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_only_the_reviewed_attribution_line_is_permitted(self):
        self.write("NOTICE", self.reference + "\n")
        self.assertEqual(hygiene.scan_files(self.root, ["NOTICE"], {"NOTICE": [self.reference]}), [])
        self.write("NOTICE", self.reference + "\nNew " + "Desk" + "MCP dependency\n")
        errors = hygiene.scan_files(self.root, ["NOTICE"], {"NOTICE": [self.reference]})
        self.assertTrue(any("NOTICE:2" in error for error in errors))

    def test_allowlisted_provenance_never_exempts_secrets(self):
        line = self.reference + " github" + "_pat_" + "fixture"
        self.write("NOTICE", line)
        self.assertTrue(any("secret" in error.lower() for error in hygiene.scan_files(self.root, ["NOTICE"], {"NOTICE": [line]})))

    def test_binary_and_stale_allowances_are_rejected(self):
        (self.root / "helper.exe").write_bytes(b"not a tracked release resource")
        self.write("NOTICE", "Current attribution\n")
        errors = hygiene.scan_files(self.root, ["helper.exe", "NOTICE"], {"NOTICE": [self.reference]})
        self.assertTrue(any("binary" in error.lower() for error in errors))
        self.assertTrue(any("stale" in error.lower() for error in errors))


if __name__ == "__main__":
    unittest.main()
