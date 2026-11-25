# SPDX-License-Identifier: Apache-2.0
import unittest

from comment_ratchet import findings, new_debt, scan_rust_comments


class CommentRatchetTests(unittest.TestCase):
    def test_literals_are_not_comments_and_lifetimes_are_not_strings(self):
        source = '''
const RAW: &str = r###"// TODO: data, not a comment
/* FIXME: still data */"###;
const BYTE: &[u8] = br#"// HACK data"#;
let url = "https://example.test/TODO";
let escaped = "\\\" // XXX data";
let slash = '/';
fn value<'a>(input: &'a str) { // TODO: real work
}
'''
        comments = scan_rust_comments(source)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]["line"], 8)
        self.assertIn("real work", comments[0]["text"])

    def test_nested_blocks_and_documentation_are_preserved(self):
        source = '''/** Public contract: input must outlive the operation. */
/* Safety: outer /* nested */ explanation. */
// SAFETY: the retained owner keeps this pointer alive.
// TODO: replace the temporary adapter.
// ----------------
'''
        comments = scan_rust_comments(source)
        self.assertEqual(len(comments), 5)
        self.assertTrue(comments[0]["documentation"])
        self.assertEqual([f["rule"] for f in findings("src/lib.rs", source)],
                         ["deferred-work", "decorative-divider"])

    def test_moving_a_comment_does_not_create_a_new_allowance(self):
        old = findings("src/lib.rs", "// TODO: existing debt\n")
        moved = findings("src/lib.rs", "\n\n// TODO: existing debt\n")
        self.assertEqual(new_debt(moved, old), [])
        changed = findings("src/lib.rs", "// TODO: unrelated debt\n")
        self.assertEqual(len(new_debt(changed, old)), 1)
        duplicated = findings("src/lib.rs", "// TODO: existing debt\n// TODO: existing debt\n")
        self.assertEqual(len(new_debt(duplicated, old)), 1)
        relocated = findings("src/other.rs", "// TODO: existing debt\n")
        self.assertEqual(len(new_debt(relocated, old)), 1)

    def test_urls_and_useful_explanations_are_not_debt(self):
        source = '''// https://example.test/docs
// Keep the handle open until the child has inherited it.
// SAFETY: only the owned process group is addressed.
/// Example: let value = 3;
'''
        self.assertEqual(findings("src/lib.rs", source), [])


if __name__ == "__main__":
    unittest.main()
