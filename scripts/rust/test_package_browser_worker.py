import hashlib
import importlib.util
import pathlib
import tempfile
import types
import unittest
import zipfile

SCRIPT = pathlib.Path(__file__).with_name('package-browser-worker.py')
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location('browser_package', SCRIPT)
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
else:
    package = types.SimpleNamespace()


class VerifiedArchiveTests(unittest.TestCase):
    def extract(self, *args, **kwargs):
        self.assertTrue(callable(getattr(package, 'extract_verified_archive', None)), 'verified archive extractor is not implemented')
        return package.extract_verified_archive(*args, **kwargs)

    def archive(self, root, entries):
        source = root / 'input.zip'
        with zipfile.ZipFile(source, 'w') as z:
            for name, content in entries:
                z.writestr(name, content)
        return source, hashlib.sha256(source.read_bytes()).hexdigest()

    def test_wrong_digest_refuses_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, _ = self.archive(root, [('runtime/node.exe', b'fixture')])
            target = root / 'out'
            with self.assertRaisesRegex(ValueError, 'digest'):
                self.extract(source, '0' * 64, target)
            self.assertFalse(target.exists())

    def test_verified_zip_cannot_traverse_outside_private_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, digest = self.archive(root, [('../outside.txt', b'unsafe')])
            with self.assertRaisesRegex(ValueError, 'path'):
                self.extract(source, digest, root / 'out')
            self.assertFalse((root / 'outside.txt').exists())
            self.assertFalse((root / 'out').exists())

    def test_case_aliases_are_rejected_before_windows_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, digest = self.archive(root, [('A.txt', b'first'), ('a.txt', b'overwrite')])
            with self.assertRaisesRegex(ValueError, 'alias'):
                self.extract(source, digest, root / 'out')
            self.assertFalse((root / 'out').exists())

    def test_selected_official_entries_are_copied_without_unrequested_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, digest = self.archive(root, [('runtime/node.exe', b'node fixture'), ('runtime/LICENSE', b'license fixture'), ('runtime/npm/unused', b'not shipped')])
            self.extract(source, digest, root / 'out', selected={'runtime/node.exe': 'node.exe', 'runtime/LICENSE': 'notices/Node-LICENSE'})
            self.assertEqual((root / 'out/node.exe').read_bytes(), b'node fixture')
            self.assertEqual((root / 'out/notices/Node-LICENSE').read_bytes(), b'license fixture')
            self.assertFalse((root / 'out/runtime/npm/unused').exists())

    def test_windows_debug_log_guard_is_an_empty_manifest_member_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            chrome = root / 'browser/chrome-win64/chrome.exe'
            chrome.parent.mkdir(parents=True)
            chrome.write_bytes(b'fixture executable')
            guard = package.create_diagnostic_guard(chrome)
            self.assertEqual(guard, chrome.with_name('debug.log'))
            self.assertEqual(guard.read_bytes(), b'')
            with self.assertRaises(FileExistsError):
                package.create_diagnostic_guard(chrome)
            self.assertEqual(guard.read_bytes(), b'')
            guard.write_bytes(b'preserved diagnostic')
            with self.assertRaises(FileExistsError):
                package.create_diagnostic_guard(chrome)
            self.assertEqual(guard.read_bytes(), b'preserved diagnostic')


if __name__ == '__main__':
    unittest.main()
