#!/usr/bin/env python3
"""Build the offline, immutable Windows Playwright runtime from pinned archives."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile

NODE_VERSION = '24.14.0'
NODE_ARCHIVE_SHA256 = '313fa40c0d7b18575821de8cb17483031fe07d95de5994f6f435f3b345f85c66'
NODE_EXE_SHA256 = '63c259c81e5d472b5f11c8d506070130cb04a1ecf84b80377a34ed6ec9048088'
NODE_URL = f'https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-win-x64.zip'
PLAYWRIGHT_VERSION = '1.63.0'
PLAYWRIGHT_SRI = 'sha512-rYCsBF/M5HjUch52bbtVONEFjv6Xu8sm8h72dNlR5bzIE1fvC/bxgspzkjSfU+MweEMmPM8KJebG6nnyxo5mCg=='
PLAYWRIGHT_URL = f'https://registry.npmjs.org/playwright-core/-/playwright-core-{PLAYWRIGHT_VERSION}.tgz'
CHROMIUM_VERSION = '153.0.8010.12'
CHROMIUM_REVISION = '1243'
CHROMIUM_ARCHIVE_SHA256 = '415968b02065d4a9e2c10b85f0ae9f489b8fba500e94d9d0a7b7c4852a7234c1'
CHROMIUM_URL = f'https://cdn.playwright.dev/builds/cft/{CHROMIUM_VERSION}/win64/chrome-win64.zip'
MAX_EXPANDED_BYTES = 4 * 1024 ** 3
MAX_ENTRIES = 50_000
WORKER_FILES = ['.gitattributes', 'worker.mjs', 'protocol.mjs', 'validation.mjs', 'session.mjs', 'driver.mjs', 'package.json', 'package-lock.json', 'README.md', 'NOTICE', 'notices/DeskMCP-LICENSE']


def digest_file(path, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('invalid archive path')
    value = value.removesuffix('/')
    parts = value.split('/')
    if any(not part or part in ('.', '..') or part[-1:] in ('.', ' ')
           or re.search(r'[\x00-\x1f<>:"|?*]', part)
           or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part)
           for part in parts):
        raise ValueError('invalid archive path')
    return PurePosixPath(*parts)


def extract_verified_archive(source, expected_sha256, target, selected=None):
    """Preflight all entries, then extract into a fresh directory without links."""
    source, target = Path(source), Path(target)
    if digest_file(source) != expected_sha256:
        raise ValueError('archive digest does not match the pinned release')
    if target.exists() or target.is_symlink():
        raise ValueError('extraction destination already exists')
    archive = zipfile.ZipFile(source) if zipfile.is_zipfile(source) else tarfile.open(source, 'r:gz')
    try:
        entries, aliases, total, output_aliases = [], {}, 0, set()
        members = archive.infolist() if isinstance(archive, zipfile.ZipFile) else archive.getmembers()
        if len(members) > MAX_ENTRIES:
            raise ValueError('archive entry budget exceeded')
        for member in members:
            if isinstance(archive, zipfile.ZipFile):
                name, directory, size = member.filename, member.is_dir(), member.file_size
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                    raise ValueError('archive links and special files are forbidden')
            else:
                name, directory, size = member.name, member.isdir(), member.size
                if not (member.isdir() or member.isfile()):
                    raise ValueError('archive links and special files are forbidden')
            relative = safe_relative(name)
            key = str(relative).casefold()
            if key in aliases:
                raise ValueError('case alias in archive')
            aliases[key] = directory
            total += size
            if size < 0 or total > MAX_EXPANDED_BYTES:
                raise ValueError('archive expanded byte budget exceeded')
            if not directory and (selected is None or name in selected):
                out = safe_relative(selected[name] if selected is not None else name)
                if str(out).casefold() in output_aliases:
                    raise ValueError('case alias in selected output')
                output_aliases.add(str(out).casefold())
                entries.append((member, out, size))
        for name in aliases:
            for parent in PurePosixPath(name).parents:
                if str(parent) != '.' and aliases.get(str(parent)) is False:
                    raise ValueError('file directory alias in archive')
        if selected is not None and len(entries) != len(selected):
            raise ValueError('required release entry is absent')
        target.mkdir(parents=True)
        try:
            for member, relative, size in entries:
                output = target.joinpath(*relative.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                source_stream = archive.open(member) if isinstance(archive, zipfile.ZipFile) else archive.extractfile(member)
                with source_stream as stream, output.open('xb') as destination:
                    copied = 0
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        copied += len(chunk)
                        if copied > size:
                            raise ValueError('archive entry exceeds its declared size')
                        destination.write(chunk)
                    if copied != size:
                        raise ValueError('archive entry is truncated')
        except BaseException:
            shutil.rmtree(target)
            raise
    finally:
        archive.close()


def create_diagnostic_guard(chromium_executable):
    """Reserve the default log name; the runtime pins it against writes/deletes.

    Chromium base logging then falls back to the owned worker cwd instead of
    creating an unlisted file beside its executable. Keep the guard immutable.
    """
    guard = chromium_executable.with_name('debug.log')
    with guard.open('xb'):
        pass
    return guard


def build(args):
    output = args.output.resolve()
    if output.exists():
        raise ValueError('output must be a new, inactive directory')
    if not args.chromium_credits.is_file() or args.chromium_credits.stat().st_size < 10_000:
        raise ValueError('complete Chromium third-party credits are required')
    sri = 'sha512-' + base64.b64encode(bytes.fromhex(digest_file(args.playwright_archive, 'sha512'))).decode('ascii')
    if sri != PLAYWRIGHT_SRI:
        raise ValueError('Playwright npm integrity does not match the locked package')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.browser-building-', dir=output.parent))
    try:
        node = stage / 'node'
        extract_verified_archive(args.node_archive, NODE_ARCHIVE_SHA256, node, {
            f'node-v{NODE_VERSION}-win-x64/node.exe': 'node.exe',
            f'node-v{NODE_VERSION}-win-x64/LICENSE': 'notices/Node-LICENSE',
        })
        if digest_file(node / 'node.exe') != NODE_EXE_SHA256:
            raise ValueError('Node executable digest differs from official SHASUMS256.txt')
        bundle = stage / 'bundle'
        node.rename(bundle)
        npm = stage / 'npm'
        extract_verified_archive(args.playwright_archive, digest_file(args.playwright_archive), npm)
        metadata = json.loads((npm / 'package/package.json').read_text(encoding='utf-8'))
        if metadata['version'] != PLAYWRIGHT_VERSION:
            raise ValueError('Playwright package version differs from the fixed contract')
        browsers = json.loads((npm / 'package/browsers.json').read_text(encoding='utf-8'))
        chromium = next(item for item in browsers['browsers'] if item['name'] == 'chromium')
        if chromium['browserVersion'] != CHROMIUM_VERSION or chromium['revision'] != CHROMIUM_REVISION:
            raise ValueError('Chromium release is not the runtime shipped with this Playwright version')
        (bundle / 'node_modules').mkdir()
        (npm / 'package').rename(bundle / 'node_modules/playwright-core')
        extract_verified_archive(args.chromium_archive, CHROMIUM_ARCHIVE_SHA256, bundle / 'browser')
        executable = bundle / 'browser/chrome-win64/chrome.exe'
        if not executable.is_file():
            raise ValueError('dedicated Chromium executable is absent')
        create_diagnostic_guard(executable)
        for relative in WORKER_FILES:
            source = args.worker_root / relative
            if not source.is_file() or source.is_symlink():
                raise ValueError(f'missing physical worker source: {relative}')
            destination = bundle / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        shutil.copyfile(args.chromium_credits, bundle / 'notices/Chromium-CREDITS.html')
        files = []
        for path in sorted(bundle.rglob('*'), key=lambda p: p.relative_to(bundle).as_posix()):
            if path.is_symlink():
                raise ValueError('unexpected resource link')
            if path.is_file():
                files.append({'path': path.relative_to(bundle).as_posix(), 'bytes': path.stat().st_size, 'sha256': digest_file(path)})
        manifest = {
            'schema_version': 1, 'protocol_version': 2, 'worker': 'worker.mjs',
            'node': {'version': NODE_VERSION, 'path': 'node.exe', 'sha256': NODE_EXE_SHA256, 'distribution_url': NODE_URL, 'archive_sha256': NODE_ARCHIVE_SHA256},
            'playwright': {'version': PLAYWRIGHT_VERSION, 'sri': PLAYWRIGHT_SRI, 'url': PLAYWRIGHT_URL},
            'browser': {'version': CHROMIUM_VERSION, 'revision': CHROMIUM_REVISION, 'executable': 'browser/chrome-win64/chrome.exe', 'archive_url': CHROMIUM_URL, 'archive_sha256': CHROMIUM_ARCHIVE_SHA256},
            'files': files,
        }
        (bundle / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + '\n', encoding='utf-8', newline='\n')
        manifest_hash = digest_file(bundle / 'manifest.json')
        bundle.rename(output)
        print(json.dumps({'bundle_root': str(output), 'manifest_sha256': manifest_hash, 'files': len(files), 'bytes': sum(f['bytes'] for f in files)}))
    finally:
        shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-archive', type=Path, required=True)
    parser.add_argument('--playwright-archive', type=Path, required=True)
    parser.add_argument('--chromium-archive', type=Path, required=True)
    parser.add_argument('--chromium-credits', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker-root', type=Path, default=Path(__file__).resolve().parents[2] / 'workers/browser-playwright')
    build(parser.parse_args())


if __name__ == '__main__':
    main()
