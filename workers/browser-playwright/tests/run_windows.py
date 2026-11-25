"""Run isolated browser/package qualification with durable, bounded console logs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

workspace = Path(__file__).resolve().parents[3]
phase, kind = sys.argv[1:3]
if not phase.replace('-', '').isalnum():
    raise SystemExit('invalid evidence phase')
evidence = workspace / '.superpowers/sdd/2026-11-23-complete-tool-surface'
environment = os.environ.copy()
environment['PATH'] = r'C:\Windows\System32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0;C:\Program Files\Git\cmd'
for key in ['NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'NODE_REDIRECT_WARNINGS', 'DEBUG', 'PWDEBUG']:
    environment.pop(key, None)
if kind == 'js':
    bundle = Path(sys.argv[3]).resolve()
    node = bundle / 'node.exe'
    if hashlib.sha256(node.read_bytes()).hexdigest() != '63c259c81e5d472b5f11c8d506070130cb04a1ecf84b80377a34ed6ec9048088':
        raise SystemExit('unqualified Node executable')
    environment['AGENT_BRIDGE_TEST_CHROME'] = str(bundle / 'browser/chrome-win64/chrome.exe')
    cwd = workspace / 'workers/browser-playwright'
    command = [str(node), '--test', '--test-concurrency=1', *map(str, sorted((cwd / 'tests').glob('*.test.mjs')))]
elif kind == 'archive':
    cwd = workspace
    command = [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/rust', '-p', 'test_package_browser_worker.py', '-v']
else:
    raise SystemExit('unknown qualification kind')
log = evidence / f'task-2-{phase}.log'
receipt = evidence / f'task-2-{phase}.json'
record = {'command': command, 'cwd': str(cwd), 'log': str(log), 'utc_started': datetime.now(timezone.utc).isoformat()}
print(json.dumps(record), flush=True)
with log.open('x', encoding='utf-8') as output:
    result = subprocess.run(command, cwd=cwd, env=environment, stdout=output, stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW)
record.update(exit_code=result.returncode, utc_finished=datetime.now(timezone.utc).isoformat())
receipt.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record), flush=True)
raise SystemExit(result.returncode)
