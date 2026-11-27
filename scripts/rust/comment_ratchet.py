# SPDX-License-Identifier: Apache-2.0
"""Audit tracked Rust comments and reject new, fingerprinted comment debt."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


RAW_STRING = re.compile(r'(?:br|cr|r)(?P<hashes>#{0,255})"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\r\n])|[^'\\\r\n])'")
DEFERRED_WORK = re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b")
DIVIDER = re.compile(r"[-=*_~#./\\]{8,}")
THIRD_PARTY_VENDORS = ("app/src-tauri/patches/glib-0.18.5/",)


def scan_rust_comments(source):
    comments = []
    i, line = 0, 1
    while i < len(source):
        start, start_line = i, line
        documentation = False
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
            documentation = source.startswith("//!", start) or (
                source.startswith("///", start) and not source.startswith("////", start)
            )
            comments.append({"line": line, "text": source[start + 2:i],
                             "documentation": documentation})
        elif source.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ValueError(f"unterminated block comment at line {start_line}")
            documentation = source.startswith("/*!", start) or (
                source.startswith("/**", start) and not source.startswith("/***", start)
            )
            comments.append({"line": line, "text": source[start + 2:i - 2],
                             "documentation": documentation})
        elif raw := RAW_STRING.match(source, i):
            terminator = '"' + raw.group("hashes")
            end = source.find(terminator, raw.end())
            if end < 0:
                raise ValueError(f"unterminated raw string at line {start_line}")
            i = end + len(terminator)
        elif source[i] == '"':
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError(f"unterminated string at line {start_line}")
        elif source[i] == "'" and (char := CHAR_LITERAL.match(source, i)):
            i = char.end()
        else:
            i += 1
        line += source.count("\n", start, i)
    return comments


def normalize(text):
    return " ".join(re.sub(r"^\s*\* ?", "", line) for line in text.splitlines()).strip()


def findings(path, source):
    result = []
    for comment in scan_rust_comments(source):
        text = normalize(comment["text"])
        rules = []
        if DEFERRED_WORK.search(text):
            rules.append("deferred-work")
        if DIVIDER.fullmatch(text):
            rules.append("decorative-divider")
        for rule in rules:
            fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
            result.append({"path": path, "line": comment["line"], "rule": rule,
                           "fingerprint": fingerprint, "text": text})
    return result


def debt_key(item):
    return item["path"], item["rule"], item["fingerprint"]


def new_debt(current, allowed):
    remaining = Counter(debt_key(item) for item in allowed)
    added = []
    for item in current:
        key = debt_key(item)
        if remaining[key]:
            remaining[key] -= 1
        else:
            added.append(item)
    return added


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def collect(repo, ref=None):
    if ref:
        names = git(repo, "ls-tree", "-rz", "--name-only", ref).decode("utf-8").split("\0")
    else:
        names = git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode("utf-8").split("\0")
    all_findings, totals, summaries = [], Counter(), []
    for name in sorted(set(names)):
        if not name.endswith(".rs"):
            continue
        if any(name.startswith(prefix) for prefix in THIRD_PARTY_VENDORS):
            continue
        if ref:
            source = git(repo, "show", f"{ref}:{name}").decode("utf-8")
        else:
            path = repo / name
            if not path.is_file():
                continue
            source = path.read_text(encoding="utf-8")
        comments = scan_rust_comments(source)
        file_findings = findings(name, source)
        docs = sum(c["documentation"] for c in comments)
        totals.update(files=1, comments=len(comments), documentation=docs,
                      ordinary=len(comments) - docs, debt=len(file_findings))
        summaries.append({"path": name, "comments": len(comments), "documentation": docs,
                          "debt": len(file_findings)})
        all_findings.extend(file_findings)
    return {"format": 1, "coverage": "Rust source comments", "totals": dict(totals),
            "files": summaries, "findings": all_findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--baseline", type=Path, default=Path("scripts/rust/comment-baseline.json"))
    parser.add_argument("--base-ref", help="Compare directly with this Git tree; ignores edited allowances")
    parser.add_argument("--report", type=Path, help="Write full audit JSON")
    parser.add_argument("--write-baseline", action="store_true", help="Record current fingerprints; CI still compares the base Git tree")
    args = parser.parse_args()
    repo = Path(git(args.repo, "rev-parse", "--show-toplevel").decode().strip())
    baseline_path = args.baseline if args.baseline.is_absolute() else repo / args.baseline
    report = collect(repo)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.write_baseline:
        baseline_path.write_text(json.dumps({"format": 1, "findings": report["findings"]}, indent=2) + "\n", encoding="utf-8")
        print(f"Recorded {len(report['findings'])} existing findings in {baseline_path.relative_to(repo)}")
        return 0
    if args.base_ref:
        allowed = collect(repo, args.base_ref)["findings"]
    else:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        if baseline.get("format") != 1:
            raise ValueError("unsupported comment baseline format")
        allowed = baseline["findings"]
    added = new_debt(report["findings"], allowed)
    for item in added:
        print(f"{item['path']}:{item['line']}: {item['rule']}: {item['text']}", file=sys.stderr)
    print("Comment audit: " + ", ".join(f"{key}={value}" for key, value in report["totals"].items()))
    if added:
        print(f"Comment ratchet refused {len(added)} new finding(s).", file=sys.stderr)
        return 1
    print("Comment ratchet passed; removed debt cannot fund a different comment or file.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Comment audit failed: {error}", file=sys.stderr)
        raise SystemExit(2)
