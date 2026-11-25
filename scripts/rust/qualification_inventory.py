"""Verify exact native test receipts; never turn missing or ignored tests into passes.

This gate checks a reviewed per-platform inventory against local libtest logs.
The caller must obtain each inventory from its exact built test executable and
review any subprocess-fixture mapping. It does not attest build provenance or
infer that the supplied suites cover the entire product.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

SHA40 = re.compile(r"[0-9a-f]{40}")
SHA64 = re.compile(r"[0-9a-f]{64}")
LOG_LIMIT = 8 * 1024 * 1024
SUCCESS = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;(?: .*)?")


class QualificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def fields(value, names, label):
    require(isinstance(value, dict) and set(value) == set(names), f"Invalid {label} fields")


def unique_names(values, label):
    require(isinstance(values, list) and all(isinstance(v, str) and v
            and len(v) <= 1024 and not any(c in v for c in "\r\n\0")
            for v in values), f"Invalid {label}")
    require(len(values) == len(set(values)), f"Duplicate {label}")
    return set(values)


def digest_value(value, pattern, label):
    require(isinstance(value, str) and pattern.fullmatch(value), f"Invalid {label}")


def read_log(root, name, expected):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", name)
            and name not in (".", "..") and not name.endswith("."), "Unsafe log name")
    digest_value(expected, SHA64, "log digest")
    path = root / name
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400,
            "Log must be an ordinary file")
    require(metadata.st_size <= LOG_LIMIT, "Log exceeds size limit")
    with path.open("rb") as handle:
        raw = handle.read(LOG_LIMIT + 1)
    require(len(raw) <= LOG_LIMIT and hashlib.sha256(raw).hexdigest() == expected,
            "Log digest or size mismatch")
    return raw.decode("utf-8")


def verify(plan, receipt, proof_root, expected_candidate):
    digest_value(expected_candidate, SHA40, "expected candidate")
    fields(plan, ("schema", "candidate", "suites"), "plan")
    fields(receipt, ("schema", "candidate", "results"), "receipt")
    require(type(plan["schema"]) is int and plan["schema"] == 1
            and type(receipt["schema"]) is int and receipt["schema"] == 1, "Unsupported schema")
    require(plan["candidate"] == expected_candidate == receipt["candidate"], "Candidate mismatch")
    require(isinstance(plan["suites"], list) and plan["suites"], "No suites")
    require(isinstance(receipt["results"], list), "Invalid results")
    required = {}
    suite_ids = set()
    fixtures_count = 0
    for suite in plan["suites"]:
        fields(suite, ("id", "platform", "binary_sha256", "discovered", "required", "fixtures"), "suite")
        sid = suite["id"]
        require(isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", sid)
                and sid not in suite_ids, "Invalid or duplicate suite ID")
        suite_ids.add(sid)
        require(suite["platform"] in ("windows", "linux", "macos"), "Invalid platform")
        digest_value(suite["binary_sha256"], SHA64, "binary digest")
        discovered = unique_names(suite["discovered"], "discovered test")
        runnable = unique_names(suite["required"], "required test")
        fixtures = suite["fixtures"]
        require(isinstance(fixtures, dict), "Invalid fixtures")
        children = unique_names(list(fixtures), "fixture")
        require(runnable and not (runnable & children)
                and discovered == runnable | children, "Incomplete or ambiguous inventory")
        for child, parents in fixtures.items():
            linked = unique_names(parents, f"parents for {child}")
            require(linked and linked <= runnable, f"Fixture has no declared required parent: {child}")
        fixtures_count += len(children)
        for name in runnable:
            required[(sid, name)] = suite["binary_sha256"]

    seen = set()
    log_names = set()
    root = Path(proof_root)
    for row in receipt["results"]:
        fields(row, ("suite", "test", "binary_sha256", "exit_code", "log", "log_sha256"), "result")
        require(isinstance(row["suite"], str) and isinstance(row["test"], str), "Invalid result identity")
        key = (row["suite"], row["test"])
        require(key in required and key not in seen, "Unexpected or duplicate test result")
        require(row["binary_sha256"] == required[key], "Binary mismatch")
        require(type(row["exit_code"]) is int and row["exit_code"] == 0, "Nonzero test exit")
        require(isinstance(row["log"], str) and row["log"] not in log_names, "Reused log")
        try:
            content = read_log(root, row["log"], row["log_sha256"])
        except (OSError, UnicodeError) as error:
            raise QualificationError(f"Cannot read proof: {key}") from error
        lines = content.splitlines()
        summaries = [line for line in lines if line.startswith("test result:")]
        names = [line for line in lines if line.startswith("test " + row["test"] + " ...")]
        require(lines.count("running 1 test") == 1 and len(names) == 1
                and len(summaries) == 1 and SUCCESS.fullmatch(summaries[0])
                and not names[0].endswith("ignored"), f"Not an exact, nonignored passing test: {key}")
        seen.add(key)
        log_names.add(row["log"])
    missing = sorted(set(required) - seen)
    require(not missing, f"Missing required tests: {missing}")
    return {"candidate": expected_candidate, "suites": len(suite_ids),
            "required": len(required), "passed": len(seen), "fixtures": fixtures_count}


def load_json(path):
    def no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--proof-root", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    try:
        result = verify(load_json(args.plan), load_json(args.receipt), args.proof_root, args.candidate)
    except (QualificationError, OSError, ValueError) as error:
        print(f"Qualification refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
