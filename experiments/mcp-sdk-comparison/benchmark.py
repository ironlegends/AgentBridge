"""Compare synthetic stdio protocol fixtures; never connect to a live server."""
import argparse
import ctypes
import json
import math
import os
import pathlib
import queue
import statistics
import subprocess
import threading
import time
from ctypes import wintypes

VERSION = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "benchmark", "version": "1"},
}


class ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
        (name, ctypes.c_size_t)
        for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
        )
    ]


def process_memory(proc):
    if os.name != "nt":
        return None, None
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    fn = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
    fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
    fn.restype = wintypes.BOOL
    if not fn(wintypes.HANDLE(int(proc._handle)), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


def percentile(values, q):
    return sorted(values)[min(len(values) - 1, math.ceil(len(values) * q) - 1)]


def run_fixture(executable, calls, warmup):
    begin = time.perf_counter_ns()
    proc = subprocess.Popen(
        [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    replies = queue.Queue()
    stderr = bytearray()

    def reader():
        try:
            for line in iter(proc.stdout.readline, b""):
                replies.put(line)
        finally:
            replies.put(None)

    def drain_errors():
        while True:
            data = proc.stderr.read(4096)
            if not data:
                break
            stderr.extend(data[:max(0, 16384 - len(stderr))])

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=drain_errors, daemon=True).start()
    sequence = 0

    def request(method, params):
        nonlocal sequence
        sequence += 1
        params = dict(params, _meta=META)
        frame = json.dumps({
            "jsonrpc": "2.0", "id": sequence, "method": method, "params": params,
        }, separators=(",", ":")).encode() + b"\n"
        start = time.perf_counter_ns()
        proc.stdin.write(frame)
        proc.stdin.flush()
        line = replies.get(timeout=8)
        elapsed = (time.perf_counter_ns() - start) / 1e6
        if line is None:
            raise RuntimeError("Fixture exited before responding: " + stderr.decode(errors="replace"))
        reply = json.loads(line)
        if reply.get("id") != sequence or "error" in reply:
            raise RuntimeError(f"Unconfirmed reply: {reply}")
        result = reply["result"]
        if result.get("resultType") != "complete":
            raise RuntimeError(f"Unexpected modern result: {result}")
        return result, elapsed

    try:
        discovery, _ = request("server/discover", {})
        startup_ms = (time.perf_counter_ns() - begin) / 1e6
        if VERSION not in discovery["supportedVersions"]:
            raise RuntimeError("Fixture did not advertise the target revision")
        catalog, _ = request("tools/list", {})
        if [t["name"] for t in catalog["tools"]] != ["echo"]:
            raise RuntimeError("Unequal fixture tool catalogs")
        for _ in range(warmup):
            result, _ = request("tools/call", {"name": "echo", "arguments": {}})
            assert result["content"][0]["text"] == "fixture"
        time.sleep(0.05)
        idle, _ = process_memory(proc)
        durations = []
        for _ in range(calls):
            result, elapsed = request("tools/call", {"name": "echo", "arguments": {}})
            if result["content"][0]["text"] != "fixture":
                raise RuntimeError("Unequal tool response")
            durations.append(elapsed)
        working, peak = process_memory(proc)
        proc.stdin.close()
        proc.wait(timeout=8)
        if proc.returncode != 0:
            raise RuntimeError(f"Fixture exit code {proc.returncode}: {stderr.decode(errors='replace')}")
        return {
            "startup_ms": startup_ms, "median_rtt_ms": statistics.median(durations),
            "p95_rtt_ms": percentile(durations, 0.95),
            "idle_working_set_bytes": idle, "final_working_set_bytes": working,
            "peak_working_set_bytes": peak, "confirmed_calls": calls + warmup,
        }
    finally:
        if proc.poll() is None:
            try:
                proc.stdin.close()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()
                proc.wait(timeout=3)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                pipe.close()
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--custom", type=pathlib.Path, required=True)
    parser.add_argument("--sdk", type=pathlib.Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--calls", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10 or not 1 <= args.calls <= 3000 or not 0 <= args.warmup <= 100:
        parser.error("Use bounded round, call, and warmup counts")
    executables = {"custom": args.custom.resolve(strict=True), "rmcp": args.sdk.resolve(strict=True)}
    output = {
        "protocol_version": VERSION, "transport": "stdio", "rounds": args.rounds,
        "calls_per_round": args.calls, "warmup_calls": args.warmup, "results": {},
    }
    for key, executable in executables.items():
        output["results"][key] = {"binary_bytes": executable.stat().st_size, "runs": []}
    for round_index in range(args.rounds):
        order = list(executables) if round_index % 2 == 0 else list(reversed(executables))
        for key in order:
            output["results"][key]["runs"].append(
                run_fixture(executables[key], args.calls, args.warmup)
            )
    for value in output["results"].values():
        runs = value["runs"]
        value["median_of_runs"] = {
            key: statistics.median(run[key] for run in runs)
            for key in runs[0] if runs[0][key] is not None
        }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
