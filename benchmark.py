#!/usr/bin/env python3
"""Measure SSH setup and small request/reply latency through an existing config.

This does not modify either machine's polling settings. First make a normal SSH
connection and verify its host key. A key with a passphrase must be available to
ssh-agent because this benchmark deliberately uses BatchMode=yes.
"""

import argparse
import json
import math
import os
from pathlib import Path
import selectors
import shlex
import statistics
import subprocess
import sys
import time
import uuid


def positive_number(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


class LineReader:
    def __init__(self, stream):
        self.stream = stream
        self.pending = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(stream, selectors.EVENT_READ)

    def line(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError("SSH response timed out; check SSH/bridge logs")
            data = os.read(self.stream.fileno(), 65536)
            if not data:
                raise RuntimeError("SSH closed before returning the expected line")
            self.pending += data
            if len(self.pending) > 1024 * 1024:
                raise RuntimeError("unexpected large output from remote shell")
        result, self.pending = self.pending.split(b"\n", 1)
        return result.rstrip(b"\r")

    def close(self):
        self.selector.close()


def percentile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    low = math.floor(index)
    high = math.ceil(index)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        help="SSH config path; omit to use the normal SSH configuration")
    parser.add_argument("--host", required=True, help="configured Host alias")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--timeout", type=positive_number, default=120.0)
    parser.add_argument("--label", default="current configuration",
                        help="description only; does NOT change polling")
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000 or not 0 <= args.warmup <= 100:
        parser.error("samples must be 1..10000, warmup 0..100")
    config = args.config.expanduser().resolve() if args.config is not None else None
    if config is not None and not config.is_file():
        parser.error("SSH config file does not exist: %s; omit --config to use the default SSH configuration" % config)
    if not args.host or args.host.startswith("-") or any(c.isspace() for c in args.host):
        parser.error("use a simple configured host alias")
    nonce = uuid.uuid4().hex
    ready = ("READY-" + nonce).encode()
    program = (
        "import sys\n"
        "print(" + repr(ready.decode()) + ", flush=True)\n"
        "for line in sys.stdin:\n"
        "    sys.stdout.write(line)\n"
        "    sys.stdout.flush()\n"
    )
    command = ["ssh", "-T"]
    if config is not None:
        command += ["-F", str(config)]
    command += ["-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "ControlMaster=no",
               "-o", "ControlPath=none", args.host,
               "python3 -u -c " + shlex.quote(program)]
    process = None
    reader = None
    try:
        started = time.perf_counter()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=None, bufsize=0)
        reader = LineReader(process.stdout)
        if reader.line(args.timeout) != ready:
            raise RuntimeError("unexpected shell startup output before benchmark greeting")
        setup_ms = (time.perf_counter() - started) * 1000
        durations = []
        for i in range(args.warmup + args.samples):
            payload = (nonce + "-" + str(i)).encode()
            begun = time.perf_counter()
            process.stdin.write(payload + b"\n")
            process.stdin.flush()
            echoed = reader.line(args.timeout)
            elapsed = (time.perf_counter() - begun) * 1000
            if echoed != payload:
                raise RuntimeError("remote echo differs; refusing to report invalid timing")
            if i >= args.warmup:
                durations.append(elapsed)
        process.stdin.close()
        status = process.wait(timeout=args.timeout)
        if status != 0:
            raise RuntimeError("SSH exited with code " + str(status))
        result = {
            "label": args.label,
            "host": args.host,
            "samples": args.samples,
            "setup_ms": round(setup_ms, 3),
            "roundtrip_ms": {
                "min": round(min(durations), 3),
                "median": round(statistics.median(durations), 3),
                "p95_estimate": round(percentile(durations, .95), 3),
                "max": round(max(durations), 3),
            },
            "note": "Measures current settings only; no CPU/storage-load or safety guarantee.",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        print("benchmark: " + str(exc), file=sys.stderr)
        return 1
    finally:
        if reader is not None:
            reader.close()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
