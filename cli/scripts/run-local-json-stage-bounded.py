#!/usr/bin/env python3
"""Run the strict JSON and jq projection stages under one wall deadline.

The input remains on stdin and the compact projection is streamed to stdout;
neither stage receives a filename for API data.  Exit codes are deliberately
small and fixed: 0 success, 1 strict JSON rejection, 2 jq/projection
rejection, and 125 local-stage timeout or supervisor failure.
"""

import argparse
import os
import selectors
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional

sys.dont_write_bytecode = True

GRACE_SECONDS = 0.25
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def kill_process(process: Optional[subprocess.Popen], term: bool) -> None:
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM if term else signal.SIGKILL)
    except Exception:
        try:
            process.send_signal(signal.SIGTERM if term else signal.SIGKILL)
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--strict-json")
    parser.add_argument("--jq-filter", required=True)
    parser.add_argument("--page-limit", type=int)
    parser.add_argument("--jq-only", action="store_true")
    parser.add_argument("--slurp", action="store_true")
    args = parser.parse_args()
    if not (0.1 <= args.timeout_seconds <= 300.0):
        raise ValueError("invalid timeout")
    if args.jq_only == (args.strict_json is not None):
        raise ValueError("select exactly one local stage mode")
    if args.page_limit is not None and not (1 <= args.page_limit <= 10000):
        raise ValueError("invalid page limit")
    return args


def main() -> int:
    try:
        args = parse_args()
    except Exception:
        return 125

    strict_process: Optional[subprocess.Popen] = None
    jq_process: Optional[subprocess.Popen] = None
    # The collector redirects this helper to a private regular file. epoll(7)
    # rejects regular-file descriptors with EPERM, so use poll(2), which also
    # supports the pipe descriptors used for backpressure and child output.
    selector = selectors.PollSelector()
    old_handlers: Dict[int, object] = {}
    interrupted = False
    timed_out = False
    output_overflow = False
    output_pending = bytearray()
    output_bytes = 0
    jq_eof = False

    def handle_signal(signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        kill_process(strict_process, True)
        kill_process(jq_process, True)

    try:
        jq_argv: List[str] = ["jq", "-c"]
        if args.slurp:
            jq_argv.append("-s")
        if args.page_limit is not None:
            jq_argv.extend(["--argjson", "pageLimit", str(args.page_limit)])
        jq_argv.extend(["-f", args.jq_filter])
        if args.jq_only:
            jq_process = subprocess.Popen(
                jq_argv,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        else:
            strict_process = subprocess.Popen(
                [sys.executable, args.strict_json],
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            assert strict_process.stdout is not None
            jq_process = subprocess.Popen(
                jq_argv,
                stdin=strict_process.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            strict_process.stdout.close()

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, handle_signal)
        assert jq_process.stdout is not None
        os.set_blocking(jq_process.stdout.fileno(), False)
        os.set_blocking(sys.stdout.fileno(), False)
        selector.register(jq_process.stdout, selectors.EVENT_READ, "jq")
        deadline = time.monotonic() + args.timeout_seconds
        while not (jq_eof and not output_pending and jq_process.poll() is not None and
                   (strict_process is None or strict_process.poll() is not None)):
            now = time.monotonic()
            if interrupted or now >= deadline:
                timed_out = timed_out or not interrupted
                kill_process(strict_process, True)
                kill_process(jq_process, True)
                grace_deadline = now + GRACE_SECONDS
                while time.monotonic() < grace_deadline:
                    if (jq_process.poll() is not None and
                            (strict_process is None or strict_process.poll() is not None)):
                        break
                    time.sleep(0.02)
                kill_process(strict_process, False)
                kill_process(jq_process, False)
                break
            events = selector.select(min(0.05, max(0.0, deadline - now)))
            if not events and not selector.get_map():
                time.sleep(0.02)
            for key, mask in events:
                if key.data == "jq" and mask & selectors.EVENT_READ:
                    try:
                        data = os.read(key.fileobj.fileno(), 8192)
                    except (BlockingIOError, OSError):
                        data = b""
                    if not data:
                        jq_eof = True
                        selector.unregister(key.fileobj)
                    else:
                        output_bytes += len(data)
                        if output_bytes > MAX_OUTPUT_BYTES:
                            output_overflow = True
                            kill_process(strict_process, False)
                            kill_process(jq_process, False)
                            break
                        output_pending.extend(data)
                        if not any(item.data == "stdout" for item in selector.get_map().values()):
                            selector.register(sys.stdout, selectors.EVENT_WRITE, "stdout")
                elif key.data == "stdout" and mask & selectors.EVENT_WRITE and output_pending:
                    try:
                        written = os.write(key.fileobj.fileno(), output_pending)
                        del output_pending[:written]
                        if not output_pending:
                            selector.unregister(key.fileobj)
                    except (BlockingIOError, OSError):
                        pass
            if output_overflow:
                break
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
            except Exception:
                pass
        if output_pending and not timed_out and not interrupted:
            return_code = 125
        else:
            return_code = 0
        if strict_process is not None:
            try:
                strict_code = strict_process.wait(timeout=GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                kill_process(strict_process, False)
                strict_code = strict_process.wait(timeout=GRACE_SECONDS)
        else:
            strict_code = 0
        try:
            jq_code = jq_process.wait(timeout=GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            kill_process(jq_process, False)
            jq_code = jq_process.wait(timeout=GRACE_SECONDS)
        if timed_out or interrupted:
            return 125
        if output_overflow:
            return 2
        if jq_code != 0:
            return 2
        if strict_process is not None and strict_code != 0:
            return 1
        return return_code
    except Exception:
        kill_process(strict_process, False)
        kill_process(jq_process, False)
        return 125
    finally:
        try:
            selector.close()
        except Exception:
            pass
        for signum, handler in old_handlers.items():
            try:
                signal.signal(signum, handler)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
