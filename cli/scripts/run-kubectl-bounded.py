#!/usr/bin/env python3
"""Run kubectl with bounded process-group lifetime and sanitized diagnostics."""

import importlib.util
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from typing import Optional

sys.dont_write_bytecode = True

_classifier_spec = importlib.util.spec_from_file_location(
    "prufyx_kubectl_stderr_classifier", Path(__file__).with_name("classify-kubectl-stderr.py")
)
if _classifier_spec is None or _classifier_spec.loader is None:
    raise ImportError("classifier unavailable")
_classifier_module = importlib.util.module_from_spec(_classifier_spec)
_classifier_spec.loader.exec_module(_classifier_module)
MAX_STDERR_BYTES = _classifier_module.MAX_STDERR_BYTES
classify = _classifier_module.classify


CHUNK_BYTES = 4096
GRACE_SECONDS = 0.25
DEFAULT_TIMEOUT_SECONDS = 30.0


def emit_classification(fd: int, value: str) -> None:
    allowed = {
        "authentication_exec_plugin_failure",
        "unauthorized",
        "authorization_rbac_forbidden",
        "invalid_kubeconfig_context",
        "tls_certificate",
        "dns",
        "transport_timeout_unreachable",
        "unsupported_not_found_api",
        "generic_api_read_failure",
    }
    if value not in allowed:
        value = "generic_api_read_failure"
    try:
        os.write(fd, (value + "\n").encode("ascii"))
    except Exception:
        pass


def kill_group(process: subprocess.Popen, term: bool) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM if term else signal.SIGKILL)
    except Exception:
        try:
            process.send_signal(signal.SIGTERM if term else signal.SIGKILL)
        except Exception:
            pass


def silence_stdout() -> None:
    """Prevent interpreter shutdown from flushing a downstream-broken pipe."""
    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_fd, 1)
        os.close(null_fd)
    except Exception:
        pass


def main() -> int:
    try:
        raw_args = sys.argv[1:]
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        classification_fd = -1
        separator = raw_args.index("--")
        option_args = raw_args[:separator]
        argv = raw_args[separator + 1 :]
        index = 0
        while index < len(option_args):
            if option_args[index] == "--timeout-seconds" and index + 1 < len(option_args):
                timeout_seconds = float(option_args[index + 1])
                index += 2
            elif option_args[index] == "--classification-fd" and index + 1 < len(option_args):
                classification_fd = int(option_args[index + 1])
                index += 2
            else:
                raise ValueError("invalid supervisor option")
        if not argv or not (0.1 <= timeout_seconds <= 300.0) or classification_fd < 0:
            emit_classification(classification_fd, "generic_api_read_failure")
            return 125
    except Exception:
        return 125

    process: Optional[subprocess.Popen] = None
    selector = selectors.DefaultSelector()
    stderr_buffer = bytearray()
    classification = "generic_api_read_failure"
    timed_out = False
    interrupted = False
    downstream_broken = False
    old_handlers = {}

    def handle_signal(signum: int, _frame: object) -> None:
        nonlocal interrupted, downstream_broken
        if signum == signal.SIGPIPE:
            downstream_broken = True
            silence_stdout()
        else:
            interrupted = True
        if process is not None:
            kill_group(process, True)

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGPIPE):
            old_handlers[signum] = signal.signal(signum, handle_signal)
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout_seconds
        grace_deadline = 0.0
        hard_stop_deadline = 0.0
        leader_exit_deadline = 0.0
        # Continue while the child is alive even after both pipes close.  A
        # silent child can otherwise make the selector empty and bypass the
        # hard deadline before process.wait().
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if process.poll() is not None and leader_exit_deadline == 0.0:
                # A helper can leave a pipe open after the kubectl leader has
                # exited.  Drain briefly, then close our copies so a detached
                # descendant cannot hold a normal read open indefinitely.
                leader_exit_deadline = now + GRACE_SECONDS
            if interrupted and grace_deadline == 0.0:
                kill_group(process, True)
                grace_deadline = now + GRACE_SECONDS
                hard_stop_deadline = now + (2 * GRACE_SECONDS)
            if not timed_out and now >= deadline:
                timed_out = True
                kill_group(process, True)
                grace_deadline = now + GRACE_SECONDS
                hard_stop_deadline = now + (2 * GRACE_SECONDS)
            # The leader may have exited while a descendant inherited either
            # pipe.  Keep targeting the process group after grace until both
            # pipes close; checking poll() here would leave that descendant
            # alive and make the supervisor wait indefinitely.
            if grace_deadline and now >= grace_deadline:
                kill_group(process, False)
                grace_deadline = now + GRACE_SECONDS
            # A child can escape the session (for example by calling setsid)
            # after inheriting our pipes.  Do not let those descriptors turn
            # process.wait() into an unbounded wait: after TERM, one KILL and
            # a bounded grace period, close the pipes and reap the leader.
            if hard_stop_deadline and now >= hard_stop_deadline:
                for key in list(selector.get_map().values()):
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    try:
                        key.fileobj.close()
                    except Exception:
                        pass
                break
            if leader_exit_deadline and now >= leader_exit_deadline:
                for key in list(selector.get_map().values()):
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    try:
                        key.fileobj.close()
                    except Exception:
                        pass
                break
            wait_for = 0.05
            if process.poll() is None:
                wait_for = min(wait_for, max(0.0, deadline - now)) if not timed_out else wait_for
            events = selector.select(wait_for)
            if not events and not selector.get_map():
                # Some selector backends return immediately for an empty
                # descriptor set; retain a bounded polling interval.
                time.sleep(wait_for)
                continue
            if not events and process.poll() is not None:
                # Give pipes one final bounded drain pass before unregistering.
                events = [(key, mask) for key, mask in selector.select(0)]
            for key, _mask in events:
                try:
                    data = os.read(key.fileobj.fileno(), CHUNK_BYTES)
                except (BlockingIOError, OSError):
                    data = b""
                if not data:
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    continue
                if key.data == "stderr":
                    if len(stderr_buffer) < MAX_STDERR_BYTES:
                        stderr_buffer.extend(data[: MAX_STDERR_BYTES - len(stderr_buffer)])
                elif not downstream_broken:
                    try:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                    except (BrokenPipeError, OSError):
                        downstream_broken = True
                        silence_stdout()
                        if process.poll() is None:
                            kill_group(process, True)
                        grace_deadline = time.monotonic() + GRACE_SECONDS
                        try:
                            selector.unregister(key.fileobj)
                        except Exception:
                            pass
        try:
            return_code = process.wait(timeout=GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            kill_group(process, False)
            try:
                return_code = process.wait(timeout=GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                return_code = 125
                classification = "generic_api_read_failure"
        if timed_out:
            classification = "transport_timeout_unreachable"
            return_code = 124
        elif interrupted:
            classification = "generic_api_read_failure"
            return_code = 130
        elif downstream_broken:
            classification = "generic_api_read_failure"
            return_code = 141
        else:
            classification = classify(bytes(stderr_buffer))
            if return_code < 0:
                return_code = 128 + (-return_code)
    except Exception:
        if process is not None and process.poll() is None:
            kill_group(process, False)
        if process is not None:
            try:
                process.wait(timeout=GRACE_SECONDS)
            except Exception:
                kill_group(process, False)
                try:
                    process.wait(timeout=GRACE_SECONDS)
                except Exception:
                    pass
        return_code = 125
        classification = "generic_api_read_failure"
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
        emit_classification(classification_fd, classification)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
