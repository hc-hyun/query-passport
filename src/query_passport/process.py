"""Bounded private subprocess transport for the Docker and local issuer boundaries."""

import os
import select
import signal
import subprocess
import time

from .contract import ContractError

MAX_PRIVATE_INPUT = 1048576


def run_process(
    argv: list[str],
    *,
    env: dict[str, str],
    stdin: bytes | None = None,
    timeout: float = 10,
    limit: int = 16384,
) -> tuple[int, bytes]:
    """Drain output while feeding input; neither pipe may defeat the deadline.

    Callers construct fixed argv. Private input travels over stdin, never argv or
    environment variables. This does not cancel work already accepted by a daemon;
    mutation callers must record an uncertain outcome and reconcile it on resume.
    """
    payload = memoryview(stdin or b"")
    if len(payload) > MAX_PRIVATE_INPUT or not 1 <= limit <= MAX_PRIVATE_INPUT or timeout <= 0:
        raise ContractError("EXECUTOR_FAILED")
    deadline = time.monotonic() + timeout
    try:
        with subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            bufsize=0,
            start_new_session=True,
        ) as process:
            assert process.stdin is not None and process.stdout is not None
            try:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                if not payload:
                    process.stdin.close()
                output = bytearray()
                reading = True
                while reading or payload:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ContractError("TIMEOUT")
                    readable, writable, _ = select.select(
                        [process.stdout] if reading else [],
                        [process.stdin] if payload else [],
                        [],
                        remaining,
                    )
                    if not readable and not writable:
                        raise ContractError("TIMEOUT")
                    if readable:
                        chunk = os.read(
                            process.stdout.fileno(), min(65536, limit + 1 - len(output))
                        )
                        if not chunk:
                            reading = False
                        output.extend(chunk)
                        if len(output) > limit:
                            raise ContractError("EXECUTOR_FAILED")
                    if writable:
                        count = os.write(process.stdin.fileno(), payload[:65536])
                        if count <= 0:
                            raise ContractError("EXECUTOR_FAILED")
                        payload = payload[count:]
                        if not payload:
                            process.stdin.close()
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                return code, bytes(output)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    except subprocess.TimeoutExpired as error:
        raise ContractError("TIMEOUT") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise ContractError("EXECUTOR_FAILED") from error
