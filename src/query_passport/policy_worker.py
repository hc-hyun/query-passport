"""Two explicit negative probes of the new Passport identity's loaded policy.

The positive M2 verifier must succeed immediately before and after these probes.
Neither probe executes SQL or treats an unavailable server as a policy refusal.
The host supplies this module plus verify_worker in isolated module namespaces.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import ipaddress
import json
import os
import re
import signal
import sys
from typing import Any

from . import verify_worker as base

CHECK_NAMES = ("client_certificate_required", "plaintext_rejected")
OVERALL_TIMEOUT_SECONDS = 8


def new_checks() -> dict[str, base.CheckState]:
    return dict.fromkeys(CHECK_NAMES, "not_checked")


def _refusal_message(message: str, request: base.Request, *, tls: bool) -> bool:
    if tls and message == "connection requires a valid client certificate":
        return True
    transport = "SSL encryption" if tls else "no encryption"
    match = re.fullmatch(
        r"(?:pg_hba\.conf rejects connection|no pg_hba\.conf entry) for host "
        r'"([^"\r\n]{1,45})", user "'
        + re.escape(request.username)
        + r'", database "'
        + re.escape(request.database)
        + '", '
        + transport,
        message,
    )
    if match is None or "%" in match[1]:
        return False
    try:
        ipaddress.ip_address(match[1])
    except ValueError:
        return False
    return True


def expected_refusal(error: BaseException, request: base.Request, *, tls: bool) -> bool:
    """Recognize server authentication refusals, never a client's password veto.

    libpq frequently omits SQLSTATE on connection establishment failures. In that
    case accept only one complete, anchored English FATAL diagnostic from the pinned
    endpoint. Other locales or diagnostic formats fail closed. All diagnostics stay
    inside this function and are discarded after producing a boolean.
    """
    if not type(error).__module__.startswith("psycopg"):
        return False
    try:
        state = getattr(error, "sqlstate", None)
        if state not in (None, "28000"):
            return False
        if state == "28000":
            diag = getattr(error, "diag", None)
            primary = getattr(diag, "message_primary", None)
            severity = getattr(diag, "severity_nonlocalized", None)
            if type(primary) is str and severity == "FATAL":
                return _refusal_message(primary, request, tls=tls)
        text = str(error)
        if len(text) > 4096:
            return False
        host = re.escape(request.host)
        address = re.escape(request.hostaddr)
        wrapper = (
            r'(?:connection failed: )?connection to server at "(?:'
            + address
            + "|"
            + host
            + r')"(?: \('
            + address
            + r"\))?, port "
            + str(request.port)
            + r" failed: FATAL:  ([^\r\n]+)\n?"
        )
        match = re.fullmatch(wrapper, text)
        return match is not None and _refusal_message(match[1], request, tls=tls)
    except Exception:  # noqa: BLE001 - discard malformed driver diagnostics
        return False


def connection_parameters(
    request: base.Request, paths: dict[str, str], *, tls: bool
) -> dict[str, str | int]:
    parameters = base.connection_parameters(request, paths)
    parameters.update(
        sslmode="verify-full" if tls else "disable",
        sslcertmode="disable",
        sslcert="/run/query-passport/no-client-certificate",
        sslkey="/run/query-passport/no-client-key",
        application_name="query-passport-policy",
    )
    return parameters


async def verify(
    request: base.Request, paths: dict[str, str], checks: dict[str, base.CheckState]
) -> None:
    driver = importlib.import_module("psycopg")
    if driver.pq.version() < 170000:
        raise base.WorkerFailure("VERIFICATION_FAILED")
    async with asyncio.timeout(OVERALL_TIMEOUT_SECONDS):
        for name, tls in ((CHECK_NAMES[0], True), (CHECK_NAMES[1], False)):
            checks[name] = "failed"
            try:
                connection = await driver.AsyncConnection.connect(
                    **connection_parameters(request, paths, tls=tls),
                    prepare_threshold=None,
                    autocommit=True,
                )
            except Exception as error:
                if not expected_refusal(error, request, tls=tls):
                    raise
            else:
                # Even a successful connection that cannot close is a failure.
                # Never execute SQL on an unexpectedly admitted negative probe.
                with contextlib.suppress(Exception):
                    await connection.close()
                raise base.WorkerFailure("VERIFICATION_FAILED")
            checks[name] = "passed"


def failure_result(error: BaseException, checks: dict[str, base.CheckState]) -> dict[str, Any]:
    return {
        "status": "failed",
        "checks": {
            name: checks[name]
            if checks.get(name) in ("passed", "failed", "not_checked")
            else "not_checked"
            for name in CHECK_NAMES
        },
        "error": base.classify_error(error),
    }


def main() -> int:
    checks = new_checks()
    try:
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), 2)
        base.sanitize_environment()
        signal.signal(signal.SIGALRM, base._alarm)
        signal.alarm(12)
        request = base.parse_request(sys.stdin.buffer.read(base.MAX_INPUT_BYTES + 1))
        base.validate_runtime(request)
        with base.credential_files(request, base.new_checks()) as paths:
            asyncio.run(verify(request, paths, checks))
        result: dict[str, Any] = {"status": "succeeded", "checks": checks, "error": None}
    except BaseException as error:  # noqa: BLE001 - standalone redaction boundary
        result = failure_result(error, checks)
    finally:
        signal.alarm(0)
    try:
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        with contextlib.suppress(OSError, ValueError):
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), 1)
        return 1
    return 0 if result["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
