"""Credential-aware, standalone worker executed inside the pinned runtime image.

The host executor sends this source via ``python -I -c``. Do not add package imports:
only the runtime's psycopg and the standard library are available. Credential bytes
stay inside libpq; this module inspects file metadata and emits fixed verdicts only.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import ipaddress
import json
import logging
import os
import re
import signal
import stat
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

CHECK_NAMES = (
    "runtime_identity",
    "credential_permissions",
    "credential_mount_read_only",
    "tls",
    "client_identity",
    "target",
    "read_only_transaction",
    "statement_timeout",
    "timeout_recovery",
    "cancellation",
    "cancellation_recovery",
    "reconnect",
)
ERROR_CODES = frozenset(
    {
        "TLS_VERIFICATION_FAILED",
        "CLIENT_AUTHENTICATION_FAILED",
        "TIMEOUT",
        "PERMISSION_DENIED",
        "TARGET_MISMATCH",
        "CONNECTION_FAILED",
        "VERIFICATION_FAILED",
        "CREDENTIAL_ACCESS_DENIED",
        "INTERNAL_ERROR",
    }
)
MAX_INPUT_BYTES = 8192
OVERALL_TIMEOUT_SECONDS = 12
CREDENTIAL_ROOT = "/run/secrets/query-man/databases"
CheckState = Literal["passed", "failed", "not_checked"]


class Result(TypedDict):
    status: Literal["succeeded", "failed"]
    checks: dict[str, CheckState]
    error: str | None


class WorkerFailure(Exception):
    """Only fixed, allowlisted verdicts cross the executor boundary."""

    def __init__(self, code: str, check: str | None = None) -> None:
        self.code = code if code in ERROR_CODES else "INTERNAL_ERROR"
        self.check = check if check in CHECK_NAMES else None
        super().__init__(self.code)


@dataclass(frozen=True)
class Request:
    host: str
    hostaddr: str
    port: int
    database: str
    username: str
    expected_dn: str
    profile_id: str
    runtime_uid: int
    runtime_gid: int


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerFailure("TARGET_MISMATCH")
        result[key] = value
    return result


def parse_request(raw: bytes) -> Request:
    """Validate the narrow executor protocol without reflecting invalid input."""
    if len(raw) > MAX_INPUT_BYTES:
        raise WorkerFailure("TARGET_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, ValueError, RecursionError):
        raise WorkerFailure("TARGET_MISMATCH") from None
    fields = set(Request.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields:
        raise WorkerFailure("TARGET_MISMATCH")
    for name in ("host", "hostaddr", "database", "username", "expected_dn", "profile_id"):
        text = value[name]
        if not isinstance(text, str) or not text or not text.isascii():
            raise WorkerFailure("TARGET_MISMATCH")
        if len(text) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in text):
            raise WorkerFailure("TARGET_MISMATCH")
    if not re.fullmatch(r"CN=[a-z][a-z0-9-]{0,124}", value["expected_dn"]):
        raise WorkerFailure("TARGET_MISMATCH")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", value["profile_id"]):
        raise WorkerFailure("TARGET_MISMATCH")
    for name in ("database", "username"):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$-]{0,62}", value[name]):
            raise WorkerFailure("TARGET_MISMATCH")
    host = value["host"]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.removesuffix(".").split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise WorkerFailure("TARGET_MISMATCH") from None
    try:
        address = ipaddress.ip_address(value["hostaddr"])
    except ValueError:
        raise WorkerFailure("TARGET_MISMATCH") from None
    if "%" in value["hostaddr"] or address.is_unspecified or address.is_multicast:
        raise WorkerFailure("TARGET_MISMATCH")
    for name, minimum, maximum in (
        ("port", 1, 65535),
        ("runtime_uid", 1, 2**31 - 1),
        ("runtime_gid", 0, 2**31 - 1),
    ):
        if type(value[name]) is not int or not minimum <= value[name] <= maximum:
            raise WorkerFailure("TARGET_MISMATCH")
    return Request(**value)


def new_checks() -> dict[str, CheckState]:
    return dict.fromkeys(CHECK_NAMES, "not_checked")


def failure_result(error: BaseException, checks: dict[str, CheckState]) -> Result:
    code = classify_error(error)
    result_checks: dict[str, CheckState] = {
        name: checks[name]
        if checks.get(name) in ("passed", "failed", "not_checked")
        else "not_checked"
        for name in CHECK_NAMES
    }
    if isinstance(error, WorkerFailure) and error.check is not None:
        result_checks[error.check] = "failed"
    return {"status": "failed", "checks": result_checks, "error": code}


def classify_error(error: BaseException) -> str:
    """Read driver diagnostics internally; never return provider text or attributes."""
    if isinstance(error, WorkerFailure):
        return error.code
    if isinstance(error, TimeoutError):
        return "TIMEOUT"
    if isinstance(error, PermissionError):
        return "CREDENTIAL_ACCESS_DENIED"
    try:
        state = getattr(error, "sqlstate", None)
    except Exception:  # noqa: BLE001 - provider diagnostics are untrusted
        return "INTERNAL_ERROR"
    if state == "57014":
        return "TIMEOUT"
    if state == "42501":
        return "PERMISSION_DENIED"
    if state == "3D000":
        return "TARGET_MISMATCH"
    if isinstance(state, str) and state.startswith("28"):
        return "CLIENT_AUTHENTICATION_FAILED"
    # libpq's connection/TLS failures often have no SQLSTATE. Match only known
    # diagnostics and discard the complete diagnostic, including paths and DNs.
    if type(error).__module__.startswith("psycopg"):
        try:
            message = str(error).lower()[:16384]
        except Exception:  # noqa: BLE001 - provider diagnostics are untrusted
            return "INTERNAL_ERROR"
        if any(
            part in message
            for part in (
                "certificate verify failed",
                "does not match host name",
                "root certificate file",
                "server does not support ssl",
                "ssl is not enabled",
            )
        ):
            return "TLS_VERIFICATION_FAILED"
        if any(
            part in message
            for part in (
                "private key",
                "client certificate",
                "certificate authentication failed",
                "certificate required",
                "unknown ca",
                "bad certificate",
                "certificate expired",
                "unsupported certificate",
                "authentication method requirement",
                "server did not request an ssl certificate",
                "without a valid ssl certificate",
                "no password supplied",
                "no pg_hba.conf entry",
                "pg_hba.conf rejects connection",
            )
        ):
            return "CLIENT_AUTHENTICATION_FAILED"
        if "timeout" in message or "timed out" in message:
            return "TIMEOUT"
        return "CONNECTION_FAILED"
    return "INTERNAL_ERROR"


def validate_runtime(request: Request) -> None:
    if (
        os.getuid() != request.runtime_uid
        or os.geteuid() != request.runtime_uid
        or os.getgid() != request.runtime_gid
        or os.getegid() != request.runtime_gid
        or any(group != request.runtime_gid for group in os.getgroups())
    ):
        raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "runtime_identity")


def validate_file_metadata(info: os.stat_result, name: str, request: Request) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "credential_permissions")
    if name == "client.key":
        valid = (info.st_uid == request.runtime_uid and mode == 0o600) or (
            info.st_uid == 0 and info.st_gid == request.runtime_gid and mode == 0o640
        )
    else:
        valid = info.st_uid in (0, request.runtime_uid) and not mode & 0o7022
    if not valid:
        raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "credential_permissions")


def _directory_metadata(info: os.stat_result, request: Request) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in (0, request.runtime_uid)
        or stat.S_IMODE(info.st_mode) & 0o7022
    ):
        raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "credential_permissions")


@contextlib.contextmanager
def credential_files(request: Request, checks: dict[str, CheckState]) -> Iterator[dict[str, str]]:
    """Pin regular file descriptors through nofollow directory traversal.

    libpq opens /proc/self/fd references to these already-validated inodes. A
    subsequent host pathname/symlink replacement cannot redirect that read.
    No certificate or key content is read into this worker's Python objects.
    """
    descriptors: list[int] = []
    paths: dict[str, str] = {}
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory_fd = os.open("/", directory_flags)
        descriptors.append(directory_fd)
        _directory_metadata(os.fstat(directory_fd), request)
        for component in (*CREDENTIAL_ROOT.strip("/").split("/"), request.profile_id):
            directory_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            descriptors.append(directory_fd)
            _directory_metadata(os.fstat(directory_fd), request)
        for name in ("ca.crt", "client.crt", "client.key"):
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            descriptors.append(descriptor)
            validate_file_metadata(os.fstat(descriptor), name, request)
            if not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY:
                raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "credential_mount_read_only")
            paths[name] = f"/proc/self/fd/{descriptor}"
        checks["credential_permissions"] = "passed"
        checks["credential_mount_read_only"] = "passed"
        yield paths
    except OSError:
        raise WorkerFailure("CREDENTIAL_ACCESS_DENIED", "credential_permissions") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def connection_parameters(request: Request, paths: dict[str, str]) -> dict[str, str | int]:
    """No caller-controlled SQL, DSN expansion, password or TLS fallback."""
    return {
        "host": request.host,
        "hostaddr": request.hostaddr,
        "port": request.port,
        "dbname": request.database,
        "user": request.username,
        "password": "",
        "passfile": "/run/query-passport/no-password-file",
        "require_auth": "none",
        "sslmode": "verify-full",
        "sslcertmode": "require",
        "ssl_min_protocol_version": "TLSv1.2",
        "sslrootcert": paths["ca.crt"],
        "sslcert": paths["client.crt"],
        "sslkey": paths["client.key"],
        "sslcrl": "/run/query-passport/no-crl-file",
        # A fixed non-secret prevents OpenSSL's interactive passphrase prompt.
        # Encrypted private keys with operator-supplied passwords are unsupported.
        "sslpassword": "query-passport-encrypted-keys-unsupported",
        "gssencmode": "disable",
        "client_encoding": "UTF8",
        "connect_timeout": 2,
        "application_name": "query-passport-verify",
        "options": (
            "-c search_path=pg_catalog -c timezone=UTC -c default_transaction_read_only=on "
            "-c statement_timeout=1500 -c lock_timeout=250 "
            "-c idle_in_transaction_session_timeout=3000"
        ),
    }


async def _row(connection: Any, sql: str) -> Any:
    async with connection.cursor() as cursor:
        await cursor.execute(sql)
        return await cursor.fetchone()


async def _identity(connection: Any, request: Request, checks: dict[str, CheckState]) -> None:
    row = await _row(
        connection,
        "SELECT ssl, client_dn, version FROM pg_catalog.pg_stat_ssl "
        "WHERE pid = pg_catalog.pg_backend_pid()",
    )
    if not row or row[0] is not True or row[2] not in ("TLSv1.2", "TLSv1.3"):
        raise WorkerFailure("TLS_VERIFICATION_FAILED", "tls")
    checks["tls"] = "passed"
    # pg_stat_ssl uses OpenSSL slash-form DNs; HBA clientname=DN uses RFC2253.
    # This backend accepts only a single conservative CN, so the two exact
    # spellings are equivalent without parsing or loosely normalizing a full DN.
    if row[1] not in (request.expected_dn, "/" + request.expected_dn):
        raise WorkerFailure("CLIENT_AUTHENTICATION_FAILED", "client_identity")
    checks["client_identity"] = "passed"
    row = await _row(
        connection,
        "SELECT pg_catalog.current_database(), session_user, "
        "pg_catalog.current_setting('server_version_num'), "
        "pg_catalog.current_setting('server_encoding'), "
        "pg_catalog.current_setting('client_encoding'), "
        "pg_catalog.host(pg_catalog.inet_server_addr()), pg_catalog.inet_server_port()",
    )
    if (
        not row
        or row[0] != request.database
        or row[1] != request.username
        or not 180000 <= int(row[2]) < 190000
        or row[3:5] != ("UTF8", "UTF8")
        or ipaddress.ip_address(row[5]) != ipaddress.ip_address(request.hostaddr)
        or row[6] != request.port
    ):
        raise WorkerFailure("TARGET_MISMATCH", "target")
    checks["target"] = "passed"
    await _transaction_check(connection)
    checks["read_only_transaction"] = "passed"


async def _transaction_check(connection: Any) -> None:
    row = await _row(
        connection,
        "SELECT pg_catalog.current_setting('transaction_read_only'), "
        "pg_catalog.current_setting('transaction_isolation'), "
        "pg_catalog.current_setting('TimeZone'), 1",
    )
    if row != ("on", "repeatable read", "UTC", 1):
        raise WorkerFailure("VERIFICATION_FAILED", "read_only_transaction")


def _expected_cancel(error: BaseException, reason: str) -> bool:
    return (
        getattr(error, "sqlstate", None) == "57014"
        and getattr(getattr(error, "diag", None), "message_primary", None) == reason
    )


async def _timeout_check(connection: Any, checks: dict[str, CheckState]) -> None:
    # set_config changes only this read-only transaction's time limit.
    await _row(connection, "SELECT pg_catalog.set_config('statement_timeout', '100', true)")
    try:
        await _row(connection, "SELECT pg_catalog.pg_sleep(0.5)")
    except Exception as error:
        if not _expected_cancel(error, "canceling statement due to statement timeout"):
            raise
    else:
        raise WorkerFailure("VERIFICATION_FAILED", "statement_timeout")
    checks["statement_timeout"] = "passed"
    await connection.rollback()
    await _transaction_check(connection)
    checks["timeout_recovery"] = "passed"
    await connection.rollback()


async def _cancellation_check(connection: Any, checks: dict[str, CheckState]) -> None:
    await _transaction_check(connection)
    pending = asyncio.create_task(_row(connection, "SELECT pg_catalog.pg_sleep(1)"))
    try:
        # Wait for a query in flight, then give the server time to receive it.
        # A missed cancellation must fail, never be confused with a timeout.
        async with asyncio.timeout(0.5):
            while not pending.done() and connection.pgconn.transaction_status != 1:
                await asyncio.sleep(0.005)
        await asyncio.sleep(0.05)
        if pending.done():
            await pending
            raise WorkerFailure("VERIFICATION_FAILED", "cancellation")
        await connection.cancel_safe(timeout=1.0)
        try:
            await pending
        except Exception as error:
            if not _expected_cancel(error, "canceling statement due to user request"):
                raise
        else:
            raise WorkerFailure("VERIFICATION_FAILED", "cancellation")
        checks["cancellation"] = "passed"
    finally:
        if not pending.done():
            pending.cancel()
        # Always retrieve task errors; asyncio must not print provider diagnostics.
        with contextlib.suppress(BaseException):
            await pending
    await connection.rollback()
    await _transaction_check(connection)
    checks["cancellation_recovery"] = "passed"
    await connection.rollback()


async def verify(request: Request, paths: dict[str, str], checks: dict[str, CheckState]) -> None:
    driver = importlib.import_module("psycopg")
    # psycopg 3.2+'s safe async cancellation needs libpq >=17 to avoid its legacy
    # blocking, potentially plaintext cancellation fallback.
    if driver.pq.version() < 170000 or not hasattr(driver.AsyncConnection, "cancel_safe"):
        raise WorkerFailure("VERIFICATION_FAILED", "cancellation")
    parameters = connection_parameters(request, paths)
    async with asyncio.timeout(OVERALL_TIMEOUT_SECONDS):
        for attempt in range(2):
            connection = await driver.AsyncConnection.connect(**parameters, prepare_threshold=None)
            try:
                await connection.set_read_only(True)
                await connection.set_isolation_level(driver.IsolationLevel.REPEATABLE_READ)
                await _identity(connection, request, checks)
                if attempt == 0:
                    await _timeout_check(connection, checks)
                    await _cancellation_check(connection, checks)
                else:
                    await connection.rollback()
                    checks["reconnect"] = "passed"
            finally:
                await connection.close()


def sanitize_environment() -> None:
    # The executor launches a minimal environment. Reject hidden libpq/OpenSSL
    # behavior defensively too; never inspect or emit environment values.
    for name in tuple(os.environ):
        if name.startswith(("PG", "OPENSSL", "SSL_")) or name == "SSLKEYLOGFILE":
            os.environ.pop(name, None)
    logging.disable(logging.CRITICAL)


def _alarm(_signum: int, _frame: object) -> None:
    raise TimeoutError


def main() -> int:
    checks = new_checks()
    try:
        # Suppress native/provider stderr (including OpenSSL) before importing the
        # driver. The executor independently discards stderr as a second boundary.
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), 2)
        sanitize_environment()
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(18)
        request = parse_request(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        validate_runtime(request)
        checks["runtime_identity"] = "passed"
        with credential_files(request, checks) as paths:
            asyncio.run(verify(request, paths, checks))
        result: Result = {"status": "succeeded", "checks": checks, "error": None}
    except BaseException as error:  # noqa: BLE001 - final standalone redaction boundary
        result = failure_result(error, checks)
    finally:
        signal.alarm(0)
    try:
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        # Avoid a second failure during interpreter stream cleanup.
        with contextlib.suppress(OSError, ValueError):
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), 1)
        return 1
    return 0 if result["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
