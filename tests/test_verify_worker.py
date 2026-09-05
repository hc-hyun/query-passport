"""Offline worker tests use metadata and fake driver responses, never credentials."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from query_passport import verify_worker as worker


@pytest.fixture
def worker_request() -> worker.Request:
    return worker.Request(
        host="passport-db",
        hostaddr="172.23.0.2",
        port=5432,
        database="passport_probe",
        username="passport_probe",
        expected_dn="CN=passport-probe",
        profile_id="probe",
        runtime_uid=10001,
        runtime_gid=10001,
    )


def raw_request(worker_request: worker.Request, **changes: object) -> bytes:
    value = dataclasses.asdict(worker_request)
    value.update(changes)
    return json.dumps(value).encode()


def test_internal_request_round_trip(worker_request: worker.Request) -> None:
    assert worker.parse_request(raw_request(worker_request)) == worker_request


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "host,other"},
        {"host": "/var/run/postgresql"},
        {"host": "db.example\npassword=secret-canary"},
        {"host": "postgres://user:secret-canary@db"},
        {"hostaddr": "127.0.0.1,172.23.0.2"},
        {"hostaddr": "localhost"},
        {"hostaddr": "0.0.0.0"},
        {"hostaddr": "::"},
        {"hostaddr": "ff02::1"},
        {"hostaddr": "fe80::1%eth0"},
        {"database": "db password=secret-canary"},
        {"database": "postgres://user:secret-canary@db"},
        {"username": "probe\x00secret-canary"},
        {"username": "probe;SELECT 1"},
        {"profile_id": "../secrets"},
        {"profile_id": "nested/probe"},
        {"profile_id": "."},
        {"profile_id": ".."},
        {"profile_id": "probe\\file"},
        {"port": True},
        {"port": "5432"},
        {"port": 0},
        {"port": 65536},
        {"runtime_uid": 0},
        {"runtime_uid": True},
        {"runtime_gid": -1},
        {"expected_dn": ""},
        {"expected_dn": "CN=probe,O=other"},
        {"expected_dn": "CN=probe/OU=other"},
        {"expected_dn": "/CN=probe"},
        {"expected_dn": "CN=secret-canary\nother"},
        {"password": "secret-canary"},
        {"options": "secret-canary"},
    ],
)
def test_internal_request_rejects_overrides_without_reflection(
    worker_request: worker.Request, changes: dict[str, object]
) -> None:
    with pytest.raises(worker.WorkerFailure) as caught:
        worker.parse_request(raw_request(worker_request, **changes))
    assert str(caught.value) == "TARGET_MISMATCH"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"null",
        b"[]",
        b"\xffsecret-canary",
        b'{"password":"secret-canary"}',
        b'{"host":"first","host":"secret-canary"}',
        b"[" * 1500,
        b" " * (worker.MAX_INPUT_BYTES + 1),
    ],
)
def test_invalid_json_is_fixed_failure(raw: bytes) -> None:
    with pytest.raises(worker.WorkerFailure, match="^TARGET_MISMATCH$"):
        worker.parse_request(raw)


def info(mode: int, uid: int = 10001, gid: int = 10001, links: int = 1) -> os.stat_result:
    return os.stat_result((mode, 1, 1, links, uid, gid, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("uid", "gid", "mode"), [(10001, 10001, 0o600), (10001, 0, 0o600), (0, 10001, 0o640)]
)
def test_allowed_key_permissions(
    worker_request: worker.Request, uid: int, gid: int, mode: int
) -> None:
    worker.validate_file_metadata(info(stat.S_IFREG | mode, uid, gid), "client.key", worker_request)


@pytest.mark.parametrize(
    ("uid", "gid", "mode", "links"),
    [
        (10001, 10001, stat.S_IFREG | 0o644, 1),
        (10001, 10001, stat.S_IFREG | 0o640, 1),
        (0, 0, stat.S_IFREG | 0o640, 1),
        (0, 10001, stat.S_IFREG | 0o600, 1),
        (10002, 10001, stat.S_IFREG | 0o600, 1),
        (10001, 10001, stat.S_IFREG | 0o4600, 1),
        (10001, 10001, stat.S_IFDIR | 0o600, 1),
        (10001, 10001, stat.S_IFLNK | 0o600, 1),
        (10001, 10001, stat.S_IFIFO | 0o600, 1),
        (10001, 10001, stat.S_IFREG | 0o600, 2),
    ],
)
def test_reject_unsafe_key_metadata(
    worker_request: worker.Request, uid: int, gid: int, mode: int, links: int
) -> None:
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        worker.validate_file_metadata(info(mode, uid, gid, links), "client.key", worker_request)


@pytest.mark.parametrize("name", ["ca.crt", "client.crt"])
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_public_certificate_permissions(
    worker_request: worker.Request, name: str, mode: int
) -> None:
    worker.validate_file_metadata(info(stat.S_IFREG | mode, 0), name, worker_request)


@pytest.mark.parametrize("mode", [0o666, 0o660, 0o4644])
def test_reject_writable_or_special_certificate_metadata(
    worker_request: worker.Request, mode: int
) -> None:
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        worker.validate_file_metadata(info(stat.S_IFREG | mode), "ca.crt", worker_request)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o700])
def test_directory_permissions(worker_request: worker.Request, mode: int) -> None:
    worker._directory_metadata(info(stat.S_IFDIR | mode, 0), worker_request)


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o1777, 0o2755])
def test_reject_mutable_directory(worker_request: worker.Request, mode: int) -> None:
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        worker._directory_metadata(info(stat.S_IFDIR | mode), worker_request)


@pytest.mark.parametrize(
    "overrides",
    [
        {"getuid": 0},
        {"geteuid": 0},
        {"getgid": 0},
        {"getegid": 0},
        {"getgroups": [10001, 10002]},
    ],
)
def test_runtime_identity_rejects_mismatch(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    values = {"getuid": 10001, "geteuid": 10001, "getgid": 10001, "getegid": 10001}
    values["getgroups"] = [10001]
    values.update(overrides)
    for name, result in values.items():
        monkeypatch.setattr(worker.os, name, lambda result=result: result)
    with pytest.raises(worker.WorkerFailure) as caught:
        worker.validate_runtime(worker_request)
    assert caught.value.check == "runtime_identity"


@pytest.fixture
def empty_credential_directory(
    worker_request: worker.Request, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[worker.Request, Path]:
    """Empty regular files verify descriptors; there is no certificate or key data."""
    worker_request = dataclasses.replace(
        worker_request, runtime_uid=os.getuid(), runtime_gid=os.getgid()
    )
    directory = tmp_path / worker_request.profile_id
    directory.mkdir()
    for name in ("ca.crt", "client.crt", "client.key"):
        path = directory / name
        path.touch(mode=0o600)
    monkeypatch.setattr(worker, "CREDENTIAL_ROOT", str(tmp_path))
    # /tmp intentionally has unsafe directory permissions. Directory policy itself
    # is tested above; these cases isolate actual nofollow descriptor traversal.
    monkeypatch.setattr(worker, "_directory_metadata", lambda *_: None)
    monkeypatch.setattr(worker.os, "fstatvfs", lambda _: SimpleNamespace(f_flag=os.ST_RDONLY))
    return worker_request, directory


def test_credential_descriptors_remain_pinned_and_are_closed(
    empty_credential_directory: tuple[worker.Request, Path],
) -> None:
    worker_request, directory = empty_credential_directory
    checks = worker.new_checks()
    with worker.credential_files(worker_request, checks) as paths:
        descriptors = [int(path.rsplit("/", 1)[1]) for path in paths.values()]
        original = os.stat(paths["client.key"])
        (directory / "client.key").rename(directory / "moved.key")
        (directory / "client.key").touch(mode=0o600)
        assert os.stat(paths["client.key"]).st_ino == original.st_ino
        assert os.stat(directory / "client.key").st_ino != original.st_ino
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert checks["credential_permissions"] == "passed"
    assert checks["credential_mount_read_only"] == "passed"


@pytest.mark.parametrize("name", ["ca.crt", "client.crt", "client.key"])
def test_reject_symlink_file(
    empty_credential_directory: tuple[worker.Request, Path], name: str
) -> None:
    worker_request, directory = empty_credential_directory
    path = directory / name
    path.rename(directory / "target")
    path.symlink_to(directory / "target")
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        with worker.credential_files(worker_request, worker.new_checks()):
            pytest.fail("symlink must never be delivered to libpq")


def test_reject_symlink_directory(
    empty_credential_directory: tuple[worker.Request, Path],
) -> None:
    worker_request, directory = empty_credential_directory
    moved = directory.with_name("moved")
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        with worker.credential_files(worker_request, worker.new_checks()):
            pytest.fail("directory symlink must be rejected")


def test_reject_fifo_without_blocking(
    empty_credential_directory: tuple[worker.Request, Path],
) -> None:
    worker_request, directory = empty_credential_directory
    (directory / "client.key").unlink()
    os.mkfifo(directory / "client.key", mode=0o600)
    with pytest.raises(worker.WorkerFailure, match="CREDENTIAL_ACCESS_DENIED"):
        with worker.credential_files(worker_request, worker.new_checks()):
            pytest.fail("FIFO must be rejected")


def test_reject_writable_mount(
    empty_credential_directory: tuple[worker.Request, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    worker_request, _ = empty_credential_directory
    monkeypatch.setattr(worker.os, "fstatvfs", lambda _: SimpleNamespace(f_flag=0))
    checks = worker.new_checks()
    with pytest.raises(worker.WorkerFailure) as caught:
        with worker.credential_files(worker_request, checks):
            pytest.fail("writable mount must be rejected")
    result = worker.failure_result(caught.value, checks)
    assert result["checks"]["credential_mount_read_only"] == "failed"
    assert result["checks"]["tls"] == "not_checked"


class DriverError(Exception):
    __module__ = "psycopg.errors"

    def __init__(self, message: str, state: str | None = None) -> None:
        self.sqlstate = state
        self.diag = SimpleNamespace(message_primary=message)
        super().__init__(message)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (DriverError("secret-canary certificate verify failed"), "TLS_VERIFICATION_FAILED"),
        (DriverError("secret-canary does not match host name"), "TLS_VERIFICATION_FAILED"),
        (
            DriverError("secret-canary SSL error: tlsv1 alert unknown ca"),
            "CLIENT_AUTHENTICATION_FAILED",
        ),
        (DriverError("secret-canary private key mismatch"), "CLIENT_AUTHENTICATION_FAILED"),
        (DriverError("secret-canary certificate expired"), "CLIENT_AUTHENTICATION_FAILED"),
        (
            DriverError("secret-canary authentication method requirement"),
            "CLIENT_AUTHENTICATION_FAILED",
        ),
        (DriverError("secret-canary no password supplied"), "CLIENT_AUTHENTICATION_FAILED"),
        (DriverError("secret-canary", "28000"), "CLIENT_AUTHENTICATION_FAILED"),
        (DriverError("secret-canary", "28P01"), "CLIENT_AUTHENTICATION_FAILED"),
        (DriverError("secret-canary", "42501"), "PERMISSION_DENIED"),
        (DriverError("secret-canary", "3D000"), "TARGET_MISMATCH"),
        (DriverError("secret-canary", "57014"), "TIMEOUT"),
        (DriverError("secret-canary timeout expired"), "TIMEOUT"),
        (DriverError("secret-canary connection refused"), "CONNECTION_FAILED"),
        (TimeoutError("secret-canary"), "TIMEOUT"),
        (PermissionError("secret-canary"), "CREDENTIAL_ACCESS_DENIED"),
        (RuntimeError("secret-canary"), "INTERNAL_ERROR"),
        (worker.WorkerFailure("secret-canary"), "INTERNAL_ERROR"),
    ],
)
def test_error_normalization_does_not_expose_provider_data(
    error: BaseException, expected: str
) -> None:
    result = worker.failure_result(error, worker.new_checks())
    assert result["status"] == "failed"
    assert result["error"] == expected
    assert set(result["checks"]) == set(worker.CHECK_NAMES)
    assert "secret-canary" not in json.dumps(result)


def test_connection_parameters_forbid_fallback_and_pin_endpoint(
    worker_request: worker.Request,
) -> None:
    paths = {
        name: f"/proc/self/fd/{index}"
        for index, name in enumerate(("ca.crt", "client.crt", "client.key"), 10)
    }
    parameters = worker.connection_parameters(worker_request, paths)
    assert parameters["host"] == worker_request.host
    assert parameters["hostaddr"] == worker_request.hostaddr
    assert parameters["port"] == worker_request.port
    assert parameters["dbname"] == worker_request.database
    assert parameters["user"] == worker_request.username
    assert parameters["sslmode"] == "verify-full"
    assert parameters["sslcertmode"] == "require"
    assert parameters["require_auth"] == "none"
    assert parameters["gssencmode"] == "disable"
    assert parameters["password"] == ""
    assert parameters["passfile"] != ""
    assert parameters["connect_timeout"] == 2
    assert parameters["client_encoding"] == "UTF8"
    assert "-c timezone=UTC" in parameters["options"]
    assert "-c default_transaction_read_only=on" in parameters["options"]
    assert "-c search_path=pg_catalog" in parameters["options"]
    assert set(paths.values()) <= set(parameters.values())


def test_sanitize_environment_removes_hidden_driver_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "PGPASSWORD",
        "PGSERVICE",
        "PGOPTIONS",
        "PGSSLKEYLOGFILE",
        "OPENSSL_CONF",
        "SSL_CERT_FILE",
        "SSLKEYLOGFILE",
    ):
        monkeypatch.setenv(name, "secret-canary")
    # Keep logging's process-global setting isolated from unrelated pytest tests.
    monkeypatch.setattr(worker.logging, "disable", lambda _: None)
    worker.sanitize_environment()
    assert not any(value == "secret-canary" for value in os.environ.values())


def test_timeout_and_cancellation_are_not_confused() -> None:
    timeout = DriverError("canceling statement due to statement timeout", "57014")
    canceled = DriverError("canceling statement due to user request", "57014")
    assert worker._expected_cancel(timeout, "canceling statement due to statement timeout")
    assert worker._expected_cancel(canceled, "canceling statement due to user request")
    assert not worker._expected_cancel(timeout, "canceling statement due to user request")
    assert not worker._expected_cancel(canceled, "canceling statement due to statement timeout")


@pytest.mark.parametrize(
    ("row", "expected_check"),
    [
        ((False, "CN=passport-probe", "TLSv1.3"), "tls"),
        ((True, "CN=passport-probe", "TLSv1.1"), "tls"),
        ((True, "CN=other-secret-canary", "TLSv1.3"), "client_identity"),
        (None, "tls"),
    ],
)
def test_identity_refuses_weak_or_wrong_tls(
    worker_request: worker.Request,
    monkeypatch: pytest.MonkeyPatch,
    row: object,
    expected_check: str,
) -> None:
    monkeypatch.setattr(worker, "_row", AsyncMock(return_value=row))
    checks = worker.new_checks()
    with pytest.raises(worker.WorkerFailure) as caught:
        asyncio.run(worker._identity(object(), worker_request, checks))
    result = worker.failure_result(caught.value, checks)
    assert result["checks"][expected_check] == "failed"
    assert "secret-canary" not in json.dumps(result)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        (0, "other"),
        (1, "other"),
        (2, "170001"),
        (2, "190000"),
        (3, "LATIN1"),
        (4, "LATIN1"),
        (5, "172.23.0.3"),
        (6, 5433),
    ],
)
def test_identity_rejects_wrong_actual_target(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch, column: int, value: object
) -> None:
    row = [
        worker_request.database,
        worker_request.username,
        "180000",
        "UTF8",
        "UTF8",
        worker_request.hostaddr,
        worker_request.port,
    ]
    row[column] = value
    monkeypatch.setattr(
        worker,
        "_row",
        AsyncMock(side_effect=[(True, worker_request.expected_dn, "TLSv1.3"), tuple(row)]),
    )
    with pytest.raises(worker.WorkerFailure, match="TARGET_MISMATCH"):
        asyncio.run(worker._identity(object(), worker_request, worker.new_checks()))


@pytest.mark.parametrize(
    "row",
    [
        ("off", "repeatable read", "UTC", 1),
        ("on", "read committed", "UTC", 1),
        ("on", "repeatable read", "Asia/Seoul", 1),
    ],
)
def test_transaction_enforces_read_only_repeatable_read_and_utc(
    monkeypatch: pytest.MonkeyPatch, row: object
) -> None:
    monkeypatch.setattr(worker, "_row", AsyncMock(return_value=row))
    with pytest.raises(worker.WorkerFailure, match="VERIFICATION_FAILED"):
        asyncio.run(worker._transaction_check(object()))


def test_requires_safe_libpq_cancellation_before_connecting(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch
) -> None:
    connect = AsyncMock()
    driver = SimpleNamespace(
        pq=SimpleNamespace(version=lambda: 160000), AsyncConnection=SimpleNamespace(connect=connect)
    )
    monkeypatch.setattr(worker.importlib, "import_module", lambda _: driver)
    paths = {name: "/proc/self/fd/9" for name in ("ca.crt", "client.crt", "client.key")}
    with pytest.raises(worker.WorkerFailure, match="VERIFICATION_FAILED"):
        asyncio.run(worker.verify(worker_request, paths, worker.new_checks()))
    connect.assert_not_called()


def test_standalone_worker_returns_only_fixed_json_on_invalid_input() -> None:
    source = Path(worker.__file__).read_text()
    completed = subprocess.run(
        [sys.executable, "-I", "-c", source],
        input=b'{"secret":"secret-canary"}',
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stderr == b""
    assert b"secret-canary" not in completed.stdout
    result = json.loads(completed.stdout)
    assert result["error"] == "TARGET_MISMATCH"
    assert set(result["checks"].values()) == {"not_checked"}


def test_provider_diagnostic_failure_still_has_fixed_result() -> None:
    class BrokenDiagnostic(DriverError):
        __module__ = "psycopg.errors"

        def __str__(self) -> str:
            raise RuntimeError("secret-canary")

    result = worker.failure_result(BrokenDiagnostic("secret-canary"), worker.new_checks())
    assert result["error"] == "INTERNAL_ERROR"
    assert "secret-canary" not in json.dumps(result)


@pytest.mark.parametrize(
    "actual_reason",
    [
        "canceling statement due to user request",
        "canceling statement due to statement timeout",
        None,
    ],
)
def test_explicit_cancel_requires_observed_user_cancellation_and_recovers(
    monkeypatch: pytest.MonkeyPatch, actual_reason: str | None
) -> None:
    async def scenario() -> None:
        signal_received = asyncio.Event()
        connection = SimpleNamespace(
            pgconn=SimpleNamespace(transaction_status=2),
            rollback=AsyncMock(),
        )

        async def cancel_safe(*, timeout: float) -> None:
            assert timeout == 1.0
            signal_received.set()

        connection.cancel_safe = AsyncMock(side_effect=cancel_safe)

        async def row(_connection: object, sql: str) -> object:
            if "pg_sleep" in sql:
                connection.pgconn.transaction_status = 1
                await signal_received.wait()
                if actual_reason is not None:
                    raise DriverError(actual_reason, "57014")
                return (None,)
            return ("on", "repeatable read", "UTC", 1)

        monkeypatch.setattr(worker, "_row", row)
        checks = worker.new_checks()
        if actual_reason == "canceling statement due to user request":
            await worker._cancellation_check(connection, checks)
            assert checks["cancellation"] == "passed"
            assert checks["cancellation_recovery"] == "passed"
            assert connection.rollback.await_count == 2
        else:
            with pytest.raises((worker.WorkerFailure, DriverError)):
                await worker._cancellation_check(connection, checks)
            assert checks["cancellation"] != "passed"
            assert checks["cancellation_recovery"] == "not_checked"
        connection.cancel_safe.assert_awaited_once()

    asyncio.run(scenario())


@pytest.mark.parametrize("fail_first", [False, True])
def test_worker_connection_budget_is_sequential_and_failure_stops_reconnect(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch, fail_first: bool
) -> None:
    active = 0
    attempts = 0
    events = []

    async def connect(**_parameters: object) -> object:
        nonlocal active, attempts
        assert active == 0, "a new connection must follow completed close"
        active += 1
        attempts += 1
        events.append("connect")

        async def close() -> None:
            nonlocal active
            active -= 1
            events.append("close")

        return SimpleNamespace(
            close=AsyncMock(side_effect=close),
            set_read_only=AsyncMock(),
            set_isolation_level=AsyncMock(),
            rollback=AsyncMock(),
        )

    driver = SimpleNamespace(
        pq=SimpleNamespace(version=lambda: 180000),
        AsyncConnection=SimpleNamespace(connect=connect, cancel_safe=AsyncMock()),
        IsolationLevel=SimpleNamespace(REPEATABLE_READ="repeatable read"),
    )
    monkeypatch.setattr(worker.importlib, "import_module", lambda _: driver)
    monkeypatch.setattr(worker, "_identity", AsyncMock())
    monkeypatch.setattr(
        worker,
        "_timeout_check",
        AsyncMock(side_effect=DriverError("secret-canary") if fail_first else None),
    )
    monkeypatch.setattr(worker, "_cancellation_check", AsyncMock())
    paths = {name: "/proc/self/fd/9" for name in ("ca.crt", "client.crt", "client.key")}
    checks = worker.new_checks()
    if fail_first:
        with pytest.raises(DriverError):
            asyncio.run(worker.verify(worker_request, paths, checks))
        assert attempts == 1
        assert checks["reconnect"] == "not_checked"
        assert events == ["connect", "close"]
    else:
        asyncio.run(worker.verify(worker_request, paths, checks))
        assert attempts == 2
        assert checks["reconnect"] == "passed"
        assert events == ["connect", "close", "connect", "close"]
    assert active == 0


@pytest.mark.parametrize("observed", ["CN=passport-probe", "/CN=passport-probe"])
def test_single_cn_accepts_actual_pg_stat_ssl_slash_representation(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch, observed: str
) -> None:
    rows = [
        (True, observed, "TLSv1.3"),
        (
            worker_request.database,
            worker_request.username,
            "180000",
            "UTF8",
            "UTF8",
            worker_request.hostaddr,
            worker_request.port,
        ),
        ("on", "repeatable read", "UTC", 1),
    ]
    monkeypatch.setattr(worker, "_row", AsyncMock(side_effect=rows))
    checks = worker.new_checks()
    asyncio.run(worker._identity(object(), worker_request, checks))
    assert checks["client_identity"] == "passed"
    assert checks["target"] == "passed"


@pytest.mark.parametrize(
    "observed",
    [
        "/CN=passport-probe/OU=other",
        "CN=passport-probe,O=other",
        "/CN=passport-probe-other",
        "/CN=PASSPORT-PROBE",
        "CN=passport-probe ",
    ],
)
def test_dn_rendering_support_does_not_accept_extra_attributes_or_partial_matches(
    worker_request: worker.Request, monkeypatch: pytest.MonkeyPatch, observed: str
) -> None:
    monkeypatch.setattr(worker, "_row", AsyncMock(return_value=(True, observed, "TLSv1.3")))
    with pytest.raises(worker.WorkerFailure, match="CLIENT_AUTHENTICATION_FAILED"):
        asyncio.run(worker._identity(object(), worker_request, worker.new_checks()))
