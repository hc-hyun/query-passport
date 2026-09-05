"""Offline policy tests; all connections are fake and files use new temporary data."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from query_passport import executor
from query_passport import policy_verification as runner
from query_passport import policy_worker as worker
from query_passport.contract import ContractError
from query_passport.verify_worker import Request

REQUEST = json.loads((Path(__file__).resolve().parents[1] / "examples/request.json").read_text())
SUCCESS = {
    "status": "succeeded",
    "checks": dict.fromkeys(worker.CHECK_NAMES, "passed"),
    "error": None,
}
PATHS = {
    "ca.crt": "/proc/self/fd/7",
    "client.crt": "/proc/self/fd/8",
    "client.key": "/proc/self/fd/9",
}


class DriverError(Exception):
    __module__ = "psycopg"

    def __init__(self, message, *, sqlstate=None, primary=None, severity="FATAL"):
        self.sqlstate = sqlstate
        self.diag = SimpleNamespace(message_primary=primary, severity_nonlocalized=severity)
        super().__init__(message)


@pytest.fixture
def worker_request():
    return Request(
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


def diagnostic(message, *, address="172.23.0.2", port=5432):
    return f'connection failed: connection to server at "{address}", port {port} failed: FATAL:  {message}\n'


def hba(
    *,
    tls,
    user="passport_probe",
    database="passport_probe",
    prefix="pg_hba.conf rejects connection",
):
    transport = "SSL encryption" if tls else "no encryption"
    return f'{prefix} for host "172.23.0.3", user "{user}", database "{database}", {transport}'


@pytest.mark.parametrize("sqlstate", [None, "28000"])
@pytest.mark.parametrize("tls", [True, False])
@pytest.mark.parametrize("prefix", ["pg_hba.conf rejects connection", "no pg_hba.conf entry"])
def test_exact_server_hba_refusal_is_required(worker_request, sqlstate, tls, prefix):
    message = hba(tls=tls, prefix=prefix)
    error = DriverError(diagnostic(message), sqlstate=sqlstate, primary=message)
    assert worker.expected_refusal(error, worker_request, tls=tls)
    assert not worker.expected_refusal(error, worker_request, tls=not tls)


@pytest.mark.parametrize("sqlstate", [None, "28000"])
def test_exact_certificate_requirement_is_only_valid_for_tls(worker_request, sqlstate):
    message = "connection requires a valid client certificate"
    error = DriverError(diagnostic(message), sqlstate=sqlstate, primary=message)
    assert worker.expected_refusal(error, worker_request, tls=True)
    assert not worker.expected_refusal(error, worker_request, tls=False)


@pytest.mark.parametrize(
    "message",
    [
        "connection refused",
        "timeout expired",
        "certificate verify failed",
        'role "passport_probe" is not permitted to log in',
        'database "passport_probe" does not exist',
        'authentication method requirement "none" failed: server requested password authentication',
        'password authentication failed for user "passport_probe"',
        "PRIVATE_PROVIDER_DIAGNOSTIC: connection requires a valid client certificate",
        hba(tls=True, user="other_user"),
        hba(tls=True, database="other_database"),
        hba(tls=True).replace("172.23.0.3", "user@example.test"),
        hba(tls=True).replace("172.23.0.3", "fe80::1%eth0"),
        hba(tls=True) + "\nDETAIL: PRIVATE_PROVIDER_DIAGNOSTIC",
        "connection requires a valid client certificate\nconnection refused",
    ],
)
def test_unrelated_or_spoofed_diagnostic_never_passes(worker_request, message):
    error = DriverError(diagnostic(message))
    assert not worker.expected_refusal(error, worker_request, tls=True)
    assert not worker.expected_refusal(error, worker_request, tls=False)


@pytest.mark.parametrize("state", ["28P01", "42501", "3D000", "08001", "57014", ""])
def test_other_sqlstate_never_counts_as_expected_refusal(worker_request, state):
    message = "connection requires a valid client certificate"
    assert not worker.expected_refusal(
        DriverError(diagnostic(message), sqlstate=state, primary=message), worker_request, tls=True
    )


@pytest.mark.parametrize(
    "wrapper",
    [
        diagnostic(hba(tls=True), address="172.23.0.99"),
        diagnostic(hba(tls=True), port=5433),
        "FATAL:  " + hba(tls=True),
        diagnostic(hba(tls=True)) + "PRIVATE_PROVIDER_DIAGNOSTIC",
        "prefix " + diagnostic(hba(tls=True)),
    ],
)
def test_unstructured_error_must_be_anchored_to_pinned_server(worker_request, wrapper):
    assert not worker.expected_refusal(DriverError(wrapper), worker_request, tls=True)


def test_hostname_wrapper_matches_only_pinned_address(worker_request):
    text = diagnostic(hba(tls=True)).replace('"172.23.0.2"', '"passport-db" (172.23.0.2)')
    assert worker.expected_refusal(DriverError(text), worker_request, tls=True)
    assert not worker.expected_refusal(
        DriverError(text.replace("(172.23.0.2)", "(172.23.0.9)")), worker_request, tls=True
    )


def test_diagnostics_properties_can_raise_without_leaking(worker_request):
    class BrokenError(Exception):
        __module__ = "psycopg"

        @property
        def sqlstate(self):
            raise ValueError("PRIVATE_PROVIDER_DIAGNOSTIC")

    assert not worker.expected_refusal(BrokenError(), worker_request, tls=True)
    assert not worker.expected_refusal(
        ValueError(diagnostic(hba(tls=True))), worker_request, tls=True
    )


@pytest.mark.parametrize("tls", [True, False])
def test_probes_disable_client_certificate_and_every_ambient_fallback(worker_request, tls):
    parameters = worker.connection_parameters(worker_request, PATHS, tls=tls)
    assert parameters["sslmode"] == ("verify-full" if tls else "disable")
    assert parameters["sslrootcert"] == PATHS["ca.crt"]
    assert parameters["sslcertmode"] == "disable"
    assert parameters["sslcert"] == "/run/query-passport/no-client-certificate"
    assert parameters["sslkey"] == "/run/query-passport/no-client-key"
    assert parameters["password"] == ""
    assert parameters["require_auth"] == "none"
    assert parameters["passfile"] == "/run/query-passport/no-password-file"
    assert parameters["gssencmode"] == "disable"
    assert parameters["hostaddr"] == worker_request.hostaddr
    assert parameters["connect_timeout"] == 2
    assert parameters["sslpassword"] == "query-passport-encrypted-keys-unsupported"
    assert parameters["application_name"] == "query-passport-policy"


def install_driver(monkeypatch, outcomes, *, version=180006):
    connect = AsyncMock(side_effect=outcomes)
    driver = SimpleNamespace(
        pq=SimpleNamespace(version=lambda: version),
        AsyncConnection=SimpleNamespace(connect=connect),
    )
    monkeypatch.setattr(worker.importlib, "import_module", lambda name: driver)
    return connect


def test_both_probes_must_receive_expected_server_refusal(worker_request, monkeypatch):
    connect = install_driver(
        monkeypatch,
        [
            DriverError(diagnostic("connection requires a valid client certificate")),
            DriverError(diagnostic(hba(tls=False))),
        ],
    )
    checks = worker.new_checks()
    asyncio.run(worker.verify(worker_request, PATHS, checks))
    assert checks == SUCCESS["checks"]
    assert [call.kwargs["sslmode"] for call in connect.await_args_list] == [
        "verify-full",
        "disable",
    ]
    assert all(call.kwargs["autocommit"] is True for call in connect.await_args_list)


@pytest.mark.parametrize("tls_acceptance", [True, False])
def test_accepted_connection_closes_without_sql_and_fails(
    worker_request, monkeypatch, tls_acceptance
):
    connection = SimpleNamespace(close=AsyncMock())
    outcomes = (
        [connection] if tls_acceptance else [DriverError(diagnostic(hba(tls=True))), connection]
    )
    connect = install_driver(monkeypatch, outcomes)
    checks = worker.new_checks()
    with pytest.raises(worker.base.WorkerFailure) as error:
        asyncio.run(worker.verify(worker_request, PATHS, checks))
    assert error.value.code == "VERIFICATION_FAILED"
    connection.close.assert_awaited_once()
    assert connect.await_count == (1 if tls_acceptance else 2)
    assert checks == {
        "client_certificate_required": "failed" if tls_acceptance else "passed",
        "plaintext_rejected": "not_checked" if tls_acceptance else "failed",
    }


@pytest.mark.parametrize(
    "message",
    ["connection refused", "timeout expired", 'authentication method requirement "none" failed'],
)
def test_network_failure_or_password_challenge_is_not_a_policy_pass(
    worker_request, monkeypatch, message
):
    install_driver(monkeypatch, [DriverError(message)])
    checks = worker.new_checks()
    with pytest.raises(DriverError):
        asyncio.run(worker.verify(worker_request, PATHS, checks))
    assert checks == {"client_certificate_required": "failed", "plaintext_rejected": "not_checked"}


def test_unsupported_libpq_does_not_attempt_connection(worker_request, monkeypatch):
    connect = install_driver(monkeypatch, [], version=160000)
    checks = worker.new_checks()
    with pytest.raises(worker.base.WorkerFailure):
        asyncio.run(worker.verify(worker_request, PATHS, checks))
    connect.assert_not_called()
    assert checks == worker.new_checks()


def test_overall_timeout_keeps_remaining_probe_unchecked(worker_request, monkeypatch):
    async def connect(**kwargs):
        await asyncio.sleep(1)

    driver = SimpleNamespace(
        pq=SimpleNamespace(version=lambda: 180006), AsyncConnection=SimpleNamespace(connect=connect)
    )
    monkeypatch.setattr(worker.importlib, "import_module", lambda name: driver)
    monkeypatch.setattr(worker, "OVERALL_TIMEOUT_SECONDS", 0.01)
    checks = worker.new_checks()
    with pytest.raises(TimeoutError):
        asyncio.run(worker.verify(worker_request, PATHS, checks))
    assert checks["plaintext_rejected"] == "not_checked"


@pytest.mark.parametrize("raw", [b'{"password":"PRIVATE_PROVIDER_DIAGNOSTIC"}', b"[", b"x" * 8193])
def test_composed_standalone_modules_need_no_installed_package(raw):
    result = subprocess.run(
        [sys.executable, "-I", "-c", runner.worker_source()],
        input=raw,
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == b""
    assert json.loads(result.stdout) == {
        "status": "failed",
        "checks": worker.new_checks(),
        "error": "TARGET_MISMATCH",
    }
    assert b"PRIVATE_PROVIDER_DIAGNOSTIC" not in result.stdout


@pytest.fixture
def binding():
    with tempfile.TemporaryDirectory(prefix="passport-policy-unit-", dir="/var/tmp") as root:
        bundle = Path(root) / "bundle"
        bundle.mkdir(mode=0o700)
        for name in ("ca.crt", "client.crt", "client.key"):
            (bundle / name).write_bytes(b"synthetic offline test fixture")
            (bundle / name).chmod(0o600)
        yield {
            "binding_version": 1,
            "allowed_uid": os.geteuid(),
            "expires_at": int(time.time()) + 3600,
            "operations": ["verify"],
            "request": copy.deepcopy(REQUEST),
            "container_id": "a" * 64,
            "container_started_at": "2026-09-05T01:02:03.000000000Z",
            "database_image_id": "sha256:" + "b" * 64,
            "network_name": "passport-test",
            "network_id": "c" * 64,
            "hostaddr": "172.22.0.2",
            "runtime_image_id": "sha256:" + "d" * 64,
            "runtime_uid": 10001,
            "runtime_gid": 10001,
            "username": "passport_check",
            "expected_dn": "CN=query-passport-test",
            "credential_dir": str(bundle),
        }


def host_fake(monkeypatch, *, response=None, effect=None, cleanup="success"):
    calls = []
    monkeypatch.setattr(executor, "target_snapshot", lambda value: "fixed-generation")

    def docker(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "run":
            if effect:
                effect()
            return json.dumps(response if response is not None else SUCCESS).encode()
        if args[0] == "rm" and cleanup != "success":
            raise ContractError("EXECUTOR_FAILED")
        if args[0] == "ps":
            return b"" if cleanup == "absent" else b"remaining"
        return b""

    monkeypatch.setattr(executor, "docker", docker)
    return calls


def test_runner_pins_generation_readonly_mount_image_uid_and_cleanup(binding, monkeypatch):
    calls = host_fake(monkeypatch)
    assert runner.run_policy_verification(binding, REQUEST) == SUCCESS
    args, kwargs = calls[0]
    assert args[args.index("--network") + 1] == binding["network_id"]
    assert args[args.index("--user") + 1] == "10001:10001"
    assert args[args.index("--entrypoint") + 1] == "/usr/bin/env"
    assert args[args.index("--mount") + 1].endswith(",readonly")
    assert "--read-only" in args and "--pull=never" in args and "--cap-drop=ALL" in args
    assert binding["runtime_image_id"] in args
    assert kwargs["timeout"] == 20 and kwargs["limit"] == 8192 and kwargs["worker_output"] is True
    payload = json.loads(kwargs["stdin"])
    assert payload["hostaddr"] == binding["hostaddr"]
    assert payload["username"] == binding["username"]
    assert args[-1] == runner.worker_source()
    name = args[args.index("--name") + 1]
    assert name.startswith("query-passport-policy-")
    assert calls[-1] == (["rm", "-f", name], {"timeout": 5})


@pytest.mark.parametrize("change", ["extra", "missing", "symlink"])
def test_unsafe_bundle_does_not_start_worker(binding, monkeypatch, change):
    bundle = Path(binding["credential_dir"])
    if change == "extra":
        (bundle / "unauthorized").write_bytes(b"synthetic")
    elif change == "missing":
        (bundle / "ca.crt").unlink()
    else:
        link = bundle.parent / "link"
        link.symlink_to(bundle, target_is_directory=True)
        binding["credential_dir"] = str(link)
    calls = host_fake(monkeypatch)
    with pytest.raises(ContractError) as error:
        runner.run_policy_verification(binding, REQUEST)
    assert error.value.code == "CREDENTIAL_ACCESS_DENIED"
    assert calls == []


def test_unauthorized_binding_rejected_before_target_or_worker(binding, monkeypatch):
    binding["runtime_uid"] = 0
    monkeypatch.setattr(executor, "target_snapshot", lambda value: pytest.fail("No execution"))
    with pytest.raises(ContractError) as error:
        runner.run_policy_verification(binding, REQUEST)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_post_probe_credential_drift_discards_success(binding, monkeypatch):
    calls = host_fake(
        monkeypatch,
        effect=lambda: (Path(binding["credential_dir"]) / "client.crt").write_bytes(
            b"changed synthetic fixture"
        ),
    )
    with pytest.raises(ContractError) as error:
        runner.run_policy_verification(binding, REQUEST)
    assert error.value.code == "TARGET_DRIFT"
    assert calls[-1][0][0] == "rm"


def test_post_probe_target_drift_discards_success(binding, monkeypatch):
    calls = host_fake(monkeypatch)
    snapshots = iter(("old", "new"))
    monkeypatch.setattr(executor, "target_snapshot", lambda value: next(snapshots))
    with pytest.raises(ContractError) as error:
        runner.run_policy_verification(binding, REQUEST)
    assert error.value.code == "TARGET_DRIFT"
    assert calls[-1][0][0] == "rm"


@pytest.mark.parametrize("cleanup", ["absent", "remaining"])
def test_cleanup_must_prove_fresh_container_absent(binding, monkeypatch, cleanup):
    calls = host_fake(monkeypatch, cleanup=cleanup)
    if cleanup == "absent":
        assert runner.run_policy_verification(binding, REQUEST) == SUCCESS
    else:
        with pytest.raises(ContractError) as error:
            runner.run_policy_verification(binding, REQUEST)
        assert error.value.code == "RECOVERY_REQUIRED"
    assert calls[-1][0][0] == "ps"


@pytest.mark.parametrize(
    "mutation", ["extra", "missing", "unchecked", "secret", "unknown_state", "all_passed_failure"]
)
def test_result_normalization_is_closed_and_redacted(mutation):
    result = copy.deepcopy(SUCCESS)
    if mutation == "extra":
        result["secret"] = "PRIVATE_PROVIDER_DIAGNOSTIC"
    elif mutation == "missing":
        del result["checks"]["plaintext_rejected"]
    elif mutation == "unchecked":
        result["checks"]["plaintext_rejected"] = "not_checked"
    elif mutation == "secret":
        result.update(status="failed", error="PRIVATE_PROVIDER_DIAGNOSTIC")
    elif mutation == "unknown_state":
        result["checks"]["plaintext_rejected"] = "PRIVATE_PROVIDER_DIAGNOSTIC"
    else:
        result.update(status="failed", error="VERIFICATION_FAILED")
    with pytest.raises(ContractError) as error:
        runner.normalize_worker_result(json.dumps(result).encode())
    assert error.value.code == "EXECUTOR_FAILED"
    assert "PRIVATE_PROVIDER_DIAGNOSTIC" not in str(error.value)


def test_failed_result_preserves_only_fixed_classification():
    result = worker.failure_result(
        DriverError("PRIVATE_PROVIDER_DIAGNOSTIC timeout expired"), worker.new_checks()
    )
    assert result["error"] == "TIMEOUT"
    assert "PRIVATE_PROVIDER_DIAGNOSTIC" not in json.dumps(result)
    assert runner.normalize_worker_result(json.dumps(result).encode()) == result


@pytest.mark.parametrize(
    "failure",
    [ContractError("TIMEOUT"), ContractError("INTERRUPTED"), KeyboardInterrupt(), SystemExit(1)],
)
@pytest.mark.parametrize("cleanup", ["remaining", "observation_failed", "interrupted"])
def test_policy_probe_uncertainty_survives_docker_cleanup(binding, monkeypatch, failure, cleanup):
    monkeypatch.setattr(executor, "target_snapshot", lambda _: "fixed-generation")
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        if args[0] == "run":
            raise failure
        assert kwargs == {"timeout": 5}
        if args[0] == "rm":
            if cleanup == "interrupted":
                raise KeyboardInterrupt()
            raise ContractError("EXECUTOR_FAILED")
        if cleanup == "observation_failed":
            raise ContractError("EXECUTOR_FAILED")
        return b"remaining"

    monkeypatch.setattr(executor, "docker", docker)
    with pytest.raises(type(failure)) as caught:
        runner.run_policy_verification(binding, REQUEST)
    assert caught.value is failure
    assert [call[0] for call in calls] == ["run", "rm", "ps"]
    name = calls[0][calls[0].index("--name") + 1]
    assert name.startswith("query-passport-policy-")
    assert calls[1] == ["rm", "-f", name]


@pytest.mark.parametrize(
    "failure",
    [ContractError("TIMEOUT"), ContractError("INTERRUPTED"), KeyboardInterrupt(), SystemExit(1)],
)
def test_successful_probe_does_not_hide_cleanup_uncertainty(binding, monkeypatch, failure):
    monkeypatch.setattr(executor, "target_snapshot", lambda _: "fixed-generation")

    def docker(args, **kwargs):
        if args[0] == "run":
            return json.dumps(SUCCESS).encode()
        if args[0] == "rm":
            raise failure
        return b""

    monkeypatch.setattr(executor, "docker", docker)
    with pytest.raises(type(failure)) as caught:
        runner.run_policy_verification(binding, REQUEST)
    assert caught.value is failure


def test_policy_worker_timeout_result_survives_cleanup_failure(binding, monkeypatch):
    result = {"status": "failed", "checks": worker.new_checks(), "error": "TIMEOUT"}
    host_fake(monkeypatch, response=result, cleanup="remaining")
    assert runner.run_policy_verification(binding, REQUEST) == result
