"""Real PG18/client-certificate integration, explicitly opted into by the operator."""

import contextlib
import copy
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from disposable import ENVIRONMENT, ROOT, DisposableDatabase, FixtureFailure, docker

from query_passport.contract import ContractError, respond
from query_passport.executor import (
    binding_directory,
    private_directory,
    run_verification,
    target_snapshot,
    validate_binding,
)
from query_passport.verify_worker import CHECK_NAMES

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 to create a new isolated PostgreSQL fixture",
)


@pytest.fixture(scope="module")
def database():
    fixture = DisposableDatabase.create()
    try:
        yield fixture
    finally:
        fixture.close()


@pytest.fixture(scope="module")
def installed_cli():
    uv = shutil.which("uv")
    if uv is None:
        raise FixtureFailure("uv is required for installed CLI verification")
    with tempfile.TemporaryDirectory(prefix="query-passport-installed-") as temporary:
        directory = Path(temporary)
        environment = {**ENVIRONMENT, "UV_CACHE_DIR": str(directory / "cache")}

        def run(*arguments):
            result = subprocess.run(
                [uv, "--no-config", *arguments],
                cwd=directory,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
            if result.returncode:
                raise FixtureFailure("Installed CLI package setup failed")

        run(
            "build",
            "--wheel",
            "--out-dir",
            str(directory / "dist"),
            "--python",
            sys.executable,
            "--no-python-downloads",
            str(ROOT),
        )
        wheels = list((directory / "dist").glob("*.whl"))
        if len(wheels) != 1:
            raise FixtureFailure("Installed CLI requires exactly one built wheel")
        virtualenv = directory / "runtime"
        run("venv", "--python", sys.executable, "--no-python-downloads", str(virtualenv))
        run(
            "pip",
            "install",
            "--python",
            str(virtualenv / "bin/python"),
            "--no-deps",
            "--offline",
            str(wheels[0]),
        )
        yield virtualenv / "bin/query-passport"


@contextlib.contextmanager
def own_operator_binding(binding):
    """Install one exclusive fixture alias, preserving unrelated operator state."""
    directory = binding_directory()
    descriptors = []
    created = []
    filename = binding["request"]["target_alias"] + ".json"
    installed = None
    try:
        parent = private_directory(str(directory.parents[2]))
        descriptors.append(parent)
        for component in directory.parts[-3:]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                child = os.open(component, flags, dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=parent)
                child = os.open(component, flags, dir_fd=parent)
                created.append((parent, component, os.fstat(child)))
            descriptors.append(child)
            info = os.fstat(child)
            if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                raise FixtureFailure("Operator binding directory has unsafe ownership or mode")
            parent = child
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise FixtureFailure("Existing operator binding directory must already be private")
        descriptor = os.open(
            filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        installed = (parent, os.fstat(descriptor))
        with os.fdopen(descriptor, "w") as stream:
            json.dump(binding, stream)
        yield
    finally:
        if installed is not None:
            parent, original = installed
            current = os.stat(filename, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise FixtureFailure("Owned test binding changed; cleanup stopped")
            os.unlink(filename, dir_fd=parent)
        for parent, component, original in reversed(created):
            current = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                try:
                    os.rmdir(component, dir_fd=parent)
                except OSError as error:
                    if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                        raise
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def test_actual_query_man_runtime_verifies_tls_identity_and_read_only_connection(database):
    validate_binding(database.binding, database.request)
    snapshot = target_snapshot(database.binding)
    result = run_verification(database.binding, database.request)
    assert result["status"] == "succeeded", result
    assert result == {
        "status": "succeeded",
        "checks": dict.fromkeys(CHECK_NAMES, "passed"),
        "error": None,
    }
    assert target_snapshot(database.binding) == snapshot
    assert database.request["source_count"] == 0
    assert (
        database.sql(
            "SELECT count(*) FROM pg_roles WHERE rolname='passport_check' AND rolcanlogin "
            "AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit "
            "AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=2"
        ).strip()
        == b"1"
    )


def test_live_public_result_keeps_zero_source_and_application_status_separate(
    database, monkeypatch
):
    import query_passport.executor as executor

    monkeypatch.setattr(executor, "load_binding", lambda request: database.binding)
    response = respond("verify", database.request)
    assert response["status"] == "succeeded"
    assert response["errors"] == []
    assert response["scope"] == "database-only"
    result = response["result"]
    assert result["mode"] == "live"
    assert result["source_count"] == 0
    for field in ("target_identity", "db_connectivity", "authentication", "certificate_validation"):
        assert result[field] == "passed"
    for field in (
        "source_inventory",
        "source_admission",
        "reader_permissions",
        "application_readiness",
        "query_man_validation",
        "deployment",
    ):
        assert result[field] == "not_checked"


@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        ("wrong-server-ca", "TLS_VERIFICATION_FAILED"),
        ("wrong-hostname", "TLS_VERIFICATION_FAILED"),
        ("wrong-client-ca", "CLIENT_AUTHENTICATION_FAILED"),
        ("wrong-dn", "CLIENT_AUTHENTICATION_FAILED"),
        ("wrong-key", "CLIENT_AUTHENTICATION_FAILED"),
        ("expired", "CLIENT_AUTHENTICATION_FAILED"),
        ("wrong-database", "CLIENT_AUTHENTICATION_FAILED"),
        ("wrong-user", "CLIENT_AUTHENTICATION_FAILED"),
        ("missing-certificate", "CREDENTIAL_ACCESS_DENIED"),
        ("world-readable-key", "CREDENTIAL_ACCESS_DENIED"),
    ],
)
def test_real_bad_credentials_and_unauthorized_targets_fail_closed(database, probe, expected):
    if probe in ("expired", "wrong-client-ca"):
        assert database.fault_evidence[probe] is True
    binding, request = database.for_probe(probe)
    result = run_verification(binding, request)
    assert result["status"] == "failed"
    assert result["error"] == expected
    assert result["checks"]["read_only_transaction"] == "not_checked"
    serialized = json.dumps(result)
    for forbidden in (
        "BEGIN CERTIFICATE",
        "PRIVATE KEY",
        str(database.directory),
        "CN=query-passport",
        "psycopg",
        "Traceback",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize("probe", ["missing-certificate", "plaintext"])
def test_server_itself_refuses_missing_certificate_and_plaintext(database, probe):
    assert database.authentication_probe(probe) == {
        "outcome": "rejected",
        "error": "CLIENT_AUTHENTICATION_FAILED",
    }


def test_unrelated_runtime_uid_cannot_read_private_key(database):
    source = (
        "import json,os\n"
        "try:\n"
        "    descriptor = os.open('/credentials/client.key', os.O_RDONLY)\n"
        "except PermissionError:\n"
        "    readable = False\n"
        "else:\n"
        "    os.close(descriptor)\n"
        "    readable = True\n"
        "print(json.dumps({'readable': readable}))\n"
    )
    result = json.loads(
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--log-driver",
                "none",
                "--user",
                "10002:10002",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--mount",
                "type=bind,src=" + str(database.bundles["valid"]) + ",dst=/credentials,readonly",
                "--entrypoint",
                "/usr/bin/env",
                database.runtime_image,
                "-i",
                "PATH=/usr/bin:/bin",
                "/app/.venv/bin/python",
                "-I",
                "-c",
                source,
            ]
        )
    )
    assert result == {"readable": False}


@pytest.mark.parametrize("field", ["container_id", "database_image_id", "network_id", "hostaddr"])
def test_bound_target_drift_fails_before_runtime_starts(database, field, monkeypatch):
    import query_passport.executor as executor

    binding = copy.deepcopy(database.binding)
    binding[field] = (
        "127.0.0.1"
        if field == "hostaddr"
        else ("sha256:" + "0" * 64 if field == "database_image_id" else "0" * 64)
    )
    calls = []
    original = executor.docker

    def bounded(args, **kwargs):
        calls.append(args)
        return original(args, **kwargs)

    monkeypatch.setattr(executor, "docker", bounded)
    with pytest.raises(ContractError) as failed:
        run_verification(binding, database.request)
    assert failed.value.code == "TARGET_MISMATCH"
    assert not any(command[0] == "run" for command in calls)


def test_offline_plan_stays_offline_after_real_database_verification(database):
    result = respond("plan", database.request)
    assert result["result"]["executable"] is False
    assert result["result"]["db_connectivity"] == "not_checked"
    assert result["result"]["source_admission"] == "not_checked"
    assert result["result"]["application_readiness"] == "not_checked"


@pytest.mark.parametrize("probe", ["valid", "expired", "wrong-client-ca"])
def test_installed_wheel_cli_uses_real_operator_binding_and_safe_live_json(
    database, installed_cli, probe
):
    capability_process = subprocess.run(
        [str(installed_cli), "capabilities"],
        cwd=installed_cli.parent,
        env=ENVIRONMENT,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert capability_process.returncode == 0
    assert capability_process.stderr == b""
    capability = json.loads(capability_process.stdout)
    assert capability["contract_version"] == "1"
    assert 1 in capability["result"]["supported_contract_majors"]
    assert "connection.verify.v2" in capability["result"]["capabilities"]
    binding, request = database.for_probe(probe)
    request["target_alias"] = "fixture-cli-" + uuid.uuid4().hex
    binding["request"] = copy.deepcopy(request)
    with own_operator_binding(binding):
        process = subprocess.run(
            [str(installed_cli), "verify", "--request", "-"],
            cwd=installed_cli.parent,
            input=json.dumps(request).encode(),
            env=ENVIRONMENT,
            capture_output=True,
            timeout=65,
            check=False,
        )
    assert process.stderr == b""
    assert len(process.stdout) <= 16384
    assert process.stdout.count(b"\n") == 1
    response = json.loads(process.stdout)
    assert response["contract_version"] == "1"
    assert response["command"] == "verify"
    assert response["scope"] == "database-only"
    result = response["result"]
    assert result["source_count"] == 0
    assert result["mode"] == "live"
    assert result["application_readiness"] == "not_checked"
    assert result["source_admission"] == "not_checked"
    if probe == "valid":
        assert process.returncode == 0
        assert response["status"] == "succeeded"
        assert response["errors"] == []
        assert result["checks"] == dict.fromkeys(CHECK_NAMES, "passed")
    else:
        assert database.fault_evidence[probe] is True
        assert process.returncode == 8
        assert response["status"] == "failed"
        assert response["errors"][0]["code"] == "CLIENT_AUTHENTICATION_FAILED"
        assert result["checks"]["credential_permissions"] == "passed"
        assert result["db_connectivity"] == "not_checked"
    for forbidden in (
        "BEGIN CERTIFICATE",
        "PRIVATE KEY",
        str(database.directory),
        str(binding_directory()),
        "CN=query-passport",
        "psycopg",
        "Traceback",
    ):
        assert forbidden.encode() not in process.stdout
