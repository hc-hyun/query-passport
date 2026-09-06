import copy
import json
import os
import time
from pathlib import Path

import pytest

from query_passport import executor
from query_passport.contract import ContractError

REQUEST = json.loads((Path(__file__).resolve().parents[1] / "examples/request.json").read_text())


@pytest.fixture
def binding():
    return {
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
        "credential_dir": "/synthetic/credentials",
    }


def test_binding_is_separate_from_public_request(binding):
    executor.validate_binding(binding, REQUEST)


@pytest.mark.parametrize(
    "field,value",
    [
        ("allowed_uid", -1),
        ("allowed_uid", True),
        ("expires_at", 0),
        ("binding_version", True),
        ("operations", ["verify", "apply"]),
        ("container_id", "some-container"),
        ("network_name", 'x"}}'),
        ("runtime_image_id", "query-man:latest"),
        ("runtime_uid", 0),
        ("runtime_gid", 0),
        ("hostaddr", "host.example.test"),
        ("hostaddr", "1.2.3.4,5.6.7.8"),
        ("username", "role; DROP DATABASE x"),
        ("credential_dir", "/tmp/x,readonly=false"),
        ("credential_dir", "/tmp/../x"),
        ("expected_dn", "anything"),
    ],
)
def test_untrusted_binding_rejected_before_docker(binding, field, value, monkeypatch):
    binding[field] = value
    monkeypatch.setattr(executor, "docker", lambda *args, **kwargs: pytest.fail("Must not execute"))
    with pytest.raises(ContractError) as error:
        executor.run_verification(binding, REQUEST)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "other.example.test"),
        ("port", 5433),
        ("database", "other_db"),
        ("id", "other-db"),
    ],
)
def test_target_mismatch_rejected_before_docker(binding, field, value, monkeypatch):
    request = copy.deepcopy(REQUEST)
    request["profile"][field] = value
    monkeypatch.setattr(executor, "docker", lambda *args, **kwargs: pytest.fail("Must not execute"))
    with pytest.raises(ContractError) as error:
        executor.run_verification(binding, request)
    assert error.value.code == "TARGET_MISMATCH"


def test_local_file_cannot_authorize_protected_environment(binding):
    request = copy.deepcopy(REQUEST)
    request["environment"] = "protected"
    binding["request"] = request
    with pytest.raises(ContractError) as error:
        executor.validate_binding(binding, request)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_exact_container_network_and_route(binding, monkeypatch):
    observed = {
        "id": binding["container_id"],
        "image": binding["database_image_id"],
        "network_id": binding["network_id"],
        "hostaddr": binding["hostaddr"],
        "running": True,
        "started_at": binding["container_started_at"],
    }
    calls = []

    def inspect(args):
        calls.append(args)
        return json.dumps(observed).encode()

    monkeypatch.setattr(executor, "docker", inspect)
    digest = executor.target_snapshot(binding)
    assert digest.startswith("sha256:")
    assert calls[0][-1] == binding["container_id"]
    assert ".Config.Env" not in calls[0][-2]
    observed["hostaddr"] = "172.22.0.3"
    with pytest.raises(ContractError) as error:
        executor.target_snapshot(binding)
    assert error.value.code == "TARGET_MISMATCH"


def test_private_operator_binding_file(binding, tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    filename = tmp_path / (REQUEST["target_alias"] + ".json")
    filename.write_text(json.dumps(binding))
    filename.chmod(0o600)
    monkeypatch.setattr(executor, "binding_directory", lambda: tmp_path)
    assert executor.load_binding(REQUEST) == binding
    filename.chmod(0o644)
    with pytest.raises(ContractError) as error:
        executor.load_binding(REQUEST)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_missing_binding_is_not_permission(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "binding_directory", lambda: tmp_path)
    with pytest.raises(ContractError) as error:
        executor.load_binding(REQUEST)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_alias_cannot_escape_binding_directory(monkeypatch):
    request = copy.deepcopy(REQUEST)
    request["target_alias"] = "../../request"
    monkeypatch.setattr(os, "open", lambda *args, **kwargs: pytest.fail("Must not read a file"))
    with pytest.raises(ContractError):
        executor.load_binding(request)


@pytest.mark.parametrize("malformation", ["extra", "message", "missing", "unchecked", "unknown"])
def test_worker_result_is_closed_and_never_echoes_provider_data(malformation):
    from query_passport.verify_worker import CHECK_NAMES

    result = {"status": "succeeded", "checks": dict.fromkeys(CHECK_NAMES, "passed"), "error": None}
    if malformation == "extra":
        result["secret"] = "PRIVATE_PROVIDER_DIAGNOSTIC"
    elif malformation == "message":
        result["error"] = "PRIVATE_PROVIDER_DIAGNOSTIC"
    elif malformation == "missing":
        del result["checks"]["tls"]
    elif malformation == "unchecked":
        result["checks"]["tls"] = "not_checked"
    else:
        result["checks"]["tls"] = "PRIVATE_PROVIDER_DIAGNOSTIC"
    with pytest.raises(ContractError) as error:
        executor.normalize_worker_result(json.dumps(result).encode())
    assert error.value.code == "EXECUTOR_FAILED"
    assert "PRIVATE_PROVIDER_DIAGNOSTIC" not in str(error.value)


def test_restarted_container_is_not_same_generation(binding, monkeypatch):
    observed = {
        "id": binding["container_id"],
        "image": binding["database_image_id"],
        "network_id": binding["network_id"],
        "hostaddr": binding["hostaddr"],
        "running": True,
        "started_at": "2026-09-05T09:09:09.000000000Z",
    }
    monkeypatch.setattr(executor, "docker", lambda args: json.dumps(observed).encode())
    with pytest.raises(ContractError) as error:
        executor.target_snapshot(binding)
    assert error.value.code == "TARGET_MISMATCH"


def test_in_place_credential_change_is_detected(tmp_path):
    # Synthetic bytes; this tests metadata drift without parsing credential material.
    path = tmp_path / "client.key"
    path.write_bytes(b"synthetic-before")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        before = executor.credential_revision(descriptor)
        path.write_bytes(b"synthetic-after")
        assert executor.credential_revision(descriptor) != before
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "failure,cleanup",
    [
        (ContractError("TIMEOUT"), "absent"),
        (ContractError("INTERRUPTED"), "remaining"),
        (KeyboardInterrupt(), "observation_failed"),
        (SystemExit(1), "interrupted"),
    ],
)
def test_verification_uncertainty_survives_cleanup_failure(
    binding, tmp_path, monkeypatch, failure, cleanup
):
    binding["credential_dir"] = str(tmp_path)
    for name in ("ca.crt", "client.crt", "client.key"):
        (tmp_path / name).write_bytes(b"synthetic offline fixture")
    monkeypatch.setattr(executor, "target_snapshot", lambda _: "fixed-generation")
    calls = []

    def docker(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "run":
            raise failure
        assert kwargs == {"timeout": 5}
        if args[0] == "rm":
            if cleanup == "interrupted":
                raise KeyboardInterrupt()
            raise ContractError("EXECUTOR_FAILED")
        assert args[0] == "ps"
        if cleanup == "observation_failed":
            raise ContractError("EXECUTOR_FAILED")
        return b"" if cleanup == "absent" else b"remaining"

    monkeypatch.setattr(executor, "docker", docker)
    with pytest.raises(type(failure)) as caught:
        executor.run_verification(binding, REQUEST)
    assert caught.value is failure
    assert [call[0][0] for call in calls] == ["run", "rm", "ps"]
    name = calls[0][0][calls[0][0].index("--name") + 1]
    assert calls[1][0] == ["rm", "-f", name]
    assert calls[2][0][3] == "name=^/" + name + "$"


@pytest.mark.parametrize(
    "failure,stage,remaining",
    [
        (ContractError("TIMEOUT"), "rm", b""),
        (ContractError("INTERRUPTED"), "rm", b"remaining"),
        (KeyboardInterrupt(), "ps", b""),
        (SystemExit(1), "ps", b"remaining"),
    ],
)
def test_cleanup_first_uncertainty_is_preserved_even_after_reconciliation(
    monkeypatch, failure, stage, remaining
):
    calls = []

    def docker(args, **kwargs):
        calls.append(args[0])
        assert kwargs == {"timeout": 5}
        if args[0] == stage:
            raise failure
        if args[0] == "rm":
            raise ContractError("EXECUTOR_FAILED")
        return remaining

    monkeypatch.setattr(executor, "docker", docker)
    with pytest.raises(type(failure)) as caught:
        executor.cleanup_container("query-passport-verify-" + "a" * 32)
    assert caught.value is failure
    assert calls == ["rm", "ps"]


@pytest.mark.parametrize("remaining", [b"", b"remaining"])
def test_cleanup_known_failure_requires_positive_absence_observation(monkeypatch, remaining):
    def docker(args, **kwargs):
        if args[0] == "rm":
            raise ContractError("EXECUTOR_FAILED")
        return remaining

    monkeypatch.setattr(executor, "docker", docker)
    name = "query-passport-verify-" + "a" * 32
    if remaining:
        with pytest.raises(ContractError) as caught:
            executor.cleanup_container(name)
        assert caught.value.code == "EXECUTOR_CLEANUP_FAILED"
    else:
        assert executor.cleanup_container(name) is None


@pytest.mark.parametrize("name", ["existing-database", "query-passport-verify-*", ""])
def test_cleanup_cannot_select_unowned_container_names(monkeypatch, name):
    monkeypatch.setattr(executor, "docker", lambda *_args, **_kwargs: pytest.fail("No Docker"))
    with pytest.raises(ContractError) as caught:
        executor.cleanup_container(name)
    assert caught.value.code == "AUTHORIZATION_REQUIRED"


def test_worker_timeout_result_is_not_replaced_by_cleanup_failure(binding, tmp_path, monkeypatch):
    from query_passport.verify_worker import CHECK_NAMES

    binding["credential_dir"] = str(tmp_path)
    for name in ("ca.crt", "client.crt", "client.key"):
        (tmp_path / name).write_bytes(b"synthetic offline fixture")
    result = {
        "status": "failed",
        "checks": dict.fromkeys(CHECK_NAMES, "not_checked"),
        "error": "TIMEOUT",
    }
    monkeypatch.setattr(executor, "target_snapshot", lambda _: "fixed-generation")

    def docker(args, **kwargs):
        if args[0] == "run":
            return json.dumps(result).encode()
        raise ContractError("EXECUTOR_FAILED")

    monkeypatch.setattr(executor, "docker", docker)
    assert executor.run_verification(binding, REQUEST) == result
