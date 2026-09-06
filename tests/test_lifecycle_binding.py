import copy
import json
import os
import time
from pathlib import Path

import pytest

from query_passport.contract import ContractError
from query_passport.executor import load_binding
from query_passport.lifecycle_binding import (
    OPERATIONS,
    validate_lifecycle_binding,
    verification_projection,
)

REQUEST = json.loads((Path(__file__).resolve().parents[1] / "examples/request.json").read_text())


@pytest.fixture
def binding():
    return {
        "binding_version": 2,
        "allowed_uid": os.geteuid(),
        "expires_at": int(time.time()) + 3600,
        "operations": sorted(OPERATIONS),
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
        "credential_dir": "/synthetic/delivery",
        "admin": {
            "uid": 999,
            "gid": 999,
            "socket_directory": "/var/run/postgresql",
            "pgdata": "/var/lib/postgresql/data",
            "network_cidr": "172.22.0.0/24",
            "connection_limit": 2,
        },
        "lifecycle": {
            "authority_dir": "/synthetic/authority",
            "authority_id": "test-authority",
            "generations_dir": "/synthetic/generations",
            "server_ca_file": "/synthetic/server/ca.crt",
            "lifetime_days": 30,
            "allow_initialize_authority": True,
            "allow_create_check_role": True,
        },
    }


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_exact_operator_binding_authorizes_only_named_operation(binding, operation):
    validate_lifecycle_binding(binding, REQUEST, operation)
    binding["operations"].remove(operation)
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, operation)
    assert error.value.code == "AUTHORIZATION_REQUIRED"


@pytest.mark.parametrize("value", [[], ["prepare", "prepare"], ["shell"], [True], "apply"])
def test_operation_list_is_closed(binding, value):
    binding["operations"] = value
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_delivery_requires_real_verification_authorization(binding):
    binding["operations"].remove("verify")
    with pytest.raises(ContractError, match="binding"):
        validate_lifecycle_binding(binding, REQUEST, "deliver")


@pytest.mark.parametrize(
    "field,value",
    [
        ("authority_dir", "/synthetic/generations/ca"),
        ("generations_dir", "/synthetic/delivery"),
        ("server_ca_file", "/synthetic/authority/server.crt"),
        ("authority_dir", "/tmp/../etc"),
        ("authority_dir", "/synthetic/x,readonly=false"),
        ("authority_dir", "//etc"),
        ("authority_dir", "/synthetic/authority/"),
        ("authority_id", "bad;command"),
        ("lifetime_days", True),
        ("lifetime_days", 91),
        ("allow_initialize_authority", "true"),
        ("allow_create_check_role", False),
        ("private_canary", "never-print-this"),
    ],
)
def test_private_configuration_rejection_does_not_echo_values(binding, field, value):
    binding["lifecycle"][field] = value
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"
    assert "never-print-this" not in str(error.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 0),
        ("uid", True),
        ("gid", -1),
        ("socket_directory", "/tmp/other"),
        ("network_cidr", "0.0.0.0/0"),
        ("network_cidr", "172.22.0.1/24"),
        ("network_cidr", "192.0.2.0/24"),
        ("connection_limit", 100),
    ],
)
def test_admin_scope_is_strict(binding, field, value):
    binding["admin"][field] = value
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_explicit_admin_database_role_preserves_os_identity_and_binding(binding):
    binding["admin"]["username"] = "query_man_admin"
    before = copy.deepcopy(binding)
    validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert binding == before
    projected = verification_projection(binding, "/synthetic/bundle")
    assert projected["username"] == "passport_check" and "admin" not in projected


@pytest.mark.parametrize("value", [None, True, "", "-postgres", "postgres;SELECT", "a" * 64])
def test_admin_database_role_cannot_inject_arguments_or_sql(binding, value):
    binding["admin"]["username"] = value
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_monitoring_review_is_private_and_target_bound(binding):
    from query_passport.local_lifecycle import binding_digest

    original = binding_digest(binding)
    binding["admin"]["monitoring"] = {
        "extension": "pg_stat_statements",
        "digest": "sha256:" + "a" * 64,
    }
    validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert binding_digest(binding) != original
    assert "admin" not in verification_projection(binding, "/synthetic/bundle")


@pytest.mark.parametrize(
    "value",
    [
        True,
        {},
        {"extension": "other", "digest": "sha256:" + "a" * 64},
        {"extension": "pg_stat_statements", "digest": "any"},
        {"extension": "pg_stat_statements", "digest": "sha256:" + "a" * 64, "skip_audit": True},
    ],
)
def test_monitoring_review_cannot_disable_or_generalize_audit(binding, value):
    binding["admin"]["monitoring"] = value
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, REQUEST, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_private_binding_cannot_authorize_protected_or_other_target(binding):
    request = copy.deepcopy(REQUEST)
    request["profile"]["host"] = "other.example.test"
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, request, "prepare")
    assert error.value.code == "TARGET_MISMATCH"
    request["environment"] = "protected"
    binding["request"] = request
    with pytest.raises(ContractError) as error:
        validate_lifecycle_binding(binding, request, "prepare")
    assert error.value.code == "AUTHORIZATION_REQUIRED"


def test_m2_projection_has_no_mutation_configuration(binding):
    projected = verification_projection(binding, "/synthetic/versions/generation/bundle")
    assert projected["binding_version"] == 1 and projected["operations"] == ["verify"]
    assert "admin" not in projected and "lifecycle" not in projected


def test_loading_v2_requires_matching_operation(binding, tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path / (REQUEST["target_alias"] + ".json")
    path.write_text(json.dumps(binding))
    path.chmod(0o600)
    monkeypatch.setattr("query_passport.executor.binding_directory", lambda: tmp_path)
    assert load_binding(REQUEST, operation="prepare") == binding
    binding["operations"].remove("apply")
    path.write_text(json.dumps(binding))
    with pytest.raises(ContractError) as error:
        load_binding(REQUEST, operation="apply")
    assert error.value.code == "AUTHORIZATION_REQUIRED"
