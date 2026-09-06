"""Fixed-adapter control flow tests; all Docker/SQL/filesystem effects are mocked."""

import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from query_passport import db_admin as admin
from query_passport.contract import ContractError
from query_passport.db_config import config_digest, owned_block

OPERATION = "a" * 32
CA_DIGEST = "sha256:" + "b" * 64
TARGET = "sha256:" + "c" * 64
CANARY = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"


def binding():
    return {
        "container_id": "d" * 64,
        "username": "passport_check",
        "expected_dn": "CN=passport-test",
        "request": {
            "environment": "local-synthetic",
            "source_count": 0,
            "profile": {"database": "query_man", "port": 5432},
        },
        "admin": {
            "uid": 999,
            "gid": 999,
            "socket_directory": "/var/run/postgresql",
            "pgdata": "/var/lib/postgresql/data",
            "network_cidr": "192.0.2.0/24",
            "connection_limit": 2,
        },
    }


def before():
    return {
        "version": 180006,
        "encoding": "UTF8",
        "database": "query_man",
        "admin": True,
        "ssl": True,
        "pgdata": "/var/lib/postgresql/data",
        "hba_path": "/var/lib/postgresql/data/pg_hba.conf",
        "ident_path": "/var/lib/postgresql/data/pg_ident.conf",
        "hba": "# original\r\nlocal all postgres trust",
        "ident": "# original mapping\n",
        "auto_size": 54,
        "auto_digest": "sha256:" + "e" * 64,
        "ca": {
            "setting": "client-ca.crt",
            "source": "configuration file",
            "sourcefile": "/var/lib/postgresql/data/postgresql.auto.conf",
            "pending_restart": False,
        },
        "ca_digest": "sha256:" + "f" * 64,
        "ca_size": 1200,
        "parse_ok": True,
        "public_audit": dict.fromkeys(admin._AUDIT_FIELDS, False),
        "role": None,
        "target_snapshot": TARGET,
    }


def own_role():
    return {
        "oid": 16402,
        "login": False,
        "superuser": False,
        "createdb": False,
        "createrole": False,
        "inherit": False,
        "replication": False,
        "bypassrls": False,
        "connection_limit": 2,
        "password_set": False,
        "valid_until_set": False,
        "memberships": 0,
        "marker": "query-passport:" + OPERATION,
        "settings": [
            {
                "database": "query_man",
                "values": [
                    "default_transaction_read_only=on",
                    "idle_in_transaction_session_timeout=5s",
                    "lock_timeout=1s",
                    "search_path=pg_catalog",
                    "statement_timeout=5s",
                ],
            }
        ],
        "audit": dict.fromkeys(admin._AUDIT_FIELDS, False),
    }


class SimulatedDatabase:
    def __init__(self):
        self.binding = binding()
        self.original = before()
        self.current = copy.deepcopy(self.original)
        self.plan = {"before": copy.deepcopy(self.original)}
        self.events = []
        self.fail_phase = None
        self.failure = ContractError("EXECUTOR_FAILED")
        self.auto_present = False
        self.auto_base = self.original["auto_digest"]
        self.ca_installed = False

    def event(self, name):
        self.events.append(name)
        if self.fail_phase == name:
            self.fail_phase = None
            raise self.failure

    def snapshot(self, _binding):
        return copy.deepcopy(self.current)

    def sql(self, _binding, statement):
        if "CREATE ROLE" in statement:
            self.event("create-nologin")
            assert self.current["role"] is None
            self.current["role"] = own_role()
            return {"status": "created"}
        if "'status','disabled'" in statement:
            self.event("disable")
            assert self.current["role"]["marker"] == "query-passport:" + OPERATION
            self.current["role"]["login"] = False
            return {"status": "disabled"}
        if "'status','enabled'" in statement:
            self.event("enable")
            assert self.current["role"]["login"] is False
            self.current["role"]["login"] = True
            return {"status": "enabled"}
        self.event("check-rules")
        return {"ident": True, "hba": True, "valid": True}

    def shell(self, _binding, script, arguments, data):
        if script == admin._CA_SCRIPT:
            self.event("install-ca")
            assert self.current["role"]["login"] is False
            self.ca_installed = True
            return {"status": "present", "digest": CA_DIGEST}
        if script == admin._CAS_SCRIPT:
            filename, expected, _operation = arguments
            field = "hba" if filename == "pg_hba.conf" else "ident"
            self.event("replace-" + field)
            assert self.current["role"] is None or self.current["role"]["login"] is False
            if config_digest(self.current[field])[7:] != expected:
                raise ContractError("TARGET_DRIFT")
            self.current[field] = data.decode()
            return {"status": "written"}
        assert script == admin._AUTO_SCRIPT
        action = arguments[0]
        self.event("auto-" + action)
        prior = self.auto_present
        if action == "install":
            assert self.current["role"]["login"] is False
            if self.auto_base != "sha256:" + arguments[2]:
                raise ContractError("TARGET_DRIFT")
            self.auto_present = True
            self.current["auto_digest"] = "sha256:" + "1" * 64
        elif action == "remove":
            self.auto_present = False
            self.current["auto_digest"] = self.auto_base
        return {
            "state": "present" if prior else "absent",
            "base_digest": self.auto_base,
            "digest": self.current["auto_digest"],
        }

    def reload(self, _binding, expected_ca):
        self.event("reload")
        self.current["ca"]["setting"] = expected_ca
        self.current["ca_digest"] = CA_DIGEST if self.auto_present else self.original["ca_digest"]


@pytest.fixture
def simulated(monkeypatch):
    server = SimulatedDatabase()
    monkeypatch.setattr(admin, "snapshot", server.snapshot)
    monkeypatch.setattr(admin, "_sql", server.sql)
    monkeypatch.setattr(admin, "_shell", server.shell)
    monkeypatch.setattr(admin, "_reload", server.reload)
    certificate = SimpleNamespace(
        not_valid_before_utc=datetime.now(UTC) - timedelta(days=1),
        not_valid_after_utc=datetime.now(UTC) + timedelta(days=1),
        extensions=SimpleNamespace(
            get_extension_for_class=lambda _: SimpleNamespace(value=SimpleNamespace(ca=True))
        ),
    )
    monkeypatch.setattr(admin.x509, "load_pem_x509_certificates", lambda _: [certificate])

    def forbidden(*_args, **_kwargs):
        pytest.fail("Mock-only test attempted Docker execution")

    monkeypatch.setattr(admin.executor, "docker", forbidden)
    return server


def provision(server):
    return admin.apply(server.binding, server.plan, OPERATION, b"synthetic-public-ca")


def test_login_is_last_after_owned_rules_ca_and_reload(simulated):
    result = provision(simulated)
    assert result == {
        "status": "applied",
        "configuration": "reconciled",
        "role": "login",
        "db_connectivity": "not_checked",
        "ca_digest": CA_DIGEST,
    }
    assert simulated.events.index("create-nologin") < simulated.events.index("install-ca")
    assert simulated.events.index("install-ca") < simulated.events.index("replace-hba")
    assert simulated.events.index("replace-ident") < simulated.events.index("replace-hba")
    assert (
        simulated.events.index("replace-hba")
        < simulated.events.index("reload")
        < simulated.events.index("enable")
    )
    assert simulated.binding["request"]["source_count"] == 0


@pytest.mark.parametrize(
    "phase",
    [
        "install-ca",
        "replace-ident",
        "replace-hba",
        "auto-install",
        "check-rules",
        "reload",
        "enable",
    ],
)
def test_partial_failure_returns_original_error_and_rerun_avoids_duplicate_role(simulated, phase):
    simulated.fail_phase = phase
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "EXECUTOR_FAILED"
    assert simulated.current["role"]["login"] is False
    assert provision(simulated)["status"] == "applied"
    assert simulated.events.count("create-nologin") == 1


@pytest.mark.parametrize(
    "failure",
    [ContractError("TIMEOUT"), ContractError("INTERRUPTED"), KeyboardInterrupt(), SystemExit(1)],
)
def test_uncertain_mutation_outcome_keeps_original_timeout_or_interrupt(simulated, failure):
    simulated.fail_phase = "install-ca"
    simulated.failure = failure
    with pytest.raises(type(failure)) as caught:
        provision(simulated)
    assert caught.value is failure
    assert simulated.current["role"]["login"] is False


@pytest.mark.parametrize("field", ["hba", "ident", "target_snapshot"])
def test_plan_drift_prevents_role_creation(simulated, field):
    simulated.current[field] += "changed"
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "TARGET_DRIFT"
    assert simulated.current["role"] is None
    assert "create-nologin" not in simulated.events


def test_auto_conf_drift_prevents_role_creation(simulated):
    simulated.auto_base = "sha256:" + "2" * 64
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "TARGET_DRIFT"
    assert simulated.current["role"] is None


@pytest.mark.parametrize("audit_field", sorted(admin._AUDIT_FIELDS))
def test_public_effective_access_blocks_before_or_after_planning(simulated, audit_field):
    initial = copy.deepcopy(simulated.original)
    initial["public_audit"][audit_field] = True
    with pytest.raises(ContractError) as caught:
        admin.validate_provision(simulated.binding, initial)
    assert caught.value.code == "PERMISSION_DENIED"
    simulated.current["public_audit"][audit_field] = True
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "PERMISSION_DENIED"
    assert simulated.current["role"] is None


def test_foreign_existing_role_is_not_altered(simulated):
    role = own_role()
    role["marker"] = None
    role["login"] = True
    simulated.current["role"] = role
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "PERMISSION_DENIED"
    assert simulated.current["role"]["login"] is True
    assert "disable" not in simulated.events
    assert simulated.current["role"]["login"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("superuser", True),
        ("inherit", True),
        ("password_set", True),
        ("replication", True),
        ("memberships", 1),
        ("memberships", False),
        ("connection_limit", -1),
        ("connection_limit", 2.0),
        ("oid", "16402"),
        ("oid", True),
        ("login", 0),
        ("settings", []),
    ],
)
def test_unsafe_owned_role_cannot_be_resumed(simulated, field, value):
    simulated.current["role"] = own_role()
    simulated.current["role"][field] = value
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "PERMISSION_DENIED"
    assert "enable" not in simulated.events


def test_verify_requires_persisted_trust_digest_and_rejects_same_path_trust_drift(simulated):
    provision(simulated)
    with pytest.raises(ContractError) as caught:
        admin.verify_applied(simulated.binding, simulated.plan, OPERATION)
    assert caught.value.code == "AUTHORIZATION_REQUIRED"
    receipt = {**simulated.plan, "applied_ca_digest": CA_DIGEST}
    assert admin.verify_applied(simulated.binding, receipt, OPERATION)["status"] == "applied"
    simulated.current["ca_digest"] = "sha256:" + "4" * 64
    with pytest.raises(ContractError) as caught:
        admin.verify_applied(simulated.binding, receipt, OPERATION)
    assert caught.value.code == "TARGET_DRIFT"


def test_verify_rejects_rule_precedence_drift_but_allows_unrelated_suffix(simulated):
    provision(simulated)
    receipt = {**simulated.plan, "applied_ca_digest": CA_DIGEST}
    simulated.current["hba"] += "\n# benign unrelated note"
    assert admin.verify_applied(simulated.binding, receipt, OPERATION)["status"] == "applied"
    simulated.current["hba"] = "host all all all trust\n" + simulated.current["hba"]
    with pytest.raises(ContractError) as caught:
        admin.verify_applied(simulated.binding, receipt, OPERATION)
    assert caught.value.code == "TARGET_DRIFT"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 170006),
        ("encoding", "LATIN1"),
        ("ssl", False),
        ("hba_path", "/unowned/hba.conf"),
        ("ident_path", "/unowned/ident.conf"),
    ],
)
def test_unsupported_server_or_config_layout_is_not_reinterpreted(field, value):
    initial = before()
    initial[field] = value
    with pytest.raises(ContractError) as caught:
        admin.validate_provision(binding(), initial)
    assert caught.value.code == "UNSUPPORTED_OPERATION"


def test_commandline_ca_override_rejected():
    initial = before()
    initial["ca"]["source"] = "command line"
    with pytest.raises(ContractError) as caught:
        admin.validate_provision(binding(), initial)
    assert caught.value.code == "UNSUPPORTED_OPERATION"


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 0),
        ("uid", True),
        ("gid", -1),
        ("connection_limit", -1),
        ("pgdata", "/data/../other"),
        ("socket_directory", CANARY),
        ("network_cidr", "192.0.2.3/24"),
    ],
)
def test_internal_binding_values_cannot_become_shell_or_sql(field, value):
    request = binding()
    request["admin"][field] = value
    with pytest.raises(ContractError):
        admin._binding(request)


@pytest.mark.parametrize("username", [None, "query_man_admin"])
def test_psql_transport_uses_fixed_socket_argv_and_stdin(monkeypatch, username):
    observed = []
    configured = binding()
    if username is not None:
        configured["admin"]["username"] = username
    initial = copy.deepcopy(configured)

    def docker(args, **kwargs):
        observed.append((args, kwargs))
        return b'{"ok":true}\n'

    monkeypatch.setattr(admin.executor, "docker", docker)
    assert admin._sql(configured, "SELECT json_build_object('ok',true);") == {"ok": True}
    args, options = observed[0]
    assert "--no-psqlrc" in args and "--no-password" in args
    assert args[args.index("--host") + 1] == "/var/run/postgresql"
    assert args[args.index("--username") + 1] == (username or "postgres")
    assert args[args.index("--user") + 1] == (
        f"{configured['admin']['uid']}:{configured['admin']['gid']}"
    )
    assert args[-2:] == ["--file", "-"]
    assert b"SET log_statement = 'none'" in options["stdin"]
    assert all("SELECT" not in part for part in args)
    assert configured == initial


@pytest.mark.parametrize("username", [None, "query_man_admin"])
def test_admin_username_normalization_changes_only_internal_return_copy(username):
    configured = binding()
    if username is not None:
        configured["admin"]["username"] = username
    original = copy.deepcopy(configured)
    normalized = admin._binding(configured)
    assert normalized["username"] == (username or "postgres")
    assert normalized is not configured["admin"]
    assert configured == original


@pytest.mark.parametrize(
    "username",
    [None, True, 1, [], {}, "", "Query_Admin", "admin-user", "user;select", "user\n", "a" * 64],
)
def test_admin_username_rejects_unsafe_values_before_executor(username, monkeypatch):
    configured = binding()
    configured["admin"]["username"] = username
    monkeypatch.setattr(admin.executor, "docker", lambda *_a, **_k: pytest.fail("No execution"))
    with pytest.raises(ContractError) as caught:
        admin._sql(configured, "SELECT 1;")
    assert caught.value.code == "AUTHORIZATION_REQUIRED"


@pytest.mark.parametrize("username", [None, "query_man_admin"])
def test_snapshot_admin_predicate_binds_both_identities_and_superuser(monkeypatch, username):
    configured = binding()
    if username is not None:
        configured["admin"]["username"] = username
    observed = before()
    observed.pop("target_snapshot")
    statements = []

    def sql(_binding, statement):
        statements.append(statement)
        return copy.deepcopy(observed)

    monkeypatch.setattr(admin, "_sql", sql)
    monkeypatch.setattr(admin.executor, "target_snapshot", lambda _: TARGET)
    assert admin.snapshot(configured)["admin"] is True
    predicate = statements[0].split("'admin',", 1)[1].split("'ssl',", 1)[0]
    expected = username or "postgres"
    assert f"current_user = '{expected}' AND session_user = '{expected}'" in predicate
    assert "FROM pg_roles WHERE rolname=current_user AND rolsuper" in predicate


@pytest.mark.parametrize("refused_admin", [False, None, "true", 1])
def test_unconfirmed_admin_identity_or_superuser_cannot_prepare_or_apply(simulated, refused_admin):
    # The fixed SQL predicate is false for a different session/current role or a
    # non-superuser; no truthy malformed catalog result may authorize mutation.
    simulated.current["admin"] = refused_admin
    with pytest.raises(ContractError) as caught:
        admin.validate_provision(simulated.binding, simulated.current)
    assert caught.value.code == "UNSUPPORTED_OPERATION"
    with pytest.raises(ContractError):
        provision(simulated)
    assert "create-nologin" not in simulated.events


def test_snapshot_is_observational_for_existing_roles(monkeypatch):
    observed = before()
    observed.pop("target_snapshot")
    observed["role"] = own_role()
    observed["role"]["marker"] = None
    monkeypatch.setattr(admin, "_sql", lambda *_: copy.deepcopy(observed))
    monkeypatch.setattr(admin.executor, "target_snapshot", lambda _: TARGET)
    result = admin.snapshot(binding())
    assert result["role"] is not None
    with pytest.raises(ContractError) as caught:
        admin.validate_provision(binding(), result)
    assert caught.value.code == "PERMISSION_DENIED"


def test_snapshot_rejects_secret_bearing_hba_without_echo(monkeypatch):
    observed = before()
    observed.pop("target_snapshot")
    observed["hba"] = "host all all all ldap ldapbindpasswd=" + CANARY
    monkeypatch.setattr(admin, "_sql", lambda *_: observed)
    monkeypatch.setattr(admin.executor, "target_snapshot", lambda _: TARGET)
    with pytest.raises(ContractError) as caught:
        admin.snapshot(binding())
    assert caught.value.code == "UNSUPPORTED_OPERATION" and CANARY not in str(caught.value)


def test_reload_requires_new_observed_reload_generation(monkeypatch):
    replies = iter(
        [
            {"loaded_at": 100},
            {"reload": True},
            {"loaded_at": 100, "setting": "new-ca.crt", "valid": True},
            {"loaded_at": 101, "setting": "new-ca.crt", "valid": True},
        ]
    )
    monkeypatch.setattr(admin, "_sql", lambda *_: next(replies))
    admin._reload(binding(), "new-ca.crt")


def test_reload_without_postmaster_observation_fails_closed(monkeypatch):
    replies = iter(
        [{"loaded_at": 100}, {"reload": True}]
        + [{"loaded_at": 100, "setting": "new-ca.crt", "valid": True}] * 12
    )
    monkeypatch.setattr(admin, "_sql", lambda *_: next(replies))
    with pytest.raises(ContractError) as caught:
        admin._reload(binding(), "new-ca.crt")
    assert caught.value.code == "VERIFICATION_FAILED"


def test_owned_marker_not_added_to_unrelated_config_on_repeated_apply(simulated):
    provision(simulated)
    original = copy.deepcopy(simulated.current)
    assert provision(simulated)["status"] == "applied"
    assert simulated.current == original
    assert owned_block(simulated.current["hba"], "passport-" + OPERATION) is not None


def test_result_never_contains_private_configuration(simulated):
    result = provision(simulated)
    encoded = json.dumps(result)
    assert "pg_hba" not in encoded and "client-ca" not in encoded and "192.0.2" not in encoded
    assert "query_man" not in encoded and "passport_check" not in encoded


MONITORING_DIGEST = "sha256:" + "1" * 64


def enable_monitoring(server):
    server.binding["admin"]["monitoring"] = {
        "extension": "pg_stat_statements",
        "digest": MONITORING_DIGEST,
    }
    for observed in (server.original, server.plan["before"], server.current):
        observed["monitoring"] = {"valid": True, "digest": MONITORING_DIGEST}


@pytest.mark.parametrize(
    "monitoring",
    [
        None,
        True,
        [],
        {},
        {"extension": "pg_stat_statements"},
        {"digest": MONITORING_DIGEST},
        {"extension": "another_extension", "digest": MONITORING_DIGEST},
        {"extension": "pg_stat_statements", "digest": "sha256:" + "A" * 64},
        {"extension": "pg_stat_statements", "digest": MONITORING_DIGEST + "\n"},
        {"extension": "pg_stat_statements", "digest": True},
        {"extension": "pg_stat_statements", "digest": MONITORING_DIGEST, "objects": [CANARY]},
    ],
)
def test_monitoring_policy_is_closed_and_rejected_before_executor(monitoring, monkeypatch):
    configured = binding()
    configured["admin"]["monitoring"] = monitoring
    monkeypatch.setattr(admin.executor, "docker", lambda *_a, **_k: pytest.fail("No execution"))
    with pytest.raises(ContractError) as caught:
        admin._sql(configured, "SELECT 1;")
    assert caught.value.code == "AUTHORIZATION_REQUIRED"
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("enabled", [False, True])
def test_monitoring_and_permission_audit_share_one_snapshot_and_do_not_return_definitions(
    monkeypatch, enabled
):
    configured = binding()
    observed = before()
    observed.pop("target_snapshot")
    if enabled:
        configured["admin"]["monitoring"] = {
            "extension": "pg_stat_statements",
            "digest": MONITORING_DIGEST,
        }
        observed["monitoring"] = {"valid": True, "digest": MONITORING_DIGEST}
    original = copy.deepcopy(configured)
    statements = []

    def sql(_binding, statement):
        statements.append(statement)
        return copy.deepcopy(observed)

    monkeypatch.setattr(admin, "_sql", sql)
    monkeypatch.setattr(admin.executor, "target_snapshot", lambda _: TARGET)
    result = admin.snapshot(configured)
    assert len(statements) == 1 and configured == original
    statement = statements[0]
    if enabled:
        assert statement.count("WITH passport_extension AS MATERIALIZED") == 1
        assert statement.count("c.oid IN (SELECT oid FROM passport_views)") == 2
        assert statement.count("p.oid IN (SELECT oid FROM passport_functions)") == 2
        assert result["monitoring"] == {"valid": True, "digest": MONITORING_DIGEST}
        assert "definition" not in json.dumps(result)
    else:
        assert "passport_monitoring" not in statement
        assert "pg_get_functiondef" not in statement
        assert "monitoring" not in result


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"valid": True},
        {"valid": 1, "digest": MONITORING_DIGEST},
        {"valid": True, "digest": CANARY},
        {"valid": True, "digest": MONITORING_DIGEST, "definition": CANARY},
    ],
)
def test_snapshot_never_accepts_malformed_or_raw_monitoring_metadata(monkeypatch, value):
    configured = binding()
    configured["admin"]["monitoring"] = {
        "extension": "pg_stat_statements",
        "digest": MONITORING_DIGEST,
    }
    observed = before()
    observed.pop("target_snapshot")
    observed["monitoring"] = value
    monkeypatch.setattr(admin, "_sql", lambda *_: observed)
    monkeypatch.setattr(admin.executor, "target_snapshot", lambda _: TARGET)
    with pytest.raises(ContractError) as caught:
        admin.snapshot(configured)
    assert caught.value.code == "EXECUTOR_FAILED" and CANARY not in str(caught.value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"valid": False, "digest": MONITORING_DIGEST},
        {"valid": 1, "digest": MONITORING_DIGEST},
        {"valid": True, "digest": "sha256:" + "2" * 64},
    ],
)
def test_unapproved_or_changed_monitoring_snapshot_cannot_start_mutation(simulated, value):
    enable_monitoring(simulated)
    if value is None:
        del simulated.current["monitoring"]
    else:
        simulated.current["monitoring"] = value
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "TARGET_DRIFT"
    assert "create-nologin" not in simulated.events


def test_approved_monitoring_is_not_adopted_without_explicit_binding(simulated):
    simulated.plan["before"]["monitoring"] = {"valid": True, "digest": MONITORING_DIGEST}
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "TARGET_DRIFT" and simulated.events == []


@pytest.mark.parametrize("audit_field", sorted(admin._AUDIT_FIELDS))
def test_monitoring_pin_does_not_bypass_other_public_or_own_role_permissions(
    simulated, audit_field
):
    enable_monitoring(simulated)
    simulated.current["public_audit"][audit_field] = True
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "PERMISSION_DENIED"
    assert "create-nologin" not in simulated.events
    simulated.current["public_audit"][audit_field] = False
    simulated.current["role"] = own_role()
    simulated.current["role"]["audit"][audit_field] = True
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "PERMISSION_DENIED"
    assert "enable" not in simulated.events


def test_monitoring_drift_after_reload_keeps_owned_role_closed(simulated, monkeypatch):
    enable_monitoring(simulated)

    def drift(_binding, expected_ca):
        simulated.reload(_binding, expected_ca)
        simulated.current["monitoring"]["digest"] = "sha256:" + "2" * 64

    monkeypatch.setattr(admin, "_reload", drift)
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "TARGET_DRIFT"
    assert simulated.current["role"]["login"] is False
    assert "enable" not in simulated.events


def test_monitoring_pin_is_rechecked_before_delivery_verification(simulated):
    enable_monitoring(simulated)
    result = provision(simulated)
    assert result["status"] == "applied" and "monitoring" not in result
    receipt = {**simulated.plan, "applied_ca_digest": CA_DIGEST}
    simulated.current["monitoring"]["digest"] = "sha256:" + "2" * 64
    with pytest.raises(ContractError) as caught:
        admin.verify_applied(simulated.binding, receipt, OPERATION)
    assert caught.value.code == "TARGET_DRIFT"


def test_error_after_login_does_not_run_compensating_database_changes(simulated, monkeypatch):
    failure = ContractError("TARGET_DRIFT")

    def failed_verification(*args):
        raise failure

    monkeypatch.setattr(admin, "verify_applied", failed_verification)
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value is failure
    assert simulated.current["role"]["login"] is True
    assert simulated.events[-1] == "enable"
    assert "disable" not in simulated.events
