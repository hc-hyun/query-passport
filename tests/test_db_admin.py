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
def test_partial_failures_close_owned_role_and_resume_without_duplicate_creation(simulated, phase):
    simulated.fail_phase = phase
    with pytest.raises(ContractError) as caught:
        provision(simulated)
    assert caught.value.code == "RECOVERY_REQUIRED"
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
    with pytest.raises(ContractError):
        admin.rollback(simulated.binding, simulated.plan, OPERATION)
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


def test_rollback_preserves_unrelated_changes_and_retains_own_identity(simulated):
    provision(simulated)
    simulated.current["hba"] = (
        "# another DBA comment\n" + simulated.current["hba"] + "\n# new final line"
    )
    simulated.current["ident"] += "# another map comment\n"
    simulated.auto_base = "sha256:" + "3" * 64
    start = len(simulated.events)
    result = admin.rollback(simulated.binding, simulated.plan, OPERATION)
    assert result["status"] == "rolled_back" and result["role"] == "nologin_retained"
    assert simulated.events[start] == "disable"
    assert (
        simulated.current["hba"]
        == "# another DBA comment\n" + simulated.original["hba"] + "\n# new final line"
    )
    assert simulated.current["ident"] == simulated.original["ident"] + "# another map comment\n"
    assert simulated.current["role"]["login"] is False and simulated.ca_installed
    assert simulated.current["auto_digest"] == simulated.auto_base
    assert admin.rollback(simulated.binding, simulated.plan, OPERATION)["status"] == "rolled_back"


def test_rollback_will_not_overwrite_changed_owned_block(simulated):
    provision(simulated)
    simulated.current["hba"] = simulated.current["hba"].replace(
        "cert clientname=DN", "trust # clientname=DN"
    )
    changed = simulated.current["hba"]
    with pytest.raises(ContractError) as caught:
        admin.rollback(simulated.binding, simulated.plan, OPERATION)
    assert caught.value.code == "RECOVERY_REQUIRED"
    assert simulated.current["hba"] == changed and simulated.current["role"]["login"] is False


def test_rollback_closes_owned_login_before_rejecting_malformed_configuration(simulated):
    provision(simulated)
    simulated.current["parse_ok"] = False
    hba = simulated.current["hba"]
    ident = simulated.current["ident"]
    with pytest.raises(ContractError) as caught:
        admin.rollback(simulated.binding, simulated.plan, OPERATION)
    assert caught.value.code == "RECOVERY_REQUIRED"
    assert simulated.current["role"]["login"] is False
    assert simulated.current["hba"] == hba
    assert simulated.current["ident"] == ident


@pytest.mark.parametrize("failure", [ContractError("TIMEOUT"), KeyboardInterrupt(), SystemExit(1)])
def test_rollback_uncertainty_is_not_converted_to_partial_failure(simulated, failure):
    provision(simulated)
    simulated.fail_phase = "replace-hba"
    simulated.failure = failure
    with pytest.raises(type(failure)) as caught:
        admin.rollback(simulated.binding, simulated.plan, OPERATION)
    assert caught.value is failure and simulated.current["role"]["login"] is False


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


def test_psql_transport_uses_fixed_socket_argv_and_stdin(monkeypatch):
    observed = []

    def docker(args, **kwargs):
        observed.append((args, kwargs))
        return b'{"ok":true}\n'

    monkeypatch.setattr(admin.executor, "docker", docker)
    assert admin._sql(binding(), "SELECT json_build_object('ok',true);") == {"ok": True}
    args, options = observed[0]
    assert "--no-psqlrc" in args and "--no-password" in args
    assert args[args.index("--host") + 1] == "/var/run/postgresql"
    assert args[args.index("--username") + 1] == "postgres"
    assert args[-2:] == ["--file", "-"]
    assert b"SET log_statement = 'none'" in options["stdin"]
    assert all("SELECT" not in part for part in args)


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
