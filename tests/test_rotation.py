"""Rotation chains with real private plans/journals and isolated external adapters."""

import copy
import hashlib

import pytest
import test_local_lifecycle as provision

from query_passport import local_lifecycle as lifecycle
from query_passport.contract import ContractError

binding = provision.binding
state_home = provision.state_home
backends = provision.backends
REQUEST = provision.REQUEST


@pytest.fixture
def rotating(backends, binding):
    revisions = {}

    def issuer(binding, operation_id, input_digest):
        return {
            **provision.ISSUANCE,
            "certificate_sha256": "sha256:" + hashlib.sha256(operation_id.encode()).hexdigest(),
        }

    original_deliver = backends.delivery.deliver.side_effect

    def deliver(source, destination, operation_id, **kwargs):
        result = original_deliver(source, destination, operation_id, **kwargs)
        result["certificate_sha256"] = issuer(binding, operation_id, "")["certificate_sha256"]
        result["revision"] = (
            "sha256:" + hashlib.sha256(("revision" + operation_id).encode()).hexdigest()
        )
        revisions[operation_id] = {
            key: result[key] for key in ("generation_id", "revision", "certificate_sha256")
        }
        return result

    backends.issuer.side_effect = issuer
    backends.delivery.deliver.side_effect = deliver
    backends.delivery.inspect_delivery.side_effect = lambda destination: copy.deepcopy(
        revisions[backends.state.active] if backends.state.active else provision.EMPTY_REVISION
    )
    initial = provision.provision_through_apply(binding)
    provision.execute("deliver", binding, initial)
    return backends, initial, revisions


def rotation(binding):
    return lifecycle.prepare(REQUEST, binding, intent="rotate")


def test_rotation_uses_new_generation_and_rollback_preserves_database(rotating, binding):
    backends, initial, revisions = rotating
    prepared = rotation(binding)
    assert prepared["intent"] == "rotate"
    assert "create_restricted_check_role" not in prepared["actions"]
    assert prepared["db_connectivity"] == "not_checked"
    before_apply_calls = backends.db.apply.call_count
    result = provision.execute("rotate", binding, prepared)
    assert result["phase"] == "verified"
    assert (
        revisions[initial["operation_id"]]["certificate_sha256"]
        != revisions[prepared["operation_id"]]["certificate_sha256"]
    )
    assert provision.execute("rotate", binding, prepared)["phase"] == "verified"
    assert backends.db.apply.call_count == before_apply_calls
    backends.db.rollback.assert_not_called()
    assert provision.execute("rollback", binding, prepared)["phase"] == "rolled_back"
    assert backends.state.active == initial["operation_id"]
    assert provision.execute("rollback", binding, prepared)["phase"] == "rolled_back"
    backends.db.rollback.assert_not_called()
    assert set(revisions) == {initial["operation_id"], prepared["operation_id"]}
    assert provision.execute("status", binding, prepared)["db_connectivity"] == "not_checked"


def test_older_operation_cannot_disable_newer_active_identity(rotating, binding):
    backends, initial, _ = rotating
    child = rotation(binding)
    provision.execute("rotate", binding, child)
    initial_events = provision.events(initial)
    with pytest.raises(ContractError) as error:
        provision.execute("rollback", binding, initial)
    assert error.value.code == "TARGET_DRIFT"
    assert provision.events(initial) == initial_events
    backends.db.rollback.assert_not_called()
    assert backends.state.active == child["operation_id"]
    provision.execute("rollback", binding, child)
    provision.execute("rollback", binding, initial)
    assert backends.state.active is None


def test_rotation_chain_reverts_in_order_and_retains_owner(rotating, binding):
    backends, initial, _ = rotating
    first = rotation(binding)
    provision.execute("rotate", binding, first)
    second = rotation(binding)
    provision.execute("rotate", binding, second)
    with pytest.raises(ContractError) as error:
        provision.execute("rollback", binding, first)
    assert error.value.code == "TARGET_DRIFT"
    assert provision.events(first)[-1]["phase"] == "verified"
    provision.execute("rollback", binding, second)
    assert backends.state.active == first["operation_id"]
    provision.execute("rollback", binding, first)
    assert backends.state.active == initial["operation_id"]
    backends.db.rollback.assert_not_called()


def test_parallel_rotation_plans_cannot_replace_a_newer_revision(rotating, binding):
    backends, _, _ = rotating
    first, stale = rotation(binding), rotation(binding)
    provision.execute("rotate", binding, first)
    before_issuance = backends.issuer.call_count
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, stale)
    assert error.value.code == "TARGET_DRIFT"
    assert backends.issuer.call_count == before_issuance
    assert backends.state.active == first["operation_id"]


def test_database_drift_after_rotation_plan_stops_before_issuance(rotating, binding):
    backends, initial, _ = rotating
    prepared = rotation(binding)
    backends.before["hba_digest"] = "sha256:" + "a" * 64
    before_issuance = backends.issuer.call_count
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert backends.issuer.call_count == before_issuance
    assert backends.state.active == initial["operation_id"]


@pytest.mark.parametrize("field", ["authority_sha256", "server_ca_sha256"])
def test_rotation_never_changes_trust_implicitly(rotating, binding, field):
    backends, initial, _ = rotating
    prepared = rotation(binding)
    original = backends.issuer.side_effect
    backends.issuer.side_effect = lambda *args: {**original(*args), field: "sha256:" + "a" * 64}
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert backends.state.active == initial["operation_id"]
    assert provision.execute("rollback", binding, prepared)["phase"] == "rolled_back"
    backends.db.rollback.assert_not_called()


def test_failed_new_client_does_not_switch_previous_active_generation(rotating, binding):
    backends, initial, _ = rotating
    prepared = rotation(binding)
    backends.verify.return_value = {"status": "failed", "error": "CLIENT_AUTHENTICATION_FAILED"}
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, prepared)
    assert error.value.code == "CLIENT_AUTHENTICATION_FAILED"
    assert backends.state.active == initial["operation_id"]
    backends.verify.return_value = {"status": "succeeded", "error": None}
    assert provision.execute("rotate", binding, prepared)["phase"] == "verified"
    assert backends.state.active == prepared["operation_id"]


def test_unusable_previous_certificate_is_not_restored(rotating, binding):
    backends, _, _ = rotating
    prepared = rotation(binding)
    provision.execute("rotate", binding, prepared)
    before_rollback = backends.delivery.rollback.call_count
    backends.verify.return_value = {"status": "failed", "error": "CLIENT_AUTHENTICATION_FAILED"}
    with pytest.raises(ContractError) as error:
        provision.execute("rollback", binding, prepared)
    assert error.value.code == "CLIENT_AUTHENTICATION_FAILED"
    assert backends.delivery.rollback.call_count == before_rollback
    assert backends.state.active == prepared["operation_id"]
    backends.db.rollback.assert_not_called()


@pytest.mark.parametrize("command", ["issue", "apply", "deliver"])
def test_rotation_plan_cannot_authorize_database_mutation_commands(rotating, binding, command):
    backends, _, _ = rotating
    prepared = rotation(binding)
    before_apply = backends.db.apply.call_count
    with pytest.raises(ContractError) as error:
        provision.execute(command, binding, prepared)
    assert error.value.code == "UNSUPPORTED_OPERATION"
    assert backends.db.apply.call_count == before_apply


def test_rolled_back_rotation_is_retired(rotating, binding):
    _, _, _ = rotating
    prepared = rotation(binding)
    provision.execute("rotate", binding, prepared)
    provision.execute("rollback", binding, prepared)
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, prepared)
    assert error.value.code == "RECOVERY_REQUIRED"


def test_rotation_timeout_is_unknown_and_preserves_previous_generation(rotating, binding):
    backends, initial, _ = rotating
    prepared = rotation(binding)
    backends.permissions.side_effect = ContractError("TIMEOUT")
    with pytest.raises(ContractError) as error:
        provision.execute("rotate", binding, prepared)
    assert error.value.code == "TIMEOUT"
    assert provision.events(prepared)[-1]["phase"] == "unknown"
    assert backends.state.active == initial["operation_id"]
