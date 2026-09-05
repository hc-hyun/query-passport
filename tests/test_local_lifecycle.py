"""Coordinator invariants with real private journals and isolated backend doubles.

Database/credential adapters have their own integration gates. These tests make
phase failures deterministic without accessing Docker, PKI, or existing state.
"""

import copy
import json
import stat
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest
import test_lifecycle_binding

import query_passport
from query_passport import executor
from query_passport import local_lifecycle as lifecycle
from query_passport import operation_store as store
from query_passport.contract import ContractError

binding = test_lifecycle_binding.binding
REQUEST = test_lifecycle_binding.REQUEST
EMPTY_REVISION = {"generation_id": None, "revision": None, "certificate_sha256": None}
ISSUANCE = {
    "certificate_sha256": "sha256:" + "e" * 64,
    "authority_sha256": "sha256:" + "f" * 64,
    "not_before": "2026-09-05T01:02:03+00:00",
    "not_after": "2026-10-05T01:02:03+00:00",
}
APPLIED_CA_DIGEST = "sha256:" + "e" * 64
UNVERIFIED_FACTS = (
    "source_inventory",
    "reader_permissions",
    "source_admission",
    "deployment",
    "application_readiness",
)
CONNECTION_FACTS = ("db_connectivity", "authentication", "certificate_validation")


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(store.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(tmp_path)))
    return tmp_path


@pytest.fixture
def backends(state_home, monkeypatch):
    """Mock only external adapters; exercise real authorization, state and locks."""
    before = {"hba_digest": "sha256:" + "1" * 64, "role": None}
    db = ModuleType("query_passport.db_admin")
    db.snapshot = Mock(side_effect=lambda binding: copy.deepcopy(before))
    db.validate_provision = Mock()
    db.apply = Mock(return_value={"ca_digest": APPLIED_CA_DIGEST})
    db.rollback = Mock()
    delivery = ModuleType("query_passport.credential_delivery")
    policy = ModuleType("query_passport.policy_verification")
    policy.run_policy_verification = Mock(return_value={"status": "succeeded", "error": None})
    delivery.inspect_delivery = Mock(return_value=copy.deepcopy(EMPTY_REVISION))
    state = SimpleNamespace(active=None, candidate=None, ca_digest=APPLIED_CA_DIGEST)

    def verify_applied(binding, plan, operation_id):
        if plan.get("applied_ca_digest") != state.ca_digest:
            raise ContractError("TARGET_DRIFT")

    db.verify_applied = Mock(side_effect=verify_applied)

    def deliver(
        source, destination, operation_id, *, expected_revision, permission_setter, validator
    ):
        candidate = destination / "versions" / operation_id / "bundle"
        state.candidate = candidate
        permission_setter(candidate)
        validator(candidate)
        # A rejected callback can never reach this simulated active publication.
        state.active = operation_id
        return {
            "generation_id": operation_id,
            "revision": "sha256:" + "2" * 64,
            "certificate_sha256": ISSUANCE["certificate_sha256"],
            "reused": False,
        }

    def rollback(destination, operation_id, previous):
        state.active = previous["generation_id"]
        return dict(previous)

    delivery.deliver = Mock(side_effect=deliver)
    delivery.rollback = Mock(side_effect=rollback)
    for name, module in (
        ("db_admin", db),
        ("credential_delivery", delivery),
        ("policy_verification", policy),
    ):
        monkeypatch.setitem(sys.modules, "query_passport." + name, module)
        monkeypatch.setattr(query_passport, name, module, raising=False)
    target = Mock(return_value="sha256:" + "3" * 64)
    verify = Mock(return_value={"status": "succeeded", "error": None})
    issuer = Mock(return_value=dict(ISSUANCE))
    trust = Mock(return_value=b"synthetic-ca-test-double")
    permissions = Mock()
    monkeypatch.setattr(executor, "target_snapshot", target)
    monkeypatch.setattr(executor, "run_verification", verify)
    monkeypatch.setattr(lifecycle, "issuer", issuer)
    monkeypatch.setattr(lifecycle, "client_trust", trust)
    monkeypatch.setattr(lifecycle, "set_runtime_permissions", permissions)
    monkeypatch.setattr(
        executor,
        "docker",
        lambda *args, **kwargs: pytest.fail("Coordinator unit test reached Docker"),
    )
    return SimpleNamespace(
        db=db,
        delivery=delivery,
        state=state,
        before=before,
        target=target,
        verify=verify,
        policy=policy.run_policy_verification,
        issuer=issuer,
        trust=trust,
        permissions=permissions,
    )


def execute(command, binding, prepared, request=None):
    return lifecycle.execute(
        command,
        REQUEST if request is None else request,
        binding,
        prepared["operation_id"],
        prepared["plan_digest"],
    )


def events(prepared):
    with store.operation(prepared["operation_id"]) as operation:
        return operation.events()


def artifact(prepared, name):
    with store.operation(prepared["operation_id"]) as operation:
        return operation.read_artifact(name)


def provision_through_apply(binding):
    prepared = lifecycle.prepare(REQUEST, binding)
    execute("issue", binding, prepared)
    execute("apply", binding, prepared)
    return prepared


@pytest.mark.parametrize("command", ["prepare", "issue", "apply", "deliver", "rollback", "status"])
def test_each_stage_requires_current_operator_authorization(binding, backends, command):
    binding["operations"].remove(command)
    with pytest.raises(ContractError) as error:
        if command == "prepare":
            lifecycle.prepare(REQUEST, binding)
        else:
            lifecycle.execute(command, REQUEST, binding, "a" * 32, "sha256:" + "b" * 64)
    assert error.value.code == "AUTHORIZATION_REQUIRED"
    backends.target.assert_not_called()
    backends.db.snapshot.assert_not_called()
    backends.issuer.assert_not_called()
    assert not store.state_directory().exists()


def test_prepare_preserves_zero_sources_and_private_plan_without_claiming_connection(
    binding, backends
):
    result = lifecycle.prepare(REQUEST, binding)
    assert result["phase"] == "prepared"
    assert result["source_count"] == 0
    for fact in (*UNVERIFIED_FACTS, *CONNECTION_FACTS):
        assert result[fact] == "not_checked"
    for private in ("admin", "lifecycle", "before", "binding_digest", "credential_dir"):
        assert private not in result
    assert "/synthetic/" not in json.dumps(result)
    plan = json.loads(artifact(result, "plan.json"))
    assert plan["request"] == REQUEST
    assert plan["before"] == backends.before
    assert plan["previous"] == EMPTY_REVISION
    path = store.state_directory() / result["operation_id"] / "plan.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [event["phase"] for event in events(result)] == ["prepared"]
    backends.issuer.assert_not_called()
    backends.db.apply.assert_not_called()
    backends.verify.assert_not_called()


def test_prepare_rejects_existing_active_credential_without_new_operation(binding, backends):
    backends.delivery.inspect_delivery.return_value = {"generation_id": "a" * 32}
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(REQUEST, binding)
    assert error.value.code == "TARGET_DRIFT"
    assert list(store.state_directory().glob("*/plan.json")) == []
    backends.db.apply.assert_not_called()


def test_prepare_rejects_target_replaced_during_snapshot(binding, backends):
    backends.target.side_effect = ["before", "after"]
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(REQUEST, binding)
    assert error.value.code == "TARGET_DRIFT"
    assert list(store.state_directory().glob("*/plan.json")) == []


@pytest.mark.parametrize("command", ["apply", "deliver"])
def test_stages_cannot_skip_their_prerequisites(binding, backends, command):
    prepared = lifecycle.prepare(REQUEST, binding)
    with pytest.raises(ContractError) as error:
        execute(command, binding, prepared)
    assert error.value.code == "RECOVERY_REQUIRED"
    assert [event["phase"] for event in events(prepared)] == ["prepared"]
    backends.db.apply.assert_not_called()
    backends.delivery.deliver.assert_not_called()


@pytest.mark.parametrize("change", ["request", "binding", "plan_digest", "target"])
def test_plan_replay_is_bound_to_request_scope_digest_and_target(binding, backends, change):
    prepared = lifecycle.prepare(REQUEST, binding)
    request = copy.deepcopy(REQUEST)
    if change == "request":
        request["source_count"] = 1
    elif change == "binding":
        binding["lifecycle"]["lifetime_days"] = 20
    elif change == "plan_digest":
        prepared["plan_digest"] = "sha256:" + "9" * 64
    else:
        backends.target.return_value = "sha256:" + "9" * 64
    with pytest.raises(ContractError) as error:
        execute("issue", binding, prepared, request)
    assert error.value.code == "TARGET_DRIFT"
    assert [event["phase"] for event in events(prepared)] == ["prepared"]
    backends.issuer.assert_not_called()


def test_authorization_expiry_extension_preserves_scope_and_plan(binding, backends):
    prepared = lifecycle.prepare(REQUEST, binding)
    binding["expires_at"] += 1800
    assert execute("issue", binding, prepared)["phase"] == "issued"


def test_config_drift_after_preparation_stops_issuance_and_keeps_plan(binding, backends):
    prepared = lifecycle.prepare(REQUEST, binding)
    original = artifact(prepared, "plan.json")
    backends.before["hba_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ContractError) as error:
        execute("issue", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert events(prepared)[-1]["phase"] == "partial_failure"
    assert events(prepared)[-1]["error"] == "TARGET_DRIFT"
    assert artifact(prepared, "plan.json") == original
    backends.issuer.assert_not_called()


def test_reissue_reuses_same_operation_and_rejects_changed_generation_metadata(binding, backends):
    prepared = lifecycle.prepare(REQUEST, binding)
    first = execute("issue", binding, prepared)
    original = artifact(prepared, "issuance.json")
    assert execute("issue", binding, prepared) == first
    assert backends.issuer.call_args.args[1] == prepared["operation_id"]
    backends.issuer.return_value = {**ISSUANCE, "certificate_sha256": "sha256:" + "0" * 64}
    with pytest.raises(ContractError) as error:
        execute("issue", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert artifact(prepared, "issuance.json") == original


def test_partial_apply_retry_preserves_evidence_and_does_not_advance_to_delivery(binding, backends):
    prepared = lifecycle.prepare(REQUEST, binding)
    execute("issue", binding, prepared)
    original = artifact(prepared, "plan.json")
    backends.db.apply.side_effect = [
        ContractError("EXECUTOR_FAILED"),
        {"ca_digest": APPLIED_CA_DIGEST},
    ]
    with pytest.raises(ContractError) as error:
        execute("apply", binding, prepared)
    assert error.value.code == "EXECUTOR_FAILED"
    assert [event["phase"] for event in events(prepared)][-2:] == ["applying", "partial_failure"]
    backends.delivery.deliver.assert_not_called()
    assert execute("apply", binding, prepared)["phase"] == "applied"
    assert backends.db.apply.call_count == 2
    assert execute("apply", binding, prepared)["phase"] == "applied"
    assert backends.db.apply.call_count == 2
    assert artifact(prepared, "plan.json") == original


def test_partial_apply_can_rollback_without_assuming_apply_completed(binding, backends):
    prepared = lifecycle.prepare(REQUEST, binding)
    execute("issue", binding, prepared)
    backends.db.apply.side_effect = ContractError("EXECUTOR_FAILED")
    with pytest.raises(ContractError):
        execute("apply", binding, prepared)
    original = artifact(prepared, "plan.json")
    assert execute("rollback", binding, prepared)["phase"] == "rolled_back"
    backends.db.rollback.assert_called_once()
    backends.delivery.rollback.assert_not_called()
    assert artifact(prepared, "plan.json") == original


@pytest.mark.parametrize("failure", [ContractError("TIMEOUT"), KeyboardInterrupt(), SystemExit(1)])
def test_uncertain_apply_outcome_is_recorded_unknown_and_allows_scoped_recovery(
    binding, backends, failure
):
    prepared = lifecycle.prepare(REQUEST, binding)
    execute("issue", binding, prepared)
    backends.db.apply.side_effect = failure
    with pytest.raises(type(failure)):
        execute("apply", binding, prepared)
    last = events(prepared)[-1]
    assert last["phase"] == "unknown"
    assert last["error"] == ("TIMEOUT" if isinstance(failure, ContractError) else "INTERRUPTED")
    assert execute("status", binding, prepared)["phase"] == "unknown"
    assert execute("rollback", binding, prepared)["phase"] == "rolled_back"
    backends.db.rollback.assert_called_once()


def test_failed_candidate_verification_cannot_publish_active_generation(binding, backends):
    prepared = provision_through_apply(binding)
    backends.verify.return_value = {"status": "failed", "error": "TLS_VERIFICATION_FAILED"}
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "TLS_VERIFICATION_FAILED"
    assert backends.state.active is None
    assert "verified" not in {event["phase"] for event in events(prepared)}
    assert events(prepared)[-1]["phase"] == "partial_failure"
    projected, request = backends.verify.call_args.args
    assert request == REQUEST
    assert projected["operations"] == ["verify"]
    assert projected["binding_version"] == 1
    assert "admin" not in projected and "lifecycle" not in projected
    assert projected["credential_dir"] == str(backends.state.candidate)


def test_database_drift_during_candidate_verification_prevents_publication(binding, backends):
    prepared = provision_through_apply(binding)
    backends.db.verify_applied.side_effect = [None, ContractError("TARGET_DRIFT")]
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert backends.state.active is None
    assert events(prepared)[-1]["phase"] == "partial_failure"


def test_server_accepting_uncredentialed_or_plaintext_connection_blocks_publication(
    binding, backends
):
    prepared = provision_through_apply(binding)
    backends.policy.return_value = {"status": "failed", "error": "VERIFICATION_FAILED"}
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "VERIFICATION_FAILED"
    assert backends.state.active is None
    assert "verified" not in {event["phase"] for event in events(prepared)}
    assert events(prepared)[-1]["error"] == "VERIFICATION_FAILED"
    projected, request = backends.policy.call_args.args
    assert request == REQUEST
    assert projected["operations"] == ["verify"]
    assert projected["credential_dir"] == str(backends.state.candidate)
    assert "admin" not in projected and "lifecycle" not in projected
    assert execute("rollback", binding, prepared)["phase"] == "rolled_back"


def test_rejected_policy_probes_are_not_success_when_fresh_valid_client_also_fails(
    binding, backends
):
    prepared = provision_through_apply(binding)
    backends.verify.side_effect = [
        {"status": "succeeded", "error": None},
        {"status": "failed", "error": "CLIENT_AUTHENTICATION_FAILED"},
    ]
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "CLIENT_AUTHENTICATION_FAILED"
    backends.policy.assert_called_once()
    assert backends.state.active is None
    assert "verified" not in {event["phase"] for event in events(prepared)}


@pytest.mark.parametrize(
    "callback,code",
    [
        ("permissions", "TIMEOUT"),
        ("verification", "TIMEOUT"),
        ("verification", "TLS_VERIFICATION_FAILED"),
        ("policy", "TIMEOUT"),
    ],
)
def test_delivery_wrapper_preserves_known_callback_failure_classification(
    binding, backends, callback, code
):
    prepared = provision_through_apply(binding)
    provider = {
        "permissions": backends.permissions,
        "verification": backends.verify,
        "policy": backends.policy,
    }[callback]
    provider.side_effect = ContractError(code)

    def wrapped_deliver(
        source, destination, operation_id, *, expected_revision, permission_setter, validator
    ):
        candidate = destination / "versions" / operation_id / "bundle"
        try:
            permission_setter(candidate)
            validator(candidate)
        except ContractError:
            # The actual delivery adapter deliberately hides callback details.
            # The coordinator must retain its own fixed classification before
            # that adapter boundary, especially an uncertain helper timeout.
            raise RuntimeError("DELIVERY_VALIDATION_FAILED") from None
        pytest.fail("Failed callback reached active credential publication")

    backends.delivery.deliver.side_effect = wrapped_deliver
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == code
    assert events(prepared)[-1]["phase"] == ("unknown" if code == "TIMEOUT" else "partial_failure")
    assert events(prepared)[-1]["error"] == code
    assert backends.state.active is None
    assert execute("rollback", binding, prepared)["phase"] == "rolled_back"


def test_delivery_revalidates_issued_generation_before_candidate_publication(binding, backends):
    prepared = provision_through_apply(binding)
    backends.issuer.return_value = {**ISSUANCE, "authority_sha256": "sha256:" + "0" * 64}
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    backends.delivery.deliver.assert_not_called()
    assert backends.state.active is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ca_digest":',
        b'{"ca_digest":"synthetic-private-corrupt-digest"}',
        json.dumps({"ca_digest": "sha256:" + "9" * 64}).encode(),
    ],
)
def test_corrupt_or_mismatched_applied_receipt_blocks_delivery(binding, backends, raw):
    prepared = provision_through_apply(binding)
    receipt = store.state_directory() / prepared["operation_id"] / "db.applied.json"
    receipt.write_bytes(raw)
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code in {"INVALID_INPUT", "TARGET_DRIFT"}
    assert "synthetic-private-corrupt-digest" not in str(error.value)
    assert receipt.read_bytes() == raw
    backends.delivery.deliver.assert_not_called()
    assert backends.state.active is None
    assert events(prepared)[-1]["phase"] == "partial_failure"


def test_delivery_uses_immutable_applied_ca_receipt_instead_of_accepting_current_trust(
    binding, backends
):
    prepared = provision_through_apply(binding)
    original = artifact(prepared, "db.applied.json")
    assert json.loads(original) == {"ca_digest": APPLIED_CA_DIGEST}
    backends.state.ca_digest = "sha256:" + "9" * 64
    with pytest.raises(ContractError) as error:
        execute("deliver", binding, prepared)
    assert error.value.code == "TARGET_DRIFT"
    assert artifact(prepared, "db.applied.json") == original
    observed_plan = backends.db.verify_applied.call_args.args[1]
    assert observed_plan["applied_ca_digest"] == APPLIED_CA_DIGEST
    backends.delivery.deliver.assert_not_called()
    assert backends.state.active is None
    assert backends.issuer.call_count == 1


def test_successful_delivery_and_status_keep_application_facts_separate(binding, backends):
    prepared = provision_through_apply(binding)
    result = execute("deliver", binding, prepared)
    assert result["phase"] == "verified"
    assert result["source_count"] == 0
    assert backends.state.active == prepared["operation_id"]
    for fact in CONNECTION_FACTS:
        assert result[fact] == "passed"
    for fact in UNVERIFIED_FACTS:
        assert result[fact] == "not_checked"
    backends.policy.assert_called_once()
    positive_checks = backends.verify.call_count
    assert positive_checks > 0
    historical = execute("status", binding, prepared)
    assert historical["phase"] == "verified"
    for fact in (*UNVERIFIED_FACTS, *CONNECTION_FACTS):
        assert historical[fact] == "not_checked"
    assert backends.verify.call_count == positive_checks
    backends.policy.assert_called_once()
    assert "/synthetic/" not in json.dumps(result)


def test_failed_delivery_can_rollback_and_cannot_restart_retired_operation(binding, backends):
    prepared = provision_through_apply(binding)
    backends.verify.return_value = {"status": "failed", "error": "CLIENT_AUTHENTICATION_FAILED"}
    with pytest.raises(ContractError):
        execute("deliver", binding, prepared)
    first = execute("rollback", binding, prepared)
    assert first["phase"] == "rolled_back"
    backends.db.rollback.assert_called_once()
    backends.delivery.rollback.assert_called_once()
    assert execute("rollback", binding, prepared) == first
    assert execute("status", binding, prepared)["phase"] == "rolled_back"
    for command in ("issue", "apply", "deliver"):
        with pytest.raises(ContractError) as error:
            execute(command, binding, prepared)
        assert error.value.code == "RECOVERY_REQUIRED"
    assert backends.state.active is None


def test_partial_rollback_retries_recovery_and_never_resumes_forward_apply(binding, backends):
    prepared = provision_through_apply(binding)
    backends.db.rollback.side_effect = [ContractError("TIMEOUT"), None]
    with pytest.raises(ContractError) as error:
        execute("rollback", binding, prepared)
    assert error.value.code == "TIMEOUT"
    assert events(prepared)[-1]["phase"] == "unknown"
    with pytest.raises(ContractError) as error:
        execute("apply", binding, prepared)
    assert error.value.code == "RECOVERY_REQUIRED"
    assert execute("rollback", binding, prepared)["phase"] == "rolled_back"


@pytest.mark.parametrize("stage", ["issue", "apply", "deliver", "rollback"])
def test_raw_provider_exception_never_escapes_result_or_journal(binding, backends, capsys, stage):
    canary = "synthetic-private-provider-diagnostic"
    prepared = lifecycle.prepare(REQUEST, binding)
    if stage != "issue":
        execute("issue", binding, prepared)
    if stage in ("deliver", "rollback"):
        execute("apply", binding, prepared)
    provider = {
        "issue": backends.issuer,
        "apply": backends.db.apply,
        "deliver": backends.delivery.deliver,
        "rollback": backends.db.rollback,
    }[stage]
    provider.side_effect = RuntimeError(canary)
    with pytest.raises(ContractError) as error:
        execute(stage, binding, prepared)
    assert error.value.code == "RECOVERY_REQUIRED"
    assert canary not in str(error.value)
    assert canary not in json.dumps(events(prepared))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("initialize", [False, True])
def test_issuer_uses_fixed_internal_protocol_and_returns_only_selected_metadata(
    binding, monkeypatch, initialize
):
    binding["lifecycle"]["allow_initialize_authority"] = initialize
    calls = []

    def run(arguments, **kwargs):
        payload = json.loads(kwargs["stdin"])
        calls.append((arguments, kwargs, payload))
        return 0, json.dumps(
            {
                "status": "succeeded",
                "metadata": {**ISSUANCE, "private_canary": "never-return"},
                "error": None,
            }
        ).encode()

    monkeypatch.setattr(lifecycle, "run_process", run)
    result = lifecycle.issuer(binding, "a" * 32, "sha256:" + "b" * 64)
    assert result == ISSUANCE
    assert [call[2]["command"] for call in calls] == (
        ["initialize-authority", "issue-client"] if initialize else ["issue-client"]
    )
    for arguments, kwargs, payload in calls:
        assert arguments == [sys.executable, "-I", "-m", "query_passport.local_pki"]
        assert kwargs["timeout"] == 20 and kwargs["limit"] == 8192
        assert kwargs["env"] == executor.PROCESS_ENV
        assert not any(field in payload for field in ("password", "private_key", "certificate"))
    assert calls[-1][2]["common_name"] == "query-passport-test"
    assert "never-return" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["malformed", "error", "exit_mismatch", "missing_fingerprint"])
def test_issuer_rejects_malformed_or_failed_output_without_echoing_provider_text(
    binding, monkeypatch, kind
):
    binding["lifecycle"]["allow_initialize_authority"] = False
    canary = "synthetic-provider-secret-canary"
    code = 0
    value = {"status": "succeeded", "metadata": dict(ISSUANCE), "error": None}
    if kind == "malformed":
        raw = canary.encode()
    else:
        if kind == "error":
            code = 1
            value = {"status": "failed", "metadata": {}, "error": canary}
        elif kind == "exit_mismatch":
            code = 1
        else:
            del value["metadata"]["authority_sha256"]
        raw = json.dumps(value).encode()
    monkeypatch.setattr(lifecycle, "run_process", lambda *args, **kwargs: (code, raw))
    with pytest.raises(ContractError) as error:
        lifecycle.issuer(binding, "a" * 32, "sha256:" + "b" * 64)
    assert error.value.code in {"EXECUTOR_FAILED", "RECOVERY_REQUIRED"}
    assert canary not in str(error.value)
