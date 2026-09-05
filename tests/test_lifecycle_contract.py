"""Public lifecycle requests select a bound operation without granting authority."""

import copy
import io
import json
import signal
import sys
from pathlib import Path

import jsonschema
import pytest

from query_passport import cli, executor, local_lifecycle
from query_passport.contract import (
    LIFECYCLE_COMMANDS,
    ContractError,
    respond,
)
from query_passport.credential_delivery import DeliveryError
from query_passport.lifecycle_contract import (
    decode_request,
    failure_result,
)
from query_passport.operation_store import StateError

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "examples/request.json").read_text())
OPERATION = {"id": "1a" * 16, "plan_digest": "sha256:" + "2b" * 32}
EXECUTE = tuple(command for command in LIFECYCLE_COMMANDS if command != "prepare")
MARKER = "SYNTHETIC_PRIVATE_VALUE_MUST_NOT_APPEAR"
SCHEMAS = {
    name: json.loads((ROOT / "schemas" / filename).read_text())
    for name, filename in (
        ("base", "request-v1.schema.json"),
        ("prepare", "prepare-request-v1.schema.json"),
        ("operation", "operation-request-v1.schema.json"),
    )
}


def request_for(command):
    request = copy.deepcopy(BASE)
    request["source_count"] = 0
    if command != "prepare":
        request["operation"] = dict(OPERATION)
    return request


def parse(command, request):
    return decode_request(command, json.dumps(request).encode())


@pytest.mark.parametrize("schema", SCHEMAS.values())
def test_schemas_are_valid_and_keep_base_projection(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    for field, value in SCHEMAS["base"]["properties"].items():
        assert schema["properties"][field] == value
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("intent", [None, "provision", "rotate"])
def test_prepare_intent_is_explicitly_normalized_and_does_not_mutate_input(intent):
    request = request_for("prepare")
    if intent is not None:
        request["intent"] = intent
    prior = copy.deepcopy(request)
    jsonschema.validate(request, SCHEMAS["prepare"])
    decoded = parse("prepare", request)
    assert decoded["intent"] == (intent or "provision")
    assert decoded["source_count"] == 0
    assert request == prior


@pytest.mark.parametrize("command", EXECUTE)
def test_operation_request_uses_one_closed_reference(command):
    request = request_for(command)
    jsonschema.validate(request, SCHEMAS["operation"])
    assert parse(command, request) == request
    assert failure_result(command, request) == {
        "operation_id": OPERATION["id"],
        "plan_digest": OPERATION["plan_digest"],
        "outcome": "not_confirmed",
        "next_action": "status_or_scoped_recovery",
    }


@pytest.mark.parametrize("command", ["inspect", "plan", "verify"])
@pytest.mark.parametrize("extra", [{"intent": "provision"}, {"operation": OPERATION}])
def test_old_commands_reject_lifecycle_fields(command, extra):
    request = {**copy.deepcopy(BASE), **extra}
    with pytest.raises(ContractError) as caught:
        parse(command, request)
    assert caught.value.code == "INVALID_INPUT"
    assert not jsonschema.Draft202012Validator(SCHEMAS["base"]).is_valid(request)


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "", "Rotate", "rotate\n", MARKER])
def test_invalid_prepare_intent(value):
    request = {**request_for("prepare"), "intent": value}
    with pytest.raises(ContractError):
        parse("prepare", request)
    assert not jsonschema.Draft202012Validator(SCHEMAS["prepare"]).is_valid(request)


@pytest.mark.parametrize("command", LIFECYCLE_COMMANDS)
@pytest.mark.parametrize("field", ["approved", "force", "sql", "password", "credential_path"])
def test_no_public_approval_credential_or_execution_escape_hatch(command, field):
    request = {**request_for(command), field: MARKER}
    with pytest.raises(ContractError) as caught:
        parse(command, request)
    assert caught.value.code == "INVALID_INPUT"
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize(
    "operation",
    [
        None,
        True,
        1,
        [],
        "ref",
        {},
        {"id": OPERATION["id"]},
        {"plan_digest": OPERATION["plan_digest"]},
        {**OPERATION, "approved": True},
        {**OPERATION, "id": "a" * 31},
        {**OPERATION, "id": "a" * 33},
        {**OPERATION, "id": "A" * 32},
        {**OPERATION, "id": "a" * 32 + "\n"},
        {**OPERATION, "id": "../" + "a" * 29},
        {**OPERATION, "id": 1},
        {**OPERATION, "plan_digest": "sha256:" + "a" * 63},
        {**OPERATION, "plan_digest": "sha256:" + "a" * 65},
        {**OPERATION, "plan_digest": "sha256:" + "A" * 64},
        {**OPERATION, "plan_digest": "sha256:" + "a" * 64 + "\n"},
        {**OPERATION, "plan_digest": True},
    ],
)
def test_malformed_operation_reference_never_reaches_binding(operation, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Invalid operation reached binding lookup")

    monkeypatch.setattr(executor, "load_binding", forbidden)
    request = {**request_for("apply"), "operation": operation}
    with pytest.raises(ContractError):
        respond("apply", request)
    assert not jsonschema.Draft202012Validator(SCHEMAS["operation"]).is_valid(request)


@pytest.mark.parametrize("command", EXECUTE)
def test_reference_is_required_and_prepare_only_intent_is_rejected(command):
    for request in (BASE, {**request_for(command), "intent": "rotate"}):
        with pytest.raises(ContractError):
            parse(command, request)
    with pytest.raises(ContractError):
        parse("prepare", request_for(command))


@pytest.mark.parametrize("raw", [b'{"operation":', b"{}{}", b"\xff", b" " * 65537])
def test_lifecycle_uses_same_bounded_utf8_json_parser(raw):
    with pytest.raises(ContractError):
        decode_request("apply", raw)


def test_duplicate_operation_key_is_rejected():
    raw = (
        json.dumps(request_for("apply"))
        .encode()
        .replace(b'"operation":', b'"operation":null,"operation":')
    )
    with pytest.raises(ContractError):
        decode_request("apply", raw)


@pytest.mark.parametrize("command", LIFECYCLE_COMMANDS)
def test_dispatch_strips_public_control_fields_and_uses_command_authorization(command, monkeypatch):
    request = request_for(command)
    if command == "prepare":
        request["intent"] = "rotate"
    expected_base = {
        key: value for key, value in request.items() if key not in {"intent", "operation"}
    }
    binding = {"private_binding": MARKER}
    calls = []
    result = {"source_count": 0, "phase": "prepared" if command == "prepare" else "verified"}

    def load(base, *, operation):
        calls.append(("binding", operation))
        assert base == expected_base
        return binding

    def prepare(base, loaded, *, intent):
        assert base == expected_base and loaded is binding and intent == "rotate"
        calls.append(("prepare", intent))
        return result

    def execute(action, base, loaded, operation_id, plan_digest):
        assert action == command and base == expected_base and loaded is binding
        assert (operation_id, plan_digest) == (OPERATION["id"], OPERATION["plan_digest"])
        calls.append(("execute", action))
        return result

    monkeypatch.setattr(executor, "load_binding", load)
    monkeypatch.setattr(local_lifecycle, "prepare", prepare)
    monkeypatch.setattr(local_lifecycle, "execute", execute)
    response = respond(command, request)
    assert response["status"] == (
        "planned" if command == "prepare" else "validated" if command == "status" else "succeeded"
    )
    assert response["scope"] == "database-only" and response["errors"] == []
    assert response["result"] is result
    assert calls[0] == ("binding", command) and len(calls) == 2
    assert MARKER not in json.dumps(response)


@pytest.mark.parametrize("command", LIFECYCLE_COMMANDS)
def test_missing_binding_never_calls_lifecycle(command, monkeypatch):
    def missing(*_args, **_kwargs):
        raise ContractError("AUTHORIZATION_REQUIRED")

    def forbidden(*_args, **_kwargs):
        pytest.fail("Missing authorization reached lifecycle execution")

    monkeypatch.setattr(executor, "load_binding", missing)
    monkeypatch.setattr(local_lifecycle, "prepare", forbidden)
    monkeypatch.setattr(local_lifecycle, "execute", forbidden)
    with pytest.raises(ContractError) as caught:
        respond(command, request_for(command))
    assert caught.value.code == "AUTHORIZATION_REQUIRED"


@pytest.mark.parametrize(
    "error,code",
    [
        (StateError("STATE_ACCESS_DENIED"), "RECOVERY_REQUIRED"),
        (StateError("STATE_WRITE_FAILED"), "RECOVERY_REQUIRED"),
        (StateError("STATE_INVALID"), "RECOVERY_REQUIRED"),
        (StateError("STATE_CONFLICT"), "RECOVERY_REQUIRED"),
        (StateError("STATE_PARTIAL"), "RECOVERY_REQUIRED"),
        (StateError("OPERATION_BUSY"), "RECOVERY_REQUIRED"),
        (StateError(MARKER), "INTERNAL_ERROR"),
        (DeliveryError("DELIVERY_ACCESS_DENIED"), "CREDENTIAL_ACCESS_DENIED"),
        (DeliveryError("DELIVERY_PERMISSION_DENIED"), "CREDENTIAL_ACCESS_DENIED"),
        (DeliveryError("DELIVERY_DRIFT"), "TARGET_DRIFT"),
        (DeliveryError("DELIVERY_INPUT_CONFLICT"), "TARGET_DRIFT"),
        (DeliveryError("DELIVERY_INVALID_INPUT"), "EXECUTOR_FAILED"),
        (DeliveryError("DELIVERY_OWNERSHIP_REQUIRED"), "RECOVERY_REQUIRED"),
        (DeliveryError("DELIVERY_PARTIAL_STATE"), "RECOVERY_REQUIRED"),
        (DeliveryError("DELIVERY_BUSY"), "RECOVERY_REQUIRED"),
        (DeliveryError("DELIVERY_ROLLED_BACK"), "RECOVERY_REQUIRED"),
        (DeliveryError("DELIVERY_VALIDATION_FAILED"), "VERIFICATION_FAILED"),
        (DeliveryError(MARKER), "INTERNAL_ERROR"),
    ],
)
def test_private_errors_are_mapped_to_fixed_public_errors(error, code, monkeypatch):
    monkeypatch.setattr(executor, "load_binding", lambda *_args, **_kwargs: {})

    def failed(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(local_lifecycle, "execute", failed)
    with pytest.raises(ContractError) as caught:
        respond("deliver", request_for("deliver"))
    assert caught.value.code == code and MARKER not in str(caught.value)


@pytest.mark.parametrize(
    "error,code,exit_code",
    [
        (ContractError("TIMEOUT"), "TIMEOUT", 5),
        (ContractError("TARGET_DRIFT"), "TARGET_DRIFT", 7),
        (KeyboardInterrupt(), "INTERRUPTED", 130),
        (SystemExit(MARKER), "INTERRUPTED", 130),
        (RuntimeError(MARKER), "INTERNAL_ERROR", 1),
    ],
)
def test_cli_uncertain_failure_retains_reference_and_never_guesses_phase(
    error, code, exit_code, monkeypatch, capfd
):
    request = request_for("apply")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))

    def failed(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(cli, "respond", failed)
    assert cli.main(["apply", "--request", "-"]) == exit_code
    captured = capfd.readouterr()
    response = json.loads(captured.out)
    assert captured.err == "" and MARKER not in captured.out
    assert response["status"] == "failed" and response["errors"][0]["code"] == code
    assert response["result"] == failure_result("apply", request)
    assert "phase" not in response["result"]


@pytest.mark.parametrize("command", LIFECYCLE_COMMANDS)
def test_invalid_base_never_echoes_even_valid_operation_reference(command, monkeypatch, capfd):
    request = request_for(command)
    request["source_count"] = -1
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    assert cli.main([command, "--request", "-"]) == 2
    response = json.loads(capfd.readouterr().out)
    assert response["result"] == {}
    assert OPERATION["id"] not in json.dumps(response)


@pytest.mark.parametrize("command", LIFECYCLE_COMMANDS)
def test_lifecycle_timeout_starts_only_after_complete_validated_input(command, monkeypatch, capfd):
    timers = []
    monkeypatch.setattr(signal, "setitimer", lambda timer, seconds: timers.append(seconds))

    def read(*_args):
        assert timers == [5]
        return json.dumps(request_for(command)).encode()

    def execute(*_args):
        assert timers == [5, 180]
        raise ContractError("AUTHORIZATION_REQUIRED")

    monkeypatch.setattr(cli, "read_request", read)
    monkeypatch.setattr(cli, "respond", execute)
    assert cli.main([command, "--request", "-"]) == 6
    assert timers == [5, 180, 0]
    response = json.loads(capfd.readouterr().out)
    assert response["result"] == failure_result(command, parse(command, request_for(command)))


def test_lifecycle_output_limit_still_retains_only_reference(monkeypatch, capfd):
    request = request_for("deliver")
    monkeypatch.setattr(cli, "read_request", lambda *_args: json.dumps(request).encode())
    monkeypatch.setattr(cli, "respond", lambda *_args: {"result": MARKER * 1000, "errors": []})
    assert cli.main(["deliver", "--request", "-"]) == 1
    captured = capfd.readouterr()
    response = json.loads(captured.out)
    assert response["errors"][0]["code"] == "OUTPUT_TOO_LARGE"
    assert response["result"] == failure_result("deliver", request)
    assert MARKER not in captured.out and captured.err == ""


def test_historical_status_is_not_reclassified_as_live_verification(monkeypatch):
    result = {
        "phase": "verified",
        "db_connectivity": "not_checked",
        "authentication": "not_checked",
        "certificate_validation": "not_checked",
        "source_count": 0,
    }
    monkeypatch.setattr(executor, "load_binding", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(local_lifecycle, "execute", lambda *_args: result)
    response = respond("status", request_for("status"))
    assert response["status"] == "validated"
    assert response["result"] == result


def test_failure_reference_helper_accepts_only_fully_validated_requests():
    assert failure_result("prepare", request_for("prepare")) == {}
    assert failure_result("verify", BASE) == {}
    assert failure_result("apply", None) == {}
    with pytest.raises(ContractError):
        failure_result("apply", {"operation": OPERATION})
