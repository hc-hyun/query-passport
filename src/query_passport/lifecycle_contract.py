"""Closed public lifecycle requests and classified local executor dispatch.

An operation reference selects a private plan; it grants no execution authority.
Only the operator-managed binding authorizes each requested lifecycle command.
"""

from typing import Any

from .contract import (
    LIFECYCLE_COMMANDS,
    ContractError,
    envelope,
    matches,
    object_fields,
    parse_json,
    require,
    validate,
)

_STATE_ERRORS = {
    "STATE_ACCESS_DENIED",
    "STATE_WRITE_FAILED",
    "STATE_INVALID",
    "STATE_CONFLICT",
    "STATE_PARTIAL",
    "OPERATION_BUSY",
}
_DELIVERY_ERRORS = {
    "DELIVERY_INVALID_INPUT": "EXECUTOR_FAILED",
    "DELIVERY_ACCESS_DENIED": "CREDENTIAL_ACCESS_DENIED",
    "DELIVERY_OWNERSHIP_REQUIRED": "RECOVERY_REQUIRED",
    "DELIVERY_INPUT_CONFLICT": "TARGET_DRIFT",
    "DELIVERY_DRIFT": "TARGET_DRIFT",
    "DELIVERY_PARTIAL_STATE": "RECOVERY_REQUIRED",
    "DELIVERY_PERMISSION_DENIED": "CREDENTIAL_ACCESS_DENIED",
    "DELIVERY_BUSY": "RECOVERY_REQUIRED",
    "DELIVERY_ROLLED_BACK": "RECOVERY_REQUIRED",
    "DELIVERY_VALIDATION_FAILED": "VERIFICATION_FAILED",
    "INTERNAL_ERROR": "INTERNAL_ERROR",
}


def validate_request(command: str, request: Any) -> dict[str, Any]:
    """Validate a command-specific request without altering the base projection."""
    if command not in LIFECYCLE_COMMANDS:
        return validate(request)
    require(type(request) is dict)
    base = dict(request)
    if command == "prepare":
        intent = base.pop("intent", "provision")
        require(type(intent) is str and intent in ("provision", "rotate"))
        validate(base)
        return {**base, "intent": intent}
    operation = base.pop("operation", None)
    object_fields(operation, {"id", "plan_digest"})
    require(matches(operation["id"], r"[a-f0-9]{32}", 32))
    require(matches(operation["plan_digest"], r"sha256:[a-f0-9]{64}", 71))
    validate(base)
    return {**base, "operation": dict(operation)}


def decode_request(command: str, raw: bytes) -> dict[str, Any]:
    return validate_request(command, parse_json(raw))


def failure_result(command: str | None, request: dict[str, Any] | None) -> dict[str, Any]:
    """Return only a fully validated operation reference, never a phase guess."""
    if command not in LIFECYCLE_COMMANDS or command == "prepare" or request is None:
        return {}
    validated = validate_request(command, request)
    return {
        "operation_id": validated["operation"]["id"],
        "plan_digest": validated["operation"]["plan_digest"],
        "outcome": "not_confirmed",
        "next_action": "status_or_scoped_recovery",
    }


def respond_lifecycle(command: str, request: Any) -> dict[str, Any]:
    # Keep offline discovery/inspection independent of runtime-only imports.
    from . import executor, local_lifecycle
    from .credential_delivery import DeliveryError
    from .operation_store import StateError

    require(command in LIFECYCLE_COMMANDS)
    validated = validate_request(command, request)
    base = dict(validated)
    intent = base.pop("intent", "provision")
    operation = base.pop("operation", None)
    try:
        binding = executor.load_binding(base, operation=command)
        if command == "prepare":
            result = local_lifecycle.prepare(base, binding, intent=intent)
        else:
            assert operation is not None
            result = local_lifecycle.execute(
                command, base, binding, operation["id"], operation["plan_digest"]
            )
    except StateError as error:
        raise ContractError(
            "RECOVERY_REQUIRED" if error.code in _STATE_ERRORS else "INTERNAL_ERROR"
        ) from None
    except DeliveryError as error:
        raise ContractError(_DELIVERY_ERRORS.get(error.code, "INTERNAL_ERROR")) from None
    status = (
        "planned" if command == "prepare" else "validated" if command == "status" else "succeeded"
    )
    return envelope(command, status, result, "database-only")
