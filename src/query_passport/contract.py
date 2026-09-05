"""Closed M1 projection of caller-validated Query Man profile v1 input.

This is not a Query Man YAML or source inventory validator. No input strings are
copied into results or exception messages, including unknown field names.
"""

import hashlib
import json
import re
from typing import Any

from . import __version__

MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 16384
MAX_DEPTH = 8
TIMEOUT_SECONDS = 5
POLICY_REVISION = "m2-local-docker-1"
COMMANDS = ("capabilities", "inspect", "plan", "verify")
FUTURE_COMMANDS = ("issue", "apply", "deliver", "rotate", "rollback")
CAPABILITIES = ("profile.inspect.v1", "plan.offline.v1", "connection.verify.v1")
ERRORS = {
    "INVALID_INPUT": (2, "Input does not match the public request contract."),
    "UNSUPPORTED_OPERATION": (3, "The requested command or capability is not implemented."),
    "UNSUPPORTED_VERSION": (3, "The requested contract or profile version is not supported."),
    "INPUT_ACCESS_DENIED": (4, "Input must be a public regular JSON file inside the workspace."),
    "INPUT_TOO_LARGE": (2, "Input exceeds the request size limit."),
    "TIMEOUT": (5, "The command exceeded its time limit."),
    "INTERNAL_ERROR": (1, "The offline command could not complete."),
    "OUTPUT_TOO_LARGE": (1, "The result exceeds the output size limit."),
    "INTERRUPTED": (130, "The offline command was interrupted."),
    "AUTHORIZATION_REQUIRED": (6, "A valid operator-managed executor binding is required."),
    "TARGET_MISMATCH": (7, "The request or observed target does not match the executor binding."),
    "TARGET_DRIFT": (7, "The target changed during the operation."),
    "EXECUTOR_FAILED": (8, "The executor did not return a valid bounded result."),
    "CREDENTIAL_ACCESS_DENIED": (8, "Credential access or file permissions failed validation."),
    "TLS_VERIFICATION_FAILED": (8, "Server TLS verification failed."),
    "CLIENT_AUTHENTICATION_FAILED": (8, "Client certificate authentication failed."),
    "PERMISSION_DENIED": (8, "The bound identity lacks the required diagnostic permissions."),
    "CONNECTION_FAILED": (8, "The bound database connection could not be established."),
    "VERIFICATION_FAILED": (8, "The requested live verification did not pass."),
    "RECOVERY_REQUIRED": (9, "An owned diagnostic resource needs executor cleanup."),
}


class ContractError(Exception):
    def __init__(self, code: str = "INVALID_INPUT") -> None:
        self.code = code
        super().__init__(ERRORS[code][1])


def require(condition: bool) -> None:
    if not condition:
        raise ContractError()


def object_fields(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    require(type(value) is dict)
    require(required <= value.keys() <= required | (optional or set()))


def matches(value: Any, pattern: str, maximum: int) -> bool:
    return type(value) is str and len(value) <= maximum and re.fullmatch(pattern, value) is not None


def validate(request: Any) -> dict[str, Any]:
    object_fields(
        request,
        {
            "contract_version",
            "profile_version",
            "scope",
            "environment",
            "deployment_alias",
            "target_alias",
            "profile",
            "source_count",
        },
        {"required_capabilities"},
    )
    require(type(request["contract_version"]) is str)
    require(type(request["profile_version"]) is int)
    if request["contract_version"] != "1" or request["profile_version"] != 1:
        raise ContractError("UNSUPPORTED_VERSION")
    require(request["scope"] == "database-only")
    require(request["environment"] in ("local-synthetic", "local", "protected"))
    for field in ("deployment_alias", "target_alias"):
        require(matches(request[field], r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", 63))
    count = request["source_count"]
    require(type(count) is int and 0 <= count <= 1000000)
    capabilities = request.get("required_capabilities", [])
    require(type(capabilities) is list and len(capabilities) <= 16)
    for capability in capabilities:
        require(matches(capability, r"[a-z][a-z0-9]*(?:[.][a-z0-9]+)+", 64))
    require(len(set(capabilities)) == len(capabilities))
    if any(capability not in CAPABILITIES for capability in capabilities):
        raise ContractError("UNSUPPORTED_OPERATION")
    profile = request["profile"]
    object_fields(profile, {"id", "host", "port", "database", "sslmode", "authentication"})
    require(matches(profile["id"], r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", 63))
    require(matches(profile["host"], r"[A-Za-z0-9.-]+", 253))
    for label in profile["host"].split("."):
        require(matches(label, r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", 63))
    require(type(profile["port"]) is int and 1 <= profile["port"] <= 65535)
    require(matches(profile["database"], r"[A-Za-z_][A-Za-z0-9_]*", 63))
    require(profile["sslmode"] == "verify-full")
    object_fields(profile["authentication"], {"type"})
    require(profile["authentication"]["type"] == "client-certificate")
    return dict(request)


def parse_json(raw: bytes) -> Any:
    if len(raw) > MAX_INPUT_BYTES:
        raise ContractError("INPUT_TOO_LARGE")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def constant(_: str) -> Any:
        raise ContractError()

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        stack = [(parsed, 1)]
        while stack:
            item, depth = stack.pop()
            require(depth <= MAX_DEPTH)
            if isinstance(item, dict):
                stack.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                stack.extend((value, depth + 1) for value in item)
        return parsed
    except (ValueError, RecursionError) as error:
        raise ContractError() from error


def decode(raw: bytes) -> dict[str, Any]:
    return validate(parse_json(raw))


def envelope(
    command: str | None,
    status: str,
    result: dict[str, Any],
    scope: str | None = None,
    code: str | None = None,
) -> dict[str, Any]:
    return {
        "contract_version": "1",
        "tool_version": __version__,
        "command": command,
        "status": status,
        "scope": scope,
        "result": result,
        "errors": [] if code is None else [{"code": code, "message": ERRORS[code][1]}],
    }


def respond(command: str, request: dict[str, Any] | None = None) -> dict[str, Any]:
    if command == "verify":
        from .executor import verify_request

        return verify_request(validate(request))
    if command == "capabilities":
        return envelope(
            command,
            "validated",
            {
                "supported_contract_majors": [1],
                "capabilities": list(CAPABILITIES),
                "commands": list(COMMANDS),
                "backend_types": ["offline", "local-docker"],
                "policy_revision": POLICY_REVISION,
                "profile_versions": [1],
                "source_reference_version": 6,
                "scopes": ["database-only"],
                "environments": ["local-synthetic", "local", "protected"],
                "live_environments": ["local-synthetic", "local"],
                "limits": {
                    "input_bytes": MAX_INPUT_BYTES,
                    "output_bytes": MAX_OUTPUT_BYTES,
                    "json_depth": MAX_DEPTH,
                    "timeout_seconds": TIMEOUT_SECONDS,
                    "live_timeout_seconds": 60,
                },
            },
        )
    if command not in COMMANDS:
        raise ContractError("UNSUPPORTED_OPERATION")
    request = validate(request)
    result: dict[str, Any] = {
        "mode": "offline",
        "profile_count": 1,
        "source_count": request["source_count"],
        "profile_validation": "passed",
        "profile_validation_scope": "public_projection_only",
        "source_inventory": "not_checked",
        "query_man_validation": "not_checked",
        "target_identity": "not_checked",
        "db_connectivity": "not_checked",
        "certificate_validation": "not_checked",
        "authentication": "not_checked",
        "deployment": "not_checked",
        "reader_permissions": "not_checked",
        "source_admission": "not_checked",
        "application_readiness": "not_checked",
    }
    if command == "plan":
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        result.update(
            {
                "input_digest": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
                "policy_revision": POLICY_REVISION,
                "executable": False,
                "target_snapshot": "unknown",
                "differences": "unknown",
                "actions": [],
                "desired_state": {"sslmode": "verify-full", "authentication": "client-certificate"},
                "required_capabilities": ["connection.verify.v1"],
                "next_action": "authorized_read_only_verification",
                "preconditions": [
                    "query_man_profile_validation",
                    "authorized_executor_target_binding",
                    "live_target_snapshot",
                ],
                "verification": [
                    "target_identity",
                    "db_connectivity",
                    "certificate_validation",
                    "authentication",
                    "deployment",
                ],
                "stop_conditions": [
                    "unsupported_capability",
                    "missing_authorization",
                    "target_mismatch",
                ],
                "recovery": "no_changes_performed",
            }
        )
        digest = json.dumps(result, sort_keys=True, separators=(",", ":"))
        result["plan_digest"] = "sha256:" + hashlib.sha256(digest.encode()).hexdigest()
    return envelope(
        command, "planned" if command == "plan" else "validated", result, "database-only"
    )
