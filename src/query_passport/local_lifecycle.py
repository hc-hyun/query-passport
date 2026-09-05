"""Local operation coordinator; all paths and privileges come from operator bindings.

The public CLI dispatches through the closed lifecycle contract. Every mutating
phase is recorded before the backend is invoked. A timeout
means unknown external state, not that the database transaction was rolled back.
"""

import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

from . import executor, operation_store
from .contract import ContractError, matches, object_fields, parse_json, require, validate
from .lifecycle_binding import validate_lifecycle_binding, verification_projection
from .process import run_process


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def binding_digest(binding: dict[str, Any]) -> str:
    # Renewal may extend the authorization deadline, but cannot change any scope,
    # identity, execution path or approved operation without a fresh plan.
    return digest({key: value for key, value in binding.items() if key != "expires_at"})


def issuer(binding: dict[str, Any], operation_id: str, input_digest: str) -> dict[str, Any]:
    configuration = binding["lifecycle"]

    def call(payload: dict[str, Any]) -> dict[str, Any]:
        code, raw = run_process(
            [sys.executable, "-I", "-m", "query_passport.local_pki"],
            env=executor.PROCESS_ENV,
            stdin=canonical(payload),
            timeout=20,
            limit=8192,
        )
        try:
            value = parse_json(raw)
            object_fields(value, {"status", "metadata", "error"})
            require(code in (0, 1))
            if code == 1:
                require(value["status"] == "failed" and value["metadata"] == {})
                # PKI-specific details remain in the issuer; no provider strings
                # or arbitrary error names become part of the public response.
                raise ContractError("RECOVERY_REQUIRED")
            require(value["status"] == "succeeded" and value["error"] is None)
            metadata = value["metadata"]
            require(type(metadata) is dict)
            require(matches(metadata.get("certificate_sha256"), r"sha256:[a-f0-9]{64}", 71))
            for field in ("not_before", "not_after"):
                require(matches(metadata.get(field), r"[0-9T:.+Z-]+", 40))
            selected = {
                key: metadata[key] for key in ("certificate_sha256", "not_before", "not_after")
            }
            if payload["command"] == "issue-client":
                for name in ("authority_sha256", "server_ca_sha256"):
                    require(matches(metadata.get(name), r"sha256:[a-f0-9]{64}", 71))
                    selected[name] = metadata[name]
            return selected
        except ContractError as error:
            if error.code == "RECOVERY_REQUIRED":
                raise
            raise ContractError("EXECUTOR_FAILED") from error

    if configuration["allow_initialize_authority"]:
        call(
            {
                "command": "initialize-authority",
                "authority_dir": configuration["authority_dir"],
                "authority_id": configuration["authority_id"],
            }
        )
    return call(
        {
            "command": "issue-client",
            "authority_dir": configuration["authority_dir"],
            "generations_dir": configuration["generations_dir"],
            "operation_id": operation_id,
            "input_digest": input_digest,
            "common_name": binding["expected_dn"][3:],
            "server_ca_file": configuration["server_ca_file"],
            "lifetime_days": configuration["lifetime_days"],
        }
    )


def client_trust(binding: dict[str, Any], expected_fingerprint: str) -> bytes:
    """Read only the issuer's public CA internally; never read or return its key."""
    directory = descriptor = -1
    try:
        directory = executor.private_directory(binding["lifecycle"]["authority_dir"])
        descriptor = os.open(
            "ca.crt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 65536
        ):
            raise ContractError("CREDENTIAL_ACCESS_DENIED")
        value = os.read(descriptor, 65537)
        after = os.fstat(descriptor)
        if (
            not value
            or len(value) > 65536
            or (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ContractError("TARGET_DRIFT")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        try:
            certificate = x509.load_pem_x509_certificate(value)
            fingerprint = "sha256:" + certificate.fingerprint(hashes.SHA256()).hex()
        except ValueError as error:
            raise ContractError("CREDENTIAL_ACCESS_DENIED") from error
        if fingerprint != expected_fingerprint:
            raise ContractError("TARGET_DRIFT")
        return value
    except OSError as error:
        raise ContractError("CREDENTIAL_ACCESS_DENIED") from error
    finally:
        for descriptor in (descriptor, directory):
            if descriptor >= 0:
                os.close(descriptor)


def set_runtime_permissions(binding: dict[str, Any], candidate: Path) -> None:
    """A fixed helper can chown only the fresh bundle it is explicitly mounted."""
    # The delivery module has pinned, created and checked this directory, and
    # validates its inode, entries and modes again after the callback.
    script = (
        "set -eu; test ! -L /bundle; "
        "test -f /bundle/ca.crt; test -f /bundle/client.crt; test -f /bundle/client.key; "
        "chmod 0755 /bundle; chmod 0644 /bundle/ca.crt /bundle/client.crt; "
        "chmod 0640 /bundle/client.key; "
        "chown 0:10001 /bundle /bundle/ca.crt /bundle/client.crt /bundle/client.key"
    )
    name = "query-passport-delivery-" + uuid.uuid4().hex
    prior_error: BaseException | None = None
    try:
        executor.docker(
            [
                "run",
                "--rm",
                "--pull=never",
                "--log-driver=none",
                "--network=none",
                "--name",
                name,
                "--user=0:0",
                "--read-only",
                "--cap-drop=ALL",
                "--cap-add=CHOWN",
                "--cap-add=FOWNER",
                "--cap-add=DAC_OVERRIDE",
                "--security-opt=no-new-privileges",
                "--pids-limit=16",
                "--memory=64m",
                "--mount",
                f"type=bind,src={candidate},dst=/bundle",
                "--entrypoint=/usr/bin/env",
                binding["database_image_id"],
                "-i",
                "PATH=/usr/bin:/bin",
                "/bin/sh",
                "-c",
                script,
            ],
            timeout=15,
            limit=1024,
        )
    except BaseException as error:
        prior_error = error
        raise
    finally:
        executor.cleanup_container(name, prior_error=prior_error)


def _summary(plan: dict[str, Any], phase: str) -> dict[str, Any]:
    return {
        "operation_id": plan["operation_id"],
        "plan_digest": digest(plan),
        "phase": phase,
        "intent": plan["intent"],
        "mode": "live",
        "source_count": plan["request"]["source_count"],
        "source_inventory": "not_checked",
        "reader_permissions": "not_checked",
        "source_admission": "not_checked",
        "deployment": "not_checked",
        "application_readiness": "not_checked",
        "certificate_validation": "passed" if phase == "verified" else "not_checked",
        "db_connectivity": "passed" if phase == "verified" else "not_checked",
        "authentication": "passed" if phase == "verified" else "not_checked",
        "target_identity": "passed",
        "recovery": "owned_changes_only",
    }


def prepare(
    request: dict[str, Any], binding: dict[str, Any], *, intent: str = "provision"
) -> dict[str, Any]:
    from . import credential_delivery, db_admin

    request = validate(request)
    require(intent in {"provision", "rotate"})
    validate_lifecycle_binding(binding, request, "prepare")
    with operation_store.target_lock(binding["container_id"]):
        target = executor.target_snapshot(binding)
        before = db_admin.snapshot(binding)
        previous = credential_delivery.inspect_delivery(Path(binding["credential_dir"]))
        rotation = None
        if intent == "provision":
            db_admin.validate_provision(binding, before)
            if previous["generation_id"] is not None:
                raise ContractError("TARGET_DRIFT")
        else:
            rotation = _prepare_rotation(request, binding, previous)
        if executor.target_snapshot(binding) != target:
            raise ContractError("TARGET_DRIFT")
        with operation_store.operation() as operation:
            plan = {
                "version": 1,
                "operation_id": operation.operation_id,
                "intent": intent,
                "request": request,
                "binding_digest": binding_digest(binding),
                "target_snapshot": target,
                "before": before,
                "previous": previous,
            }
            if rotation is not None:
                plan["rotation"] = rotation
            encoded = canonical(plan)
            # Reuse the closed parser/depth limits on readback; reject before any
            # execution if a configuration cannot fit in a bounded private plan.
            parse_json(encoded)
            operation.write_artifact("plan.json", encoded)
            operation.record("prepared")
            return {
                **_summary(plan, "prepared"),
                "actions": (
                    [
                        "issue_client_certificate",
                        "create_restricted_check_role",
                        "append_client_ca_trust",
                        "install_owned_auth_rules",
                        "publish_verified_credential",
                    ]
                    if intent == "provision"
                    else [
                        "issue_client_certificate",
                        "verify_new_connections",
                        "publish_verified_credential",
                    ]
                ),
                "preserves": [
                    "existing_database_objects",
                    "existing_roles_and_grants",
                    "existing_server_credentials",
                    "existing_client_trust",
                    "previous_credential_generations",
                ],
                "account": binding["username"],
                "client_dn": binding["expected_dn"],
                "certificate_lifetime_days": binding["lifecycle"]["lifetime_days"],
            }


def _load_plan(
    operation: operation_store.Operation,
    request: dict[str, Any],
    binding: dict[str, Any],
    plan_digest: str,
    *,
    allow_retired: bool = False,
) -> dict[str, Any]:
    plan = parse_json(operation.read_artifact("plan.json"))
    object_fields(
        plan,
        {
            "version",
            "operation_id",
            "intent",
            "request",
            "binding_digest",
            "target_snapshot",
            "before",
            "previous",
        },
        {"rotation"},
    )
    if (
        plan["version"] != 1
        or type(plan["version"]) is not int
        or plan["operation_id"] != operation.operation_id
        or plan["intent"] not in ("provision", "rotate")
        or (plan["intent"] == "rotate") != ("rotation" in plan)
        or plan["request"] != request
        or plan["binding_digest"] != binding_digest(binding)
        or digest(plan) != plan_digest
    ):
        raise ContractError("TARGET_DRIFT")
    if not operation.events() or (
        not allow_retired and any(event["phase"] == "rolled_back" for event in operation.events())
    ):
        raise ContractError("RECOVERY_REQUIRED")
    if executor.target_snapshot(binding) != plan["target_snapshot"]:
        raise ContractError("TARGET_DRIFT")
    return dict(plan)


def _save_once(operation: operation_store.Operation, name: str, value: Any) -> None:
    encoded = canonical(value)
    if name in os.listdir(operation.directory):
        if operation.read_artifact(name) != encoded:
            raise ContractError("TARGET_DRIFT")
    else:
        operation.write_artifact(name, encoded)


def _applied_plan(operation: operation_store.Operation, plan: dict[str, Any]) -> dict[str, Any]:
    receipt = parse_json(operation.read_artifact("db.applied.json"))
    object_fields(receipt, {"ca_digest"})
    require(matches(receipt["ca_digest"], r"sha256:[a-f0-9]{64}", 71))
    return {**plan, "applied_ca_digest": receipt["ca_digest"]}


def _prepare_rotation(
    request: dict[str, Any], binding: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    from . import db_admin

    previous_id = previous["generation_id"]
    if previous_id is None:
        raise ContractError("RECOVERY_REQUIRED")
    with operation_store.operation(previous_id) as predecessor:
        stored = parse_json(predecessor.read_artifact("plan.json"))
        old_plan = _load_plan(predecessor, request, binding, digest(stored))
        if predecessor.events()[-1]["phase"] != "verified":
            raise ContractError("RECOVERY_REQUIRED")
        if parse_json(predecessor.read_artifact("delivery.json")) != previous:
            raise ContractError("TARGET_DRIFT")
        issuance = parse_json(predecessor.read_artifact("issuance.json"))
        old_owner = old_plan.get("rotation", {})
        rotation = {
            "owner_operation_id": old_owner.get("owner_operation_id", previous_id),
            "owner_plan_digest": old_owner.get("owner_plan_digest", digest(old_plan)),
            "predecessor_plan_digest": digest(old_plan),
            "authority_sha256": issuance["authority_sha256"],
            "server_ca_sha256": issuance["server_ca_sha256"],
        }
    owner = _rotation_owner(request, binding, {"rotation": rotation, "previous": previous})
    db_admin.verify_applied(binding, owner, owner["operation_id"])
    return rotation


def _rotation_owner(
    request: dict[str, Any], binding: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a verified predecessor and its original DB owner without copying history."""
    rotation = plan["rotation"]
    object_fields(
        rotation,
        {
            "owner_operation_id",
            "owner_plan_digest",
            "predecessor_plan_digest",
            "authority_sha256",
            "server_ca_sha256",
        },
    )
    require(matches(rotation["owner_operation_id"], r"[a-f0-9]{32}", 32))
    for name in (
        "owner_plan_digest",
        "predecessor_plan_digest",
        "authority_sha256",
        "server_ca_sha256",
    ):
        require(matches(rotation[name], r"sha256:[a-f0-9]{64}", 71))
    previous_id = plan["previous"]["generation_id"]
    require(matches(previous_id, r"[a-f0-9]{32}", 32))
    require(plan.get("operation_id") not in {previous_id, rotation["owner_operation_id"]})
    with operation_store.operation(previous_id) as predecessor:
        _load_plan(predecessor, request, binding, rotation["predecessor_plan_digest"])
        if predecessor.events()[-1]["phase"] != "verified":
            raise ContractError("RECOVERY_REQUIRED")
        if parse_json(predecessor.read_artifact("delivery.json")) != plan["previous"]:
            raise ContractError("TARGET_DRIFT")
    with operation_store.operation(rotation["owner_operation_id"]) as original:
        owner = _load_plan(original, request, binding, rotation["owner_plan_digest"])
        if owner["intent"] != "provision" or original.events()[-1]["phase"] != "verified":
            raise ContractError("RECOVERY_REQUIRED")
        issuance = parse_json(original.read_artifact("issuance.json"))
        if any(
            issuance[name] != rotation[name] for name in ("authority_sha256", "server_ca_sha256")
        ):
            raise ContractError("TARGET_DRIFT")
        return _applied_plan(original, owner)


def _verify_generation(
    operation: operation_store.Operation,
    request: dict[str, Any],
    binding: dict[str, Any],
    applied_plan: dict[str, Any],
    candidate: Path,
) -> None:
    from . import db_admin
    from .policy_verification import run_policy_verification

    operation.record("verifying")
    db_admin.verify_applied(binding, applied_plan, applied_plan["operation_id"])
    projected = verification_projection(binding, str(candidate))
    for check in (executor.run_verification, run_policy_verification, executor.run_verification):
        verified = check(projected, request)
        if verified["status"] != "succeeded":
            raise ContractError(verified["error"])
    db_admin.verify_applied(binding, applied_plan, applied_plan["operation_id"])


def _deliver_generation(
    operation: operation_store.Operation,
    plan: dict[str, Any],
    request: dict[str, Any],
    binding: dict[str, Any],
    applied_plan: dict[str, Any],
) -> None:
    from . import credential_delivery, db_admin

    db_admin.verify_applied(binding, applied_plan, applied_plan["operation_id"])
    _save_once(operation, "issuance.json", issuer(binding, operation.operation_id, digest(plan)))
    boundary_failure = None

    def verify_candidate(candidate: Path) -> None:
        nonlocal boundary_failure
        try:
            _verify_generation(operation, request, binding, applied_plan, candidate)
        except ContractError as error:
            boundary_failure = error.code
            raise

    def permissions(candidate: Path) -> None:
        nonlocal boundary_failure
        try:
            set_runtime_permissions(binding, candidate)
        except ContractError as error:
            boundary_failure = error.code
            raise

    operation.record("delivering")
    try:
        delivered = credential_delivery.deliver(
            Path(binding["lifecycle"]["generations_dir"]) / operation.operation_id / "bundle",
            Path(binding["credential_dir"]),
            operation.operation_id,
            expected_revision=plan["previous"],
            permission_setter=permissions,
            validator=verify_candidate,
        )
    except Exception:
        if boundary_failure is not None:
            raise ContractError(boundary_failure) from None
        raise
    _save_once(
        operation,
        "delivery.json",
        {key: delivered[key] for key in ("generation_id", "revision", "certificate_sha256")},
    )
    operation.record("delivered")


def _check_rollback_pointer(plan: dict[str, Any], binding: dict[str, Any]) -> None:
    from . import credential_delivery

    active = credential_delivery.inspect_delivery(Path(binding["credential_dir"]))
    if active["generation_id"] not in {plan["operation_id"], plan["previous"]["generation_id"]}:
        # An older operation must not disable the account used by a newer active
        # generation. Revert child rotations in order before the original DB plan.
        raise ContractError("TARGET_DRIFT")


def _execute_rotation(
    command: str,
    operation: operation_store.Operation,
    plan: dict[str, Any],
    request: dict[str, Any],
    binding: dict[str, Any],
) -> dict[str, Any]:
    from . import credential_delivery, db_admin

    if command not in {"rotate", "rollback"}:
        raise ContractError("UNSUPPORTED_OPERATION")
    phases = {event["phase"] for event in operation.events()}
    _check_rollback_pointer(plan, binding)
    if command != "rollback" and "rolling_back" in phases:
        raise ContractError("RECOVERY_REQUIRED")
    owner = _rotation_owner(request, binding, plan)
    db_admin.verify_applied(binding, owner, owner["operation_id"])
    operation.record("rolling_back" if command == "rollback" else "issuing")
    try:
        if command == "rotate":
            if db_admin.snapshot(binding) != plan["before"]:
                raise ContractError("TARGET_DRIFT")
            metadata = issuer(binding, operation.operation_id, digest(plan))
            if any(
                metadata[name] != plan["rotation"][name]
                for name in ("authority_sha256", "server_ca_sha256")
            ):
                raise ContractError("TARGET_DRIFT")
            if metadata["certificate_sha256"] == plan["previous"]["certificate_sha256"]:
                raise ContractError("VERIFICATION_FAILED")
            _save_once(operation, "issuance.json", metadata)
            operation.record("issued")
            operation.record("checking_delivery")
            _deliver_generation(operation, plan, request, binding, owner)
            phase = "verified"
        else:
            if "delivering" in phases:
                candidate = (
                    Path(binding["credential_dir"])
                    / "versions"
                    / plan["previous"]["generation_id"]
                    / "bundle"
                )
                _verify_generation(operation, request, binding, owner, candidate)
                credential_delivery.rollback(
                    Path(binding["credential_dir"]), operation.operation_id, plan["previous"]
                )
            phase = "rolled_back"
        if executor.target_snapshot(binding) != plan["target_snapshot"]:
            raise ContractError("TARGET_DRIFT")
        operation.record(phase)
        return _summary(plan, phase)
    except BaseException as error:
        code = (
            error.code
            if isinstance(error, ContractError)
            else "INTERRUPTED"
            if isinstance(error, (KeyboardInterrupt, SystemExit))
            else "RECOVERY_REQUIRED"
        )
        operation.record(
            "unknown" if code in {"TIMEOUT", "INTERRUPTED"} else "partial_failure", code
        )
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise ContractError(code) from None


def execute(
    command: str,
    request: dict[str, Any],
    binding: dict[str, Any],
    operation_id: str,
    plan_digest: str,
) -> dict[str, Any]:
    """Resume one explicit phase after reconciling its owned state.

    Return values contain no private paths, configuration text or issuer output.
    Reissuing uses the same generation ID; failed apply/delivery never silently
    proceeds to a later phase and rollback cannot reactivate a retired operation.
    """
    from . import credential_delivery, db_admin

    request = validate(request)
    validate_lifecycle_binding(binding, request, command)
    require(command in {"issue", "apply", "deliver", "rotate", "rollback", "status"})
    require(matches(operation_id, r"[a-f0-9]{32}", 32))
    require(matches(plan_digest, r"sha256:[a-f0-9]{64}", 71))
    with operation_store.target_lock(binding["container_id"]):
        with operation_store.operation(operation_id) as operation:
            plan = _load_plan(
                operation,
                request,
                binding,
                plan_digest,
                allow_retired=command in {"rollback", "status"},
            )
            phases = {event["phase"] for event in operation.events()}
            if command == "status":
                # Historical observations only; this is not a fresh DB verification.
                result = _summary(plan, operation.events()[-1]["phase"])
                for field in ("db_connectivity", "authentication", "certificate_validation"):
                    result[field] = "not_checked"
                return result
            if plan["intent"] == "rotate":
                return _execute_rotation(command, operation, plan, request, binding)
            if command == "rotate":
                raise ContractError("UNSUPPORTED_OPERATION")
            if command == "rollback" and "delivering" in phases:
                _check_rollback_pointer(plan, binding)
            stage = {
                "issue": "issuing",
                "apply": "applying",
                "deliver": "checking_delivery",
                "rollback": "rolling_back",
            }[command]
            if command == "apply" and "issued" not in phases:
                raise ContractError("RECOVERY_REQUIRED")
            if command == "deliver" and "applied" not in phases:
                raise ContractError("RECOVERY_REQUIRED")
            if command == "apply" and phases & {"delivering", "delivered", "verified"}:
                raise ContractError("RECOVERY_REQUIRED")
            if command == "issue" and phases & {
                "applying",
                "applied",
                "delivering",
                "delivered",
                "verified",
                "rolling_back",
            }:
                raise ContractError("RECOVERY_REQUIRED")
            if command != "rollback" and "rolling_back" in phases:
                raise ContractError("RECOVERY_REQUIRED")
            operation.record(stage)
            try:
                if command == "issue":
                    if db_admin.snapshot(binding) != plan["before"]:
                        raise ContractError("TARGET_DRIFT")
                    metadata = issuer(binding, operation_id, digest(plan))
                    _save_once(operation, "issuance.json", metadata)
                    phase = "issued"
                elif command == "apply":
                    metadata = parse_json(operation.read_artifact("issuance.json"))
                    trust = client_trust(binding, metadata["authority_sha256"])
                    if "applied" not in phases:
                        applied = db_admin.apply(binding, plan, operation_id, trust)
                        require(matches(applied["ca_digest"], r"sha256:[a-f0-9]{64}", 71))
                        _save_once(
                            operation, "db.applied.json", {"ca_digest": applied["ca_digest"]}
                        )
                    db_admin.verify_applied(binding, _applied_plan(operation, plan), operation_id)
                    phase = "applied"
                elif command == "deliver":
                    _deliver_generation(
                        operation, plan, request, binding, _applied_plan(operation, plan)
                    )
                    phase = "verified"
                else:
                    if "applying" in phases:
                        db_admin.rollback(binding, plan, operation_id)
                    if "delivering" in phases:
                        credential_delivery.rollback(
                            Path(binding["credential_dir"]), operation_id, plan["previous"]
                        )
                    phase = "rolled_back"
                if executor.target_snapshot(binding) != plan["target_snapshot"]:
                    raise ContractError("TARGET_DRIFT")
                operation.record(phase)
                return _summary(plan, phase)
            except BaseException as error:
                code = (
                    error.code
                    if isinstance(error, ContractError)
                    else "INTERRUPTED"
                    if isinstance(error, (KeyboardInterrupt, SystemExit))
                    else "RECOVERY_REQUIRED"
                )
                operation.record(
                    "unknown" if code in {"TIMEOUT", "INTERRUPTED"} else "partial_failure", code
                )
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                raise ContractError(code) from None
