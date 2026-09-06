"""Local Docker executor. Binding files are operator-owned, never public requests.

The authenticated OS account and its private binding directory form the local
authorization boundary. This is not a protected-environment approval backend.
"""

import hashlib
import ipaddress
import json
import os
import pwd
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from .contract import ContractError, envelope, matches, object_fields, parse_json, require, validate
from .process import run_process

DOCKER = "/usr/bin/docker"
DOCKER_ARGS = [DOCKER, "--host", "unix:///var/run/docker.sock"]
PROCESS_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
    "LANG": "C.UTF-8",
}
MAX_BINDING_BYTES = 16384


def docker(
    args: list[str],
    *,
    stdin: bytes | None = None,
    timeout: float = 10,
    limit: int = 16384,
    worker_output: bool = False,
) -> bytes:
    """Run one fixed executor operation with bounded output, time and no raw stderr."""
    code, output = run_process(
        DOCKER_ARGS + args, env=PROCESS_ENV, stdin=stdin, timeout=timeout, limit=limit
    )
    if worker_output and code in (0, 1):
        try:
            result = parse_json(output)
        except ContractError as error:
            raise ContractError("EXECUTOR_FAILED") from error
        if type(result) is not dict or result.get("status") != (
            "succeeded" if code == 0 else "failed"
        ):
            raise ContractError("EXECUTOR_FAILED")
    elif code != 0:
        raise ContractError("EXECUTOR_FAILED")
    return output


def _uncertain(error: BaseException | None) -> bool:
    return isinstance(error, (KeyboardInterrupt, SystemExit)) or (
        isinstance(error, ContractError) and error.code in {"TIMEOUT", "INTERRUPTED"}
    )


def cleanup_container(name: str, *, prior_error: BaseException | None = None) -> None:
    """Remove one fresh owned container without replacing the original failure.

    The caller retains and rethrows its original exception. A timeout or interrupt
    first encountered during cleanup also remains uncertain, even if a later
    observation finds the container absent; observation does not complete the
    interrupted Docker request.
    """
    if not matches(name, r"query-passport-(?:verify|policy|delivery)-[a-f0-9]{32}", 96):
        raise ContractError("AUTHORIZATION_REQUIRED")
    cleanup_error: BaseException | None = None
    try:
        docker(["rm", "-f", name], timeout=5)
    except BaseException as removal_error:  # noqa: BLE001 - preserve the first uncertainty
        try:
            remaining = docker(
                ["ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"],
                timeout=5,
            )
            if remaining.strip():
                cleanup_error = ContractError("EXECUTOR_CLEANUP_FAILED")
        except BaseException as observation_error:  # noqa: BLE001 - bounded cleanup classification
            cleanup_error = (
                observation_error
                if _uncertain(observation_error)
                else ContractError("EXECUTOR_CLEANUP_FAILED")
            )
        if _uncertain(removal_error):
            cleanup_error = removal_error
        elif not isinstance(removal_error, ContractError):
            cleanup_error = cleanup_error or ContractError("EXECUTOR_CLEANUP_FAILED")
    if cleanup_error is not None and prior_error is None:
        raise cleanup_error


def binding_directory() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".config/query-passport/executors"


def private_directory(path: str, *, runtime_owner: bool = False) -> int:
    """Walk trusted-owned directories; permit root's sticky temporary directory."""
    parsed = Path(path)
    if not parsed.is_absolute() or ".." in parsed.parts:
        raise ContractError("AUTHORIZATION_REQUIRED")
    owners = {0, os.geteuid()} | ({10001} if runtime_owner else set())
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open("/", flags)
    try:
        for part in (*parsed.parts[1:], None):
            info = os.fstat(directory)
            mode = stat.S_IMODE(info.st_mode)
            sticky_root = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
            if info.st_uid not in owners or (mode & 0o022 and not sticky_root):
                raise ContractError("AUTHORIZATION_REQUIRED")
            if part is not None:
                child = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def load_binding(request: dict[str, Any], *, operation: str = "verify") -> dict[str, Any]:
    request = validate(request)
    directory = descriptor = -1
    try:
        directory = private_directory(str(binding_directory()))
        info = os.fstat(directory)
        if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) != 0o700:
            raise ContractError("AUTHORIZATION_REQUIRED")
        descriptor = os.open(
            request["target_alias"] + ".json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_BINDING_BYTES
        ):
            raise ContractError("AUTHORIZATION_REQUIRED")
        raw = os.read(descriptor, MAX_BINDING_BYTES + 1)
        if len(raw) > MAX_BINDING_BYTES:
            raise ContractError("AUTHORIZATION_REQUIRED")
        try:
            binding = parse_json(raw)
        except ContractError as error:
            raise ContractError("AUTHORIZATION_REQUIRED") from error
        if type(binding) is dict and binding.get("binding_version") == 2:
            from .lifecycle_binding import validate_lifecycle_binding

            validate_lifecycle_binding(binding, request, operation)
        else:
            if operation != "verify":
                raise ContractError("AUTHORIZATION_REQUIRED")
            validate_binding(binding, request)
        return dict(binding)
    except (OSError, ValueError, RecursionError) as error:
        raise ContractError("AUTHORIZATION_REQUIRED") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def validate_binding(binding: Any, request: dict[str, Any]) -> None:
    try:
        object_fields(
            binding,
            {
                "binding_version",
                "allowed_uid",
                "expires_at",
                "operations",
                "request",
                "container_id",
                "container_started_at",
                "database_image_id",
                "network_name",
                "network_id",
                "hostaddr",
                "runtime_image_id",
                "runtime_uid",
                "runtime_gid",
                "username",
                "expected_dn",
                "credential_dir",
            },
        )
        require(type(binding["binding_version"]) is int and binding["binding_version"] == 1)
        require(type(binding["allowed_uid"]) is int and binding["allowed_uid"] == os.geteuid())
        require(type(binding["expires_at"]) is int and time.time() < binding["expires_at"])
        require(binding["operations"] == ["verify"])
        expected = validate(binding["request"])
        # protected execution needs an external approval/evidence backend, not a local file.
        require(expected["environment"] in ("local-synthetic", "local"))
        require(request["environment"] in ("local-synthetic", "local"))
        for field in ("container_id", "network_id"):
            require(matches(binding[field], r"[a-f0-9]{64}", 64))
        require(matches(binding["container_started_at"], r"[0-9T:.Z-]+", 64))
        for field in ("database_image_id", "runtime_image_id"):
            require(matches(binding[field], r"sha256:[a-f0-9]{64}", 71))
        require(matches(binding["network_name"], r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", 128))
        require(type(binding["hostaddr"]) is str)
        require(ipaddress.ip_address(binding["hostaddr"]).version == 4)
        require(binding["runtime_uid"] == 10001 and type(binding["runtime_uid"]) is int)
        require(binding["runtime_gid"] == 10001 and type(binding["runtime_gid"]) is int)
        require(matches(binding["username"], r"[a-z_][a-z0-9_]*", 63))
        require(matches(binding["expected_dn"], r"CN=[a-z][a-z0-9-]*", 128))
        path = binding["credential_dir"]
        require(type(path) is str and Path(path).is_absolute() and ".." not in Path(path).parts)
        require("," not in path and "\n" not in path and "\x00" not in path)
    except (ContractError, ValueError) as error:
        raise ContractError("AUTHORIZATION_REQUIRED") from error
    for field in (
        "scope",
        "environment",
        "deployment_alias",
        "target_alias",
        "profile_version",
        "profile",
    ):
        if expected[field] != request[field]:
            raise ContractError("TARGET_MISMATCH")


def target_snapshot(binding: dict[str, Any]) -> str:
    network = binding["network_name"]
    template = (
        '{"id":{{json .Id}},"running":{{json .State.Running}},"image":{{json .Image}},'
        '"started_at":{{json .State.StartedAt}},'
        '"network_id":{{json (index .NetworkSettings.Networks "' + network + '").NetworkID}},'
        '"hostaddr":{{json (index .NetworkSettings.Networks "' + network + '").IPAddress}}}'
    )
    try:
        current = json.loads(
            docker(
                ["inspect", "--type", "container", "--format", template, binding["container_id"]]
            )
        )
    except (ValueError, ContractError) as error:
        raise ContractError("TARGET_MISMATCH") from error
    expected = {
        "id": binding["container_id"],
        "running": True,
        "started_at": binding["container_started_at"],
        "image": binding["database_image_id"],
        "network_id": binding["network_id"],
        "hostaddr": binding["hostaddr"],
    }
    if current != expected:
        raise ContractError("TARGET_MISMATCH")
    return "sha256:" + hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()


def run_verification(binding: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    request = validate(request)
    validate_binding(binding, request)
    snapshot = target_snapshot(binding)
    # Pin the checked directory and keep it alive until Docker has consumed its mount.
    # Docker daemon resolves paths independently, so also reject a pathname change
    # immediately before/after execution. Credential worker pins each file by FD.
    descriptor = -1
    started = False
    prior_error: BaseException | None = None
    name = "query-passport-verify-" + uuid.uuid4().hex
    try:
        descriptor = private_directory(binding["credential_dir"], runtime_owner=True)
        if set(os.listdir(descriptor)) - {"ca.crt", "client.crt", "client.key"}:
            raise ContractError("CREDENTIAL_ACCESS_DENIED")
        original = credential_revision(descriptor)
        directory_identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        pathname = os.stat(binding["credential_dir"], follow_symlinks=False)
        if (pathname.st_dev, pathname.st_ino) != directory_identity:
            raise ContractError("CREDENTIAL_ACCESS_DENIED")
        profile = request["profile"]
        payload = {
            "host": profile["host"],
            "hostaddr": binding["hostaddr"],
            "port": profile["port"],
            "database": profile["database"],
            "profile_id": profile["id"],
            "username": binding["username"],
            "expected_dn": binding["expected_dn"],
            "runtime_uid": binding["runtime_uid"],
            "runtime_gid": binding["runtime_gid"],
        }
        source = Path(__file__).with_name("verify_worker.py").read_text()
        started = True
        output = docker(
            [
                "run",
                "--rm",
                "--pull=never",
                "--log-driver",
                "none",
                "--name",
                name,
                "--network",
                binding["network_id"],
                "--user",
                "10001:10001",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "128m",
                "--mount",
                "type=bind,src="
                + binding["credential_dir"]
                + ",dst=/run/secrets/query-man/databases/"
                + profile["id"]
                + ",readonly",
                "--entrypoint",
                "/usr/bin/env",
                "-i",
                binding["runtime_image_id"],
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "LANG=C.UTF-8",
                "/app/.venv/bin/python",
                "-I",
                "-c",
                source,
            ],
            stdin=json.dumps(payload).encode(),
            timeout=25,
            limit=8192,
            worker_output=True,
        )
        if target_snapshot(binding) != snapshot:
            raise ContractError("TARGET_DRIFT")
        pathname = os.stat(binding["credential_dir"], follow_symlinks=False)
        if (pathname.st_dev, pathname.st_ino) != directory_identity or (
            credential_revision(descriptor) != original
        ):
            raise ContractError("TARGET_DRIFT")
        result = normalize_worker_result(output)
        if result["error"] in ("TIMEOUT", "INTERRUPTED"):
            prior_error = ContractError(result["error"])
        return result
    except (OSError, ValueError) as error:
        raise ContractError("CREDENTIAL_ACCESS_DENIED") from error
    except BaseException as error:
        prior_error = error
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        # Only remove the fresh diagnostic container owned by this invocation.
        if started:
            cleanup_container(name, prior_error=prior_error)


def credential_revision(directory: int) -> list[tuple[int, ...] | None]:
    """Metadata only: detect in-place edits and replacement without reading secrets."""
    result: list[tuple[int, ...] | None] = []
    for name in (".", "ca.crt", "client.crt", "client.key"):
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            result.append(
                (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_uid,
                    info.st_gid,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
            )
        except FileNotFoundError:
            result.append(None)
    return result


def normalize_worker_result(raw: bytes) -> dict[str, Any]:
    from .verify_worker import CHECK_NAMES, ERROR_CODES

    try:
        result = parse_json(raw)
        object_fields(result, {"status", "checks", "error"})
        object_fields(result["checks"], set(CHECK_NAMES))
        require(
            all(state in ("passed", "failed", "not_checked") for state in result["checks"].values())
        )
        if result["status"] == "succeeded":
            require(result["error"] is None)
            require(all(state == "passed" for state in result["checks"].values()))
        else:
            require(result["status"] == "failed" and type(result["error"]) is str)
            require(result["error"] in ERROR_CODES)
        return dict(result)
    except ContractError as error:
        raise ContractError("EXECUTOR_FAILED") from error


def verify_request(request: dict[str, Any]) -> dict[str, Any]:
    from .contract import respond

    request = validate(request)
    binding = load_binding(request)
    if binding["binding_version"] == 2:
        from . import credential_delivery, operation_store
        from .lifecycle_binding import verification_projection

        # A v2 binding names the private delivery store. Resolve its current
        # immutable bundle under the same target lock used by lifecycle changes.
        try:
            with operation_store.target_lock(binding["container_id"]):
                destination = Path(binding["credential_dir"])
                active = credential_delivery.inspect_delivery(destination)
                if active["generation_id"] is None:
                    raise ContractError("CREDENTIAL_ACCESS_DENIED")
                directory = destination / "versions" / active["generation_id"] / "bundle"
                worker = run_verification(verification_projection(binding, str(directory)), request)
                if credential_delivery.inspect_delivery(destination) != active:
                    raise ContractError("TARGET_DRIFT")
        except credential_delivery.DeliveryError as error:
            raise ContractError("CREDENTIAL_ACCESS_DENIED") from error
        except operation_store.StateError as error:
            raise ContractError(error.code) from error
    else:
        worker = run_verification(binding, request)
    result = respond("inspect", request)["result"]
    checks = worker["checks"]
    result.update(
        {
            "mode": "live",
            "checks": checks,
            "verification_scope": "database-only",
            "executor_target_binding": "passed",
        }
    )
    result["target_identity"] = checks["target"]
    result["db_connectivity"] = checks["read_only_transaction"]
    result["authentication"] = checks["client_identity"]
    result["certificate_validation"] = (
        "passed" if checks["tls"] == checks["client_identity"] == "passed" else "not_checked"
    )
    result["verification_runtime"] = checks["runtime_identity"]
    # The diagnostic container is not the application's deployment or readiness.
    return envelope("verify", worker["status"], result, request["scope"], code=worker["error"])
