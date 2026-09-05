"""Pinned local Docker runner for explicit loaded-authentication-policy probes."""

import json
import os
import uuid
from pathlib import Path
from typing import Any

from . import executor
from .contract import ContractError, object_fields, parse_json, require, validate
from .policy_worker import CHECK_NAMES
from .verify_worker import ERROR_CODES


def worker_source() -> str:
    """Compose trusted modules without requiring the Passport package in Query Man."""
    directory = Path(__file__).parent
    source = "import sys, types\n"
    source += "package = types.ModuleType('query_passport')\npackage.__path__ = []\n"
    source += "sys.modules['query_passport'] = package\n"
    for name in ("verify_worker", "policy_worker"):
        full_name = "query_passport." + name
        contents = (directory / (name + ".py")).read_text()
        source += f"module = types.ModuleType({full_name!r})\n"
        source += "module.__package__ = 'query_passport'\n"
        source += f"sys.modules[{full_name!r}] = module\n"
        source += f"setattr(package, {name!r}, module)\n"
        source += f"exec(compile({contents!r}, '<{name}>', 'exec'), module.__dict__)\n"
    source += "raise SystemExit(module.main())\n"
    return source


def normalize_worker_result(raw: bytes) -> dict[str, Any]:
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
            require(any(state != "passed" for state in result["checks"].values()))
        return dict(result)
    except ContractError as error:
        raise ContractError("EXECUTOR_FAILED") from error


def run_policy_verification(binding: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Only internal, authorized projections of the new Passport check identity.

    The lifecycle coordinator brackets these negative probes with successful M2
    verification using this same immutable credential directory and target binding.
    """
    request = validate(request)
    executor.validate_binding(binding, request)
    snapshot = executor.target_snapshot(binding)
    descriptor = -1
    started = False
    prior_error: BaseException | None = None
    name = "query-passport-policy-" + uuid.uuid4().hex
    try:
        descriptor = executor.private_directory(binding["credential_dir"], runtime_owner=True)
        if set(os.listdir(descriptor)) != {"ca.crt", "client.crt", "client.key"}:
            raise ContractError("CREDENTIAL_ACCESS_DENIED")
        original = executor.credential_revision(descriptor)
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
        source = worker_source()
        started = True
        output = executor.docker(
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
            timeout=20,
            limit=8192,
            worker_output=True,
        )
        if executor.target_snapshot(binding) != snapshot:
            raise ContractError("TARGET_DRIFT")
        pathname = os.stat(binding["credential_dir"], follow_symlinks=False)
        if (pathname.st_dev, pathname.st_ino) != directory_identity or (
            executor.credential_revision(descriptor) != original
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
        if started:
            executor.cleanup_container(name, prior_error=prior_error)
