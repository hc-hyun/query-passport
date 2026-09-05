"""Opt-in installed-wheel lifecycle against a newly owned disposable database.

The console entry point uses its real pwd-based operator/state paths. Only opaque
operations returned by this test are opened; successful, rolled-back synthetic
records are cleaned up after their private plan and directory identity agree.
Existing records are never enumerated, and target lock files are retained.
"""

import copy
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from disposable import ENVIRONMENT, ROOT, FixtureFailure
from disposable_m3 import M3Database
from test_live_integration import own_operator_binding

from query_passport import operation_store as store
from query_passport.contract import ERRORS, MAX_OUTPUT_BYTES
from query_passport.credential_delivery import inspect_delivery
from query_passport.executor import private_directory
from query_passport.lifecycle_binding import OPERATIONS
from query_passport.local_lifecycle import binding_digest, digest

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 to test an installed CLI on a fresh M3 target",
)


def check(condition, message):
    # Avoid pytest assertion rendering of a malformed provider/public response.
    if not condition:
        raise FixtureFailure(message)


@pytest.fixture(scope="module")
def installed_cli():
    uv = shutil.which("uv")
    check(uv is not None, "Installed lifecycle test requires uv")
    with tempfile.TemporaryDirectory(
        prefix="query-passport-installed-m3-", dir="/var/tmp"
    ) as temporary:
        directory = Path(temporary)
        environment = {**ENVIRONMENT, "UV_CACHE_DIR": str(directory / "cache")}

        def setup(*arguments):
            try:
                result = subprocess.run(
                    [uv, "--no-config", *arguments],
                    cwd=directory,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=180,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                raise FixtureFailure("Installed lifecycle package setup failed") from None
            check(result.returncode == 0, "Installed lifecycle package setup failed")

        setup(
            "build",
            "--wheel",
            "--out-dir",
            str(directory / "dist"),
            "--python",
            sys.executable,
            "--no-python-downloads",
            str(ROOT),
        )
        wheels = list((directory / "dist").glob("*.whl"))
        check(len(wheels) == 1, "Installed lifecycle requires exactly one wheel")
        dependencies = directory / "runtime-requirements.txt"
        setup(
            "export",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(dependencies),
            "--project",
            str(ROOT),
        )
        virtualenv = directory / "runtime"
        setup("venv", "--python", sys.executable, "--no-python-downloads", str(virtualenv))
        setup(
            "pip",
            "install",
            "--python",
            str(virtualenv / "bin/python"),
            "--require-hashes",
            "--requirement",
            str(dependencies),
        )
        setup(
            "pip",
            "install",
            "--python",
            str(virtualenv / "bin/python"),
            "--no-deps",
            "--offline",
            str(wheels[0]),
        )
        # The installed issuer must import its runtime dependency without the
        # source checkout, development dependencies, or an editable installation.
        try:
            checked = subprocess.run(
                [
                    str(virtualenv / "bin/python"),
                    "-I",
                    "-c",
                    "import sys, pathlib, cryptography, query_passport; "
                    "assert query_passport.__version__ == '0.3.0'; "
                    "assert pathlib.Path(query_passport.__file__).resolve().is_relative_to("
                    "pathlib.Path(sys.prefix).resolve())",
                ],
                cwd=directory,
                env=ENVIRONMENT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise FixtureFailure("Installed runtime import verification failed") from None
        check(checked.returncode == 0, "Installed runtime import verification failed")
        yield virtualenv / "bin/query-passport", directory


class InstalledLifecycle:
    def __init__(self, executable, workspace, database, binding):
        self.executable = executable
        self.workspace = workspace
        self.database = database
        self.binding = binding
        self.owned_operations = {}

    def call(self, command, request=None, *, expected_error=None):
        arguments = [str(self.executable), command, "--format", "json"]
        if request is not None:
            arguments += ["--request", "-"]
        try:
            completed = subprocess.run(
                arguments,
                input=None if request is None else json.dumps(request).encode(),
                cwd=self.workspace,
                env=ENVIRONMENT,
                capture_output=True,
                timeout=240,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise FixtureFailure("Installed lifecycle command did not finish") from None
        check(completed.stderr == b"", "Installed lifecycle wrote unexpected stderr")
        check(
            len(completed.stdout) <= MAX_OUTPUT_BYTES,
            "Installed lifecycle exceeded JSON output bound",
        )
        check(
            b"-----BEGIN" not in completed.stdout, "Installed lifecycle exposed credential material"
        )
        check(
            str(self.database.base_directory).encode() not in completed.stdout,
            "Installed lifecycle exposed a private provider path",
        )
        try:
            response = json.loads(completed.stdout)
        except (ValueError, RecursionError):
            raise FixtureFailure("Installed lifecycle did not return valid JSON") from None
        check(
            type(response) is dict
            and set(response)
            == {
                "contract_version",
                "tool_version",
                "command",
                "status",
                "scope",
                "result",
                "errors",
            },
            "Installed lifecycle response envelope mismatch",
        )
        check(response["contract_version"] == "1", "Installed lifecycle contract version mismatch")
        check(response["tool_version"] == "0.3.0", "Installed lifecycle tool version mismatch")
        check(response["command"] == command, "Installed lifecycle command mismatch")
        check(type(response["result"]) is dict, "Installed lifecycle result is not an object")
        if expected_error is not None:
            check(expected_error in ERRORS, "Installed lifecycle test expected an unknown code")
            check(
                completed.returncode == ERRORS[expected_error][0],
                "Installed lifecycle failure exit mismatch",
            )
            check(response["status"] == "failed", "Installed lifecycle failure status mismatch")
            check(
                response["errors"]
                == [{"code": expected_error, "message": ERRORS[expected_error][1]}],
                "Installed lifecycle failure code mismatch",
            )
            return response["result"]
        if completed.returncode != 0:
            codes = response["errors"]
            reported = "UNCLASSIFIED"
            if (
                type(codes) is list
                and len(codes) == 1
                and type(codes[0]) is dict
                and type(codes[0].get("code")) is str
                and codes[0]["code"] in ERRORS
            ):
                reported = codes[0]["code"]
            reference = ""
            if request is not None and type(request.get("operation")) is dict:
                operation_id = request["operation"].get("id")
                if type(operation_id) is str and re.fullmatch(r"[0-9a-f]{32}", operation_id):
                    reference = "; synthetic record=" + operation_id
            raise FixtureFailure(
                "Installed lifecycle command failed: " + command + " (" + reported + ")" + reference
            )
        check(response["errors"] == [], "Installed lifecycle reported unexpected errors")
        expected_status = {
            "capabilities": "validated",
            "prepare": "planned",
            "status": "validated",
        }.get(command, "succeeded")
        check(response["status"] == expected_status, "Installed lifecycle success status mismatch")
        if command != "capabilities":
            check(response["scope"] == "database-only", "Installed lifecycle scope mismatch")
        return response["result"]

    def prepare(self, *, intent="provision"):
        request = copy.deepcopy(self.database.request)
        if intent != "provision":
            request["intent"] = intent
        prepared = self.call("prepare", request)
        operation_id = prepared.get("operation_id")
        plan_digest = prepared.get("plan_digest")
        check(
            type(operation_id) is str and re.fullmatch(r"[0-9a-f]{32}", operation_id),
            "Invalid installed operation ID",
        )
        check(
            type(plan_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", plan_digest),
            "Invalid installed plan digest",
        )
        with store.operation(operation_id) as operation:
            plan = json.loads(operation.read_artifact("plan.json"))
            info = os.fstat(operation.directory)
            check(plan["operation_id"] == operation_id, "Synthetic operation ownership mismatch")
            check(plan["request"] == self.database.request, "Synthetic operation target mismatch")
            check(
                plan["binding_digest"] == binding_digest(self.binding),
                "Synthetic operation binding mismatch",
            )
            check(digest(plan) == plan_digest, "Synthetic operation plan digest mismatch")
            check(plan["intent"] == intent, "Synthetic operation intent mismatch")
            check(
                stat.S_IMODE(info.st_mode) == 0o700, "Synthetic operation directory is not private"
            )
            self.owned_operations[operation_id] = {
                "directory_identity": (info.st_dev, info.st_ino),
                "plan_digest": plan_digest,
            }
        return prepared

    def step(self, command, prepared, *, expected_error=None):
        request = copy.deepcopy(self.database.request)
        request["operation"] = {
            "id": prepared["operation_id"],
            "plan_digest": prepared["plan_digest"],
        }
        return self.call(command, request, expected_error=expected_error)

    def clean_successful_synthetic_records(self):
        # No operation-directory enumeration and no cleanup of target lock files.
        # On any test failure this method is not called, preserving the journal.
        with store.target_lock(self.binding["container_id"]):
            root = private_directory(str(store.state_directory()))
            try:
                for operation_id, owned in self.owned_operations.items():
                    with store.operation(operation_id) as operation:
                        plan = json.loads(operation.read_artifact("plan.json"))
                        info = os.fstat(operation.directory)
                        named = os.stat(operation_id, dir_fd=root, follow_symlinks=False)
                        check(
                            (info.st_dev, info.st_ino) == owned["directory_identity"]
                            and (named.st_dev, named.st_ino) == owned["directory_identity"],
                            "Synthetic operation directory changed; records retained",
                        )
                        check(
                            plan["operation_id"] == operation_id
                            and plan["request"] == self.database.request
                            and plan["binding_digest"] == binding_digest(self.binding)
                            and digest(plan) == owned["plan_digest"],
                            "Synthetic operation ownership changed; records retained",
                        )
                        check(
                            operation.events()[-1]["phase"] == "rolled_back",
                            "Synthetic operation is not recovered; records retained",
                        )
                        shutil.rmtree(operation_id, dir_fd=root)
            finally:
                os.close(root)


def assert_unchecked_application(result):
    check(result["source_count"] == 0, "Installed lifecycle lost zero-source context")
    for field in (
        "source_inventory",
        "reader_permissions",
        "source_admission",
        "deployment",
        "application_readiness",
    ):
        check(
            result[field] == "not_checked", "Installed lifecycle overclaimed application readiness"
        )


def test_installed_cli_provisions_rotates_verifies_and_recovers_only_owned_changes(installed_cli):
    executable, workspace = installed_cli
    database = M3Database.create()
    try:
        binding = copy.deepcopy(database.binding)
        binding.update(
            {
                "binding_version": 2,
                "operations": sorted(OPERATIONS),
                "lifecycle": {
                    "authority_dir": str(database.authority_dir),
                    "authority_id": "passport-installed-test-ca",
                    "generations_dir": str(database.generations_dir),
                    "server_ca_file": str(database.server_ca_file),
                    "lifetime_days": 30,
                    "allow_initialize_authority": True,
                    "allow_create_check_role": True,
                },
            }
        )
        cli = InstalledLifecycle(executable, workspace, database, binding)
        with own_operator_binding(binding):
            capabilities = cli.call("capabilities")
            check(
                {"prepare", "issue", "apply", "deliver", "verify", "rotate", "status", "rollback"}
                <= set(capabilities["commands"]),
                "Installed CLI is missing lifecycle commands",
            )
            prepared = cli.prepare()
            assert_unchecked_application(prepared)
            check(prepared["db_connectivity"] == "not_checked", "Prepare overclaimed connectivity")
            check(cli.step("issue", prepared)["phase"] == "issued", "Installed issuance incomplete")
            check(cli.step("apply", prepared)["phase"] == "applied", "Installed apply incomplete")
            delivered = cli.step("deliver", prepared)
            check(delivered["phase"] == "verified", "Installed delivery was not verified")
            assert_unchecked_application(delivered)
            original_revision = inspect_delivery(database.credential_dir)
            check(
                original_revision["generation_id"] == prepared["operation_id"],
                "Installed delivery did not activate its owned generation",
            )
            verified = cli.call("verify", database.request)
            assert_unchecked_application(verified)
            check(verified["db_connectivity"] == "passed", "Installed verify did not connect")
            historical = cli.step("status", prepared)
            check(
                historical["db_connectivity"] == "not_checked",
                "Status overclaimed fresh connectivity",
            )

            rotation = cli.prepare(intent="rotate")
            assert_unchecked_application(rotation)
            rotated = cli.step("rotate", rotation)
            check(rotated["phase"] == "verified", "Installed rotation was not verified")
            assert_unchecked_application(rotated)
            rotated_revision = inspect_delivery(database.credential_dir)
            check(
                rotated_revision["generation_id"] == rotation["operation_id"]
                and rotated_revision["certificate_sha256"]
                != original_revision["certificate_sha256"],
                "Installed rotation did not activate a new certificate",
            )
            check(
                cli.call("verify", database.request)["db_connectivity"] == "passed",
                "Rotated credential did not connect",
            )
            cli.step("rollback", prepared, expected_error="TARGET_DRIFT")
            check(
                inspect_delivery(database.credential_dir) == rotated_revision,
                "Rejected parent rollback changed the active child credential",
            )
            check(
                database.sql(
                    "SELECT rolcanlogin::int FROM pg_roles WHERE rolname='passport_check'"
                ).strip()
                == b"1",
                "Rejected parent rollback disabled the child's database role",
            )
            check(
                cli.step("rollback", rotation)["phase"] == "rolled_back",
                "Rotation rollback incomplete",
            )
            check(
                inspect_delivery(database.credential_dir) == original_revision,
                "Rotation rollback did not restore the exact previous revision",
            )
            check(
                cli.call("verify", database.request)["db_connectivity"] == "passed",
                "Restored credential did not connect",
            )
            check(
                cli.step("status", rotation)["phase"] == "rolled_back",
                "Rotation history lost recovery",
            )

            check(
                cli.step("rollback", prepared)["phase"] == "rolled_back",
                "Provision rollback incomplete",
            )
            check(
                cli.step("rollback", prepared)["phase"] == "rolled_back",
                "Rollback is not idempotent",
            )
            check(
                cli.step("status", prepared)["phase"] == "rolled_back",
                "Provision history lost recovery",
            )
            cli.call("verify", database.request, expected_error="CREDENTIAL_ACCESS_DENIED")
            check(
                inspect_delivery(database.credential_dir)["generation_id"] is None,
                "Provision rollback did not retire the active credential",
            )
            for plan in (prepared, rotation):
                check(
                    database.credential_dir.joinpath(
                        "versions", plan["operation_id"], "bundle", "client.key"
                    ).is_file(),
                    "Lifecycle recovery removed preserved synthetic credential history",
                )
            after = database.snapshot()
            check(after["ssl_ca_file"] == "client-ca.crt", "Original client trust was not restored")
            check(
                after["existing_roles"] == 1 and after["business_relations"] == 0,
                "Unrelated fixture objects changed",
            )
            cli.clean_successful_synthetic_records()
    finally:
        database.close()
