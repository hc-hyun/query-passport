"""Opt-in Query Man DBA helper -> installed Passport -> fresh database lifecycle.

No external repository is inspected during ordinary collection or default tests.
The repository must be explicitly selected, and only the helper is executed.
Owned operation tracking and successful synthetic record cleanup reuse the exact
installed-CLI gate; production credentials and records are never discovered.
"""

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import test_installed_lifecycle as installed
from disposable import ENVIRONMENT, FixtureFailure
from disposable_m3 import M3Database
from test_live_integration import own_operator_binding

from query_passport import operation_store as store
from query_passport.contract import ERRORS, MAX_OUTPUT_BYTES
from query_passport.credential_delivery import inspect_delivery
from query_passport.lifecycle_binding import OPERATIONS

installed_cli = installed.installed_cli
check = installed.check
assert_unchecked_application = installed.assert_unchecked_application

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1"
    or not os.environ.get("QUERY_PASSPORT_QUERY_MAN_REPO"),
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 and QUERY_PASSPORT_QUERY_MAN_REPO for consumer E2E",
)


@pytest.fixture(scope="module")
def consumer_repository():
    repository = Path(os.environ["QUERY_PASSPORT_QUERY_MAN_REPO"])
    check(
        repository.is_absolute(),
        "Consumer test requires an explicitly selected absolute repository",
    )
    helper = repository / ".agents/skills/query-man-dba-onboarding/scripts/query_passport_verify.py"
    check(helper.is_file(), "Selected repository has no Query Man DBA Passport helper")
    return repository


class SkillLifecycle(installed.InstalledLifecycle):
    def __init__(self, executable, workspace, database, binding, repository):
        super().__init__(executable, workspace, database, binding)
        self.repository = repository
        self.helper = (
            repository / ".agents/skills/query-man-dba-onboarding/scripts/query_passport_verify.py"
        )

    def call(self, command, request=None, *, expected_error=None):
        check(request is not None, "DBA helper calls require a public request")
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(self.helper),
                    command,
                    "--passport",
                    str(self.executable),
                    "--request",
                    "-",
                    "--workspace",
                    str(self.workspace),
                ],
                input=json.dumps(request).encode(),
                cwd=self.repository,
                env=ENVIRONMENT,
                capture_output=True,
                timeout=240,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise FixtureFailure("Query Man consumer lifecycle command did not finish") from None
        check(completed.stderr == b"", "Query Man consumer wrote unexpected stderr")
        check(
            0 < len(completed.stdout) <= MAX_OUTPUT_BYTES
            and completed.stdout.endswith(b"\n")
            and completed.stdout.count(b"\n") == 1,
            "Query Man consumer exceeded its single JSON response bound",
        )
        check(
            b"-----BEGIN" not in completed.stdout, "Query Man consumer exposed credential material"
        )
        check(
            str(self.database.base_directory).encode() not in completed.stdout,
            "Query Man consumer exposed a private provider path",
        )
        try:
            response = json.loads(completed.stdout)
        except (ValueError, RecursionError):
            raise FixtureFailure("Query Man consumer did not return valid JSON") from None
        check(type(response) is dict, "Query Man consumer response is not an object")
        check(response.get("tool") == "query-passport", "Query Man consumer tool identity mismatch")
        check(response.get("command") == command, "Query Man consumer command mismatch")
        if expected_error is not None:
            check(expected_error in ERRORS, "Consumer test expected an unknown error code")
            check(
                completed.returncode == ERRORS[expected_error][0]
                and response.get("status") == "failed"
                and response.get("error") == expected_error,
                "Query Man consumer discarded the classified lifecycle failure",
            )
            if command != "verify":
                check(
                    set(response)
                    == {
                        "tool",
                        "tool_version",
                        "contract_version",
                        "command",
                        "status",
                        "error",
                        "operation_id",
                        "plan_digest",
                        "outcome",
                        "next_action",
                    },
                    "Query Man consumer failure lost recovery context or claimed an execution phase",
                )
                check(
                    response["operation_id"] == request["operation"]["id"]
                    and response["plan_digest"] == request["operation"]["plan_digest"]
                    and response["outcome"] == "not_confirmed"
                    and response["next_action"] == "status_or_scoped_recovery",
                    "Query Man consumer failure changed the operation recovery reference",
                )
            return response
        if completed.returncode != 0:
            known = set(ERRORS) | {
                "PASSPORT_RESPONSE_INVALID",
                "PASSPORT_INCOMPATIBLE",
                "PASSPORT_TIMEOUT",
                "PASSPORT_UNAVAILABLE",
            }
            code = response.get("error")
            reported = code if type(code) is str and code in known else "UNCLASSIFIED"
            reference = ""
            operation = request.get("operation")
            if type(operation) is dict:
                operation_id = operation.get("id")
                if type(operation_id) is str and re.fullmatch(r"[0-9a-f]{32}", operation_id):
                    reference = "; synthetic record=" + operation_id
            raise FixtureFailure(
                "Query Man consumer command failed: " + command + " (" + reported + ")" + reference
            )
        check(
            response.get("tool_version") == "0.3.0" and response.get("contract_version") == "1",
            "Query Man consumer accepted an incompatible Passport version",
        )
        expected_status = {"prepare": "planned", "status": "validated"}.get(command, "succeeded")
        check(
            response.get("status") == expected_status, "Query Man consumer success status mismatch"
        )
        check(
            response.get("scope") == "database-only", "Query Man consumer changed operation scope"
        )
        check("error" not in response, "Query Man consumer mixed success and failure")
        return response


def test_dba_skill_calls_installed_lifecycle_and_preserves_real_failure_recovery_context(
    consumer_repository, installed_cli
):
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
                    "authority_id": "passport-consumer-test-ca",
                    "generations_dir": str(database.generations_dir),
                    "server_ca_file": str(database.server_ca_file),
                    "lifetime_days": 30,
                    "allow_initialize_authority": True,
                    "allow_create_check_role": True,
                },
            }
        )
        skill = SkillLifecycle(executable, workspace, database, binding, consumer_repository)
        with own_operator_binding(binding):
            prepared = skill.prepare()
            assert_unchecked_application(prepared)
            check(
                prepared["db_connectivity"] == "not_checked", "DBA prepare overclaimed connection"
            )
            check(skill.step("issue", prepared)["phase"] == "issued", "DBA issuance incomplete")
            check(skill.step("apply", prepared)["phase"] == "applied", "DBA apply incomplete")
            delivered = skill.step("deliver", prepared)
            check(delivered["phase"] == "verified", "DBA delivery was not verified")
            assert_unchecked_application(delivered)
            original = inspect_delivery(database.credential_dir)
            check(
                original["generation_id"] == prepared["operation_id"],
                "DBA delivery did not publish its generation",
            )
            verified = skill.call("verify", database.request)
            assert_unchecked_application(verified)
            check(verified["db_connectivity"] == "passed", "DBA verify did not confirm connection")
            historical = skill.step("status", prepared)
            assert_unchecked_application(historical)
            check(
                historical["db_connectivity"] == "not_checked",
                "DBA status claimed fresh connectivity",
            )

            rotation = skill.prepare(intent="rotate")
            check(rotation["intent"] == "rotate", "DBA lost the reviewed rotation intent")
            rotated = skill.step("rotate", rotation)
            check(rotated["phase"] == "verified", "DBA rotation was not verified")
            assert_unchecked_application(rotated)
            active = inspect_delivery(database.credential_dir)
            check(
                active["generation_id"] == rotation["operation_id"]
                and active["certificate_sha256"] != original["certificate_sha256"],
                "DBA rotation did not activate a new credential",
            )
            check(
                skill.call("verify", database.request)["db_connectivity"] == "passed",
                "Rotated DBA credential failed",
            )

            # This is an actual producer failure with scope=null and a nonempty
            # operation result, not a consumer-specific synthetic wire fixture.
            failure = skill.step("rollback", prepared, expected_error="TARGET_DRIFT")
            check(failure["outcome"] == "not_confirmed", "DBA failure guessed committed effects")
            check(
                inspect_delivery(database.credential_dir) == active,
                "Rejected DBA rollback changed active credentials",
            )
            historical = skill.step("status", prepared)
            check(
                historical["db_connectivity"] == "not_checked",
                "DBA failure status claimed connectivity",
            )
            with store.operation(prepared["operation_id"]) as operation:
                recorded_phase = operation.events()[-1]["phase"]
            check(
                historical["phase"] == recorded_phase,
                "DBA status changed the recorded phase after a rejected mutation",
            )

            check(
                skill.step("rollback", rotation)["phase"] == "rolled_back",
                "DBA rotation rollback incomplete",
            )
            check(
                inspect_delivery(database.credential_dir) == original,
                "DBA rollback changed previous revision",
            )
            check(
                skill.call("verify", database.request)["db_connectivity"] == "passed",
                "Restored DBA credential failed",
            )
            check(
                skill.step("rollback", prepared)["phase"] == "rolled_back",
                "DBA provision rollback incomplete",
            )
            check(
                skill.step("rollback", prepared)["phase"] == "rolled_back",
                "DBA rollback was not idempotent",
            )
            check(
                skill.step("status", prepared)["phase"] == "rolled_back",
                "DBA status lost recovered state",
            )
            skill.call("verify", database.request, expected_error="CREDENTIAL_ACCESS_DENIED")
            check(
                inspect_delivery(database.credential_dir)["generation_id"] is None,
                "DBA rollback left active credentials",
            )
            after = database.snapshot()
            check(
                after["ssl_ca_file"] == "client-ca.crt"
                and after["existing_roles"] == 1
                and after["business_relations"] == 0,
                "DBA lifecycle changed unrelated fixture state",
            )
            skill.clean_successful_synthetic_records()
    finally:
        database.close()
