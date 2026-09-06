"""Real local provisioning and recovery on newly owned disposable targets only."""

import copy
import json
import os

import pytest
from disposable_m3 import M3Database

from query_passport import executor
from query_passport import local_lifecycle as lifecycle
from query_passport import operation_store as store
from query_passport.contract import ContractError
from query_passport.lifecycle_binding import OPERATIONS

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 for a fresh disposable M3 lifecycle",
)


@pytest.fixture
def target(monkeypatch):
    database = M3Database.create()
    try:
        private_state = database.base_directory / "operations"
        private_state.mkdir(mode=0o700)
        monkeypatch.setattr(store, "state_directory", lambda: private_state)
        monkeypatch.setattr(
            store,
            "_open_root",
            lambda: os.open(private_state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
        )
        binding = copy.deepcopy(database.binding)
        binding.update(
            {
                "binding_version": 2,
                "operations": sorted(OPERATIONS),
                "lifecycle": {
                    "authority_dir": str(database.authority_dir),
                    "authority_id": "passport-test-ca",
                    "generations_dir": str(database.generations_dir),
                    "server_ca_file": str(database.server_ca_file),
                    "lifetime_days": 30,
                    "allow_initialize_authority": True,
                    "allow_create_check_role": True,
                },
            }
        )
        yield database, binding
    finally:
        database.close()


def step(command, target, plan):
    database, binding = target
    return lifecycle.execute(
        command, database.request, binding, plan["operation_id"], plan["plan_digest"]
    )


def test_prepare_issue_apply_deliver_verify(target, monkeypatch):
    from query_passport import credential_delivery

    database, binding = target
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )
    plan = lifecycle.prepare(database.request, binding)
    assert plan["source_count"] == 0 and plan["db_connectivity"] == "not_checked"
    issued = step("issue", target, plan)
    assert issued["phase"] == "issued" and issued["certificate_validation"] == "not_checked"
    assert step("issue", target, plan)["phase"] == "issued"
    assert step("apply", target, plan)["phase"] == "applied"
    assert step("apply", target, plan)["phase"] == "applied"
    delivered = step("deliver", target, plan)
    assert delivered["phase"] == "verified" and delivered["db_connectivity"] == "passed"
    assert delivered["application_readiness"] == "not_checked"
    assert step("deliver", target, plan)["phase"] == "verified"
    monkeypatch.setattr(executor, "load_binding", lambda request: binding)
    public_verify = executor.verify_request(database.request)
    assert public_verify["status"] == "succeeded"
    assert public_verify["result"]["source_count"] == 0
    assert public_verify["result"]["application_readiness"] == "not_checked"
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )
    active = credential_delivery.inspect_delivery(database.credential_dir)
    assert active["generation_id"] == plan["operation_id"]
    candidate = database.credential_dir / "versions" / plan["operation_id"] / "bundle"
    assert candidate.joinpath("client.key").stat().st_uid == 0
    assert candidate.joinpath("client.key").stat().st_gid == 10001
    assert step("status", target, plan)["db_connectivity"] == "not_checked"
    after = database.snapshot()
    assert after["existing_roles"] == 1 and after["business_relations"] == 0


def test_drift_after_plan_stops_before_issuance(target):
    database, binding = target
    plan = lifecycle.prepare(database.request, binding)
    database.sql("ALTER SYSTEM SET log_min_duration_statement = 5000")
    with pytest.raises(ContractError) as error:
        step("issue", target, plan)
    assert error.value.code == "TARGET_DRIFT"
    assert not database.authority_dir.exists()
    assert database.snapshot()["passport_roles"] == 0


def test_uncertain_apply_reconciles_and_reuses_owned_change(target, monkeypatch):
    from query_passport import db_admin

    database, binding = target
    plan = lifecycle.prepare(database.request, binding)
    step("issue", target, plan)
    original = db_admin.apply

    def lost_response(*args, **kwargs):
        original(*args, **kwargs)
        raise ContractError("TIMEOUT")

    monkeypatch.setattr(db_admin, "apply", lost_response)
    with pytest.raises(ContractError) as error:
        step("apply", target, plan)
    assert error.value.code == "TIMEOUT"
    with store.operation(plan["operation_id"]) as operation:
        assert operation.events()[-1]["phase"] == "applying"
    monkeypatch.setattr(db_admin, "apply", original)
    assert step("apply", target, plan)["phase"] == "applied"
    assert step("deliver", target, plan)["phase"] == "verified"
    assert database.snapshot()["passport_roles"] == 1


def test_failed_candidate_verification_preserves_inactive_delivery(target, monkeypatch):
    from query_passport import credential_delivery

    database, binding = target
    plan = lifecycle.prepare(database.request, binding)
    step("issue", target, plan)
    step("apply", target, plan)
    original = executor.run_verification
    monkeypatch.setattr(
        executor,
        "run_verification",
        lambda *args: {
            "status": "failed",
            "error": "TLS_VERIFICATION_FAILED",
            "checks": {},
        },
    )
    with pytest.raises(ContractError) as error:
        step("deliver", target, plan)
    assert error.value.code == "TLS_VERIFICATION_FAILED"
    assert credential_delivery.inspect_delivery(database.credential_dir)["generation_id"] is None
    monkeypatch.setattr(executor, "run_verification", original)
    assert step("deliver", target, plan)["phase"] == "verified"


def test_public_business_grants_are_reported_without_changing_them(target):
    database, binding = target
    database.sql(
        "CREATE TABLE public.fixture_business (id integer); GRANT SELECT ON public.fixture_business TO PUBLIC",
        database="query_man",
    )
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(database.request, binding)
    assert error.value.code == "PERMISSION_DENIED"
    assert database.snapshot()["passport_roles"] == 0
    assert database.snapshot()["business_relations"] == 1


def test_same_path_ca_bundle_drift_stops_delivery(target):
    database, binding = target
    plan = lifecycle.prepare(database.request, binding)
    step("issue", target, plan)
    step("apply", target, plan)
    with store.operation(plan["operation_id"]) as operation:
        issuance = json.loads(operation.read_artifact("issuance.json"))
    # Fault injection removes the pre-existing service's CA while retaining the
    # new Passport CA. A positive new-client probe alone would miss this damage.
    new_ca_only = lifecycle.client_trust(binding, issuance["authority_sha256"])
    filename = "query-passport-client-ca-" + plan["operation_id"] + ".crt"
    executor.docker(
        [
            "exec",
            "--interactive",
            "--user",
            f"{database.postgres_uid}:{database.postgres_gid}",
            binding["container_id"],
            "/bin/sh",
            "-c",
            'cat > "$1"',
            "passport-fixture-fault",
            "/var/lib/postgresql/data/" + filename,
        ],
        stdin=new_ca_only,
    )
    with pytest.raises(ContractError) as error:
        step("deliver", target, plan)
    assert error.value.code == "TARGET_DRIFT"
    assert not database.credential_dir.exists()
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )


def test_loaded_trust_policy_is_detected_even_when_disk_rules_are_restored(target):
    from query_passport import credential_delivery, db_admin

    database, binding = target
    plan = lifecycle.prepare(database.request, binding)
    step("issue", target, plan)
    step("apply", target, plan)
    executor.docker(
        [
            "exec",
            "--user",
            f"{database.postgres_uid}:{database.postgres_gid}",
            binding["container_id"],
            "/bin/sh",
            "-c",
            "set -eu; cd /var/lib/postgresql/data; "
            "cp pg_hba.conf fixture-policy-before; "
            '{ printf "hostssl query_man passport_check %s trust\\n" "$1"; '
            "cat fixture-policy-before; } > fixture-policy-stage; "
            "mv fixture-policy-stage pg_hba.conf",
            "passport-fixture-policy",
            binding["admin"]["network_cidr"],
        ]
    )
    db_admin._reload(
        binding,
        binding["admin"]["pgdata"] + "/query-passport-client-ca-" + plan["operation_id"] + ".crt",
    )
    executor.docker(
        [
            "exec",
            "--user",
            f"{database.postgres_uid}:{database.postgres_gid}",
            binding["container_id"],
            "/bin/sh",
            "-c",
            "mv /var/lib/postgresql/data/fixture-policy-before /var/lib/postgresql/data/pg_hba.conf",
        ]
    )
    # The expected disk rules are back; deliberately do not reload them. A disk
    # catalog inspection alone cannot detect the still-loaded permissive rule.
    with pytest.raises(ContractError) as error:
        step("deliver", target, plan)
    assert error.value.code == "VERIFICATION_FAILED"
    assert credential_delivery.inspect_delivery(database.credential_dir)["generation_id"] is None
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )
