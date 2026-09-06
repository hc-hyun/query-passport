"""Real M3 lifecycle with independent operating-system and database admin names."""

import copy
import json
import os

import pytest
from disposable_m3 import M3Database
from test_m3_integration import step

from query_passport import credential_delivery, executor
from query_passport import local_lifecycle as lifecycle
from query_passport import operation_store as store
from query_passport.lifecycle_binding import OPERATIONS

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 for a fresh alternative-admin M3 target",
)


@pytest.fixture
def target(monkeypatch):
    database = M3Database.create(admin_username="fixture_admin")
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


def test_lifecycle_uses_bound_admin_without_postgres_database_role(target, monkeypatch):
    database, binding = target
    assert database.postgres_uid == 999
    assert database.postgres_gid == 999
    assert binding["admin"]["username"] == "fixture_admin"
    assert json.loads(
        database.sql(
            "SELECT json_build_object('user', current_user, 'session_user', session_user, "
            "'postgres_roles', (SELECT count(*) FROM pg_roles WHERE rolname='postgres'), "
            "'superuser', (SELECT rolsuper FROM pg_roles WHERE rolname=current_user))"
        )
    ) == {
        "user": "fixture_admin",
        "session_user": "fixture_admin",
        "postgres_roles": 0,
        "superuser": True,
    }
    baseline = database.snapshot()
    assert baseline["passport_roles"] == 0
    assert baseline["public_database_grants"] == baseline["public_schema_grants"] == 0
    assert baseline["business_relations"] == 0
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )

    plan = lifecycle.prepare(database.request, binding)
    assert plan["source_count"] == 0
    assert plan["db_connectivity"] == "not_checked"
    assert step("issue", target, plan)["phase"] == "issued"
    assert step("apply", target, plan)["phase"] == "applied"
    delivered = step("deliver", target, plan)
    assert delivered["phase"] == "verified"
    assert delivered["db_connectivity"] == "passed"
    assert delivered["application_readiness"] == "not_checked"
    assert (
        credential_delivery.inspect_delivery(database.credential_dir)["generation_id"]
        == plan["operation_id"]
    )
    monkeypatch.setattr(executor, "load_binding", lambda request: binding)
    verified = executor.verify_request(database.request)
    assert verified["status"] == "succeeded"
    assert verified["result"]["source_count"] == 0
    assert verified["result"]["application_readiness"] == "not_checked"

    assert database.sql("SELECT count(*) FROM pg_roles WHERE rolname='postgres'").strip() == b"0"
    assert database.sql("SELECT current_user").strip() == b"fixture_admin"
    assert (
        database.sql("SELECT rolcanlogin::int FROM pg_roles WHERE rolname='passport_check'").strip()
        == b"1"
    )
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )
    after = database.snapshot()
    assert after["existing_roles"] == 1
    assert after["public_database_grants"] == after["public_schema_grants"] == 0
    assert after["business_relations"] == 0
