"""Opt-in checks for the narrowly pinned PostgreSQL monitoring exception."""

import json
import os

import pytest
from test_m3_integration import step
from test_m3_integration import target as target

from query_passport import credential_delivery, db_admin, executor
from query_passport import local_lifecycle as lifecycle
from query_passport.contract import ContractError
from query_passport.db_config import config_digest

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 for fresh monitoring-extension targets",
)


@pytest.fixture
def monitoring_target(target):
    database, _ = target
    database.sql("CREATE EXTENSION pg_stat_statements VERSION '1.12'", database="query_man")
    return target


def monitoring(binding):
    # Fixed private catalog query returns only the validity flag and metadata hash.
    return db_admin._sql(
        binding,
        db_admin._MONITORING_CTE
        + "SELECT json_build_object('valid',valid,'digest',digest) FROM passport_monitoring;",
    )


def approve_monitoring(binding):
    observed = monitoring(binding)
    assert observed["valid"] is True
    binding["admin"]["monitoring"] = {
        "extension": "pg_stat_statements",
        "digest": observed["digest"],
    }
    return observed


def preserved_configuration(binding):
    # Never expose snapshot's raw authentication-file contents in assertions.
    snapshot = db_admin.snapshot(binding)
    return {
        "hba": config_digest(snapshot["hba"]),
        "ident": config_digest(snapshot["ident"]),
        "auto": snapshot["auto_digest"],
        "ca": snapshot["ca_digest"],
        "ca_setting": snapshot["ca"]["setting"],
    }


def test_matching_monitoring_pin_preserves_public_acl_and_configuration(monitoring_target):
    database, binding = monitoring_target
    assert database.request["source_count"] == 0
    assert json.loads(
        database.sql(
            "SELECT json_build_object("
            "'version', (SELECT extversion FROM pg_extension WHERE extname='pg_stat_statements'), "
            "'view_select', (SELECT count(*) FROM pg_class c JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname='public' "
            "AND c.relname IN ('pg_stat_statements','pg_stat_statements_info') "
            "AND has_table_privilege('public',c.oid,'SELECT')), "
            "'routine_execute', (SELECT count(*) FROM pg_proc p JOIN pg_namespace n "
            "ON n.oid=p.pronamespace WHERE n.nspname='public' "
            "AND p.proname IN ('pg_stat_statements','pg_stat_statements_info') "
            "AND has_function_privilege('public',p.oid,'EXECUTE')))",
            database="query_man",
        )
    ) == {"version": "1.12", "view_select": 2, "routine_execute": 2}
    strict = db_admin.snapshot(binding)
    assert strict["public_audit"] == {
        **dict.fromkeys(db_admin._AUDIT_FIELDS, False),
        "table_access": True,
        "routine_access": True,
    }
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(database.request, binding)
    assert error.value.code == "PERMISSION_DENIED"
    assert not database.authority_dir.exists()
    assert database.snapshot()["passport_roles"] == 0

    approved = approve_monitoring(binding)
    assert db_admin.snapshot(binding)["public_audit"] == dict.fromkeys(
        db_admin._AUDIT_FIELDS, False
    )
    plan = lifecycle.prepare(database.request, binding)
    assert plan["source_count"] == 0
    assert plan["db_connectivity"] == "not_checked"
    assert step("issue", monitoring_target, plan)["phase"] == "issued"
    assert step("apply", monitoring_target, plan)["phase"] == "applied"
    delivered = step("deliver", monitoring_target, plan)
    assert delivered["phase"] == "verified"
    assert delivered["db_connectivity"] == "passed"
    assert delivered["application_readiness"] == "not_checked"
    assert monitoring(binding) == approved
    assert (
        executor.run_verification(database.existing_binding(), database.request)["status"]
        == "succeeded"
    )
    assert (
        credential_delivery.inspect_delivery(database.credential_dir)["generation_id"]
        == plan["operation_id"]
    )
    assert monitoring(binding) == approved
    assert database.snapshot()["existing_roles"] == 1


@pytest.mark.parametrize(
    ("change", "still_valid"),
    [
        (
            "CREATE OR REPLACE VIEW public.pg_stat_statements_info "
            "AS SELECT * FROM public.pg_stat_statements_info() WHERE false",
            True,
        ),
        ("ALTER FUNCTION public.pg_stat_statements_info() SECURITY DEFINER", False),
    ],
    ids=["view-definition", "security-definer"],
)
def test_monitoring_change_after_plan_stops_before_issuance(monitoring_target, change, still_valid):
    database, binding = monitoring_target
    approved = approve_monitoring(binding)
    plan = lifecycle.prepare(database.request, binding)
    database.sql(change, database="query_man")
    changed = monitoring(binding)
    assert changed["valid"] is still_valid
    assert changed["digest"] != approved["digest"]
    with pytest.raises(ContractError) as error:
        step("issue", monitoring_target, plan)
    assert error.value.code == "TARGET_DRIFT"
    assert not database.authority_dir.exists()
    assert not database.generations_dir.exists()
    assert database.snapshot()["passport_roles"] == 0
    assert monitoring(binding) == changed


@pytest.mark.parametrize(
    ("change", "audit_field"),
    [
        (
            "CREATE FUNCTION public.fixture_business() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "routine_access",
        ),
        (
            "CREATE TABLE public.fixture_business (id integer); "
            "GRANT INSERT ON public.fixture_business TO PUBLIC",
            "table_access",
        ),
        (
            "CREATE TABLE public.fixture_business (id integer); "
            "GRANT SELECT ON public.fixture_business TO PUBLIC",
            "table_access",
        ),
    ],
    ids=["business-routine", "business-write", "business-read"],
)
def test_monitoring_pin_does_not_exempt_other_public_privileges(
    monitoring_target, change, audit_field
):
    database, binding = monitoring_target
    approved = approve_monitoring(binding)
    before = db_admin.snapshot(binding)
    assert before["public_audit"] == dict.fromkeys(db_admin._AUDIT_FIELDS, False)
    db_admin.validate_provision(binding, before)
    database.sql(change, database="query_man")
    assert monitoring(binding) == approved
    expected = {**dict.fromkeys(db_admin._AUDIT_FIELDS, False), audit_field: True}
    assert db_admin.snapshot(binding)["public_audit"] == expected
    assert database.request["source_count"] == 0
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(database.request, binding)
    assert error.value.code == "PERMISSION_DENIED"
    assert not database.authority_dir.exists()
    assert database.snapshot()["passport_roles"] == 0
    assert db_admin.snapshot(binding)["public_audit"] == expected
    assert monitoring(binding) == approved


@pytest.mark.parametrize(
    "change",
    [
        "GRANT UPDATE ON public.pg_stat_statements_info TO PUBLIC",
        "GRANT UPDATE (dealloc) ON public.pg_stat_statements_info TO PUBLIC",
    ],
    ids=["view-update", "column-update"],
)
def test_repinning_monitoring_acl_does_not_approve_writes(monitoring_target, change):
    database, binding = monitoring_target
    original = approve_monitoring(binding)
    db_admin.validate_provision(binding, db_admin.snapshot(binding))
    database.sql(change, database="query_man")
    repinned = approve_monitoring(binding)
    assert repinned["digest"] != original["digest"]
    expected = {**dict.fromkeys(db_admin._AUDIT_FIELDS, False), "table_access": True}
    assert db_admin.snapshot(binding)["public_audit"] == expected
    with pytest.raises(ContractError) as error:
        lifecycle.prepare(database.request, binding)
    assert error.value.code == "PERMISSION_DENIED"
    assert not database.authority_dir.exists()
    assert database.snapshot()["passport_roles"] == 0
    assert db_admin.snapshot(binding)["public_audit"] == expected
    assert monitoring(binding) == repinned
