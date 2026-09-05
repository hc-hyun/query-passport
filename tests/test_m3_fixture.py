"""Opt-in smoke check for the new writable disposable M3 target."""

import os
import stat

import pytest
from disposable_m3 import PGDATA, M3Database

from query_passport.executor import target_snapshot, validate_binding

pytestmark = pytest.mark.skipif(
    os.environ.get("QUERY_PASSPORT_DOCKER_TESTS") != "1",
    reason="Set QUERY_PASSPORT_DOCKER_TESTS=1 to create a fresh disposable M3 target",
)


def test_fresh_m3_target_has_tls_writable_auth_and_no_passport_role():
    database = M3Database.create()
    directory = database.base_directory
    try:
        assert directory.parent.as_posix() == "/var/tmp"
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert database.server_ca_file.is_file()
        assert not database.authority_dir.exists()
        assert not database.generations_dir.exists()
        assert not database.credential_dir.exists()
        assert database.request["source_count"] == 0
        assert database.request["environment"] == "local-synthetic"
        assert (
            database.sql("SELECT current_setting('server_version_num')::int / 10000").strip()
            == b"18"
        )
        snapshot = database.snapshot()
        assert snapshot == {
            "version": snapshot["version"],
            "encoding": "UTF8",
            "ssl": "on",
            "pgdata": PGDATA,
            "hba_file": PGDATA + "/pg_hba.conf",
            "ident_file": PGDATA + "/pg_ident.conf",
            "ssl_ca_file": "client-ca.crt",
            "command_line_auth_settings": 0,
            "passport_roles": 0,
            "existing_roles": 1,
            "public_database_grants": 0,
            "public_schema_grants": 0,
            "business_relations": 0,
            "hba_errors": 0,
            "ident_errors": 0,
        }
        assert snapshot["version"] // 10000 == 18
        existing = database.existing_binding()
        validate_binding(existing, database.request)
        observed = target_snapshot(existing)
        assert observed == target_snapshot(existing)
        assert existing["username"] == "fixture_existing"
        assert database.binding["username"] == "passport_check"
        assert set(database.admin) == {
            "uid",
            "gid",
            "socket_directory",
            "pgdata",
            "network_cidr",
            "connection_limit",
        }
        assert database.admin["uid"] != 0
        assert database.admin["gid"] != 0
    finally:
        database.close()
    assert not directory.exists()
    database.close()
