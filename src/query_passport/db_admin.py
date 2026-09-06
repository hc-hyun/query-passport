"""Fixed local PostgreSQL administration for an operation-owned check identity.

Snapshots and plans are private journal material, never public CLI results. The
caller holds operation_store.target_lock throughout each operation and records
the phase before calling a mutation. No database, source, view, or table is made.
Existing CA/key/certificate files and unowned configuration bytes are preserved.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from cryptography import x509

from . import executor
from .contract import ContractError
from .db_config import build_auth_rules, config_digest, owned_block, propose_config

MAX_CONFIG_BYTES = 131072
_ADMIN_FIELDS = {"uid", "gid", "socket_directory", "pgdata", "network_cidr", "connection_limit"}
_AUDIT_FIELDS = {
    "database_create",
    "database_temp",
    "schema_create",
    "table_access",
    "sequence_access",
    "routine_access",
}
_ROLE_SETTINGS = [
    "default_transaction_read_only=on",
    "idle_in_transaction_session_timeout=5s",
    "lock_timeout=1s",
    "search_path=pg_catalog",
    "statement_timeout=5s",
]


def _require(condition: bool, code: str = "TARGET_DRIFT") -> None:
    if not condition:
        raise ContractError(code)


def _name(value: Any) -> str:
    _require(
        type(value) is str and re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value) is not None,
        "AUTHORIZATION_REQUIRED",
    )
    return str(value)


def _path(value: Any) -> str:
    _require(
        type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}", value) is not None,
        "AUTHORIZATION_REQUIRED",
    )
    parsed = PurePosixPath(value)
    _require(".." not in parsed.parts and str(parsed) == value, "AUTHORIZATION_REQUIRED")
    return str(value)


def _binding(binding: dict[str, Any]) -> dict[str, Any]:
    admin = binding.get("admin")
    _require(
        type(admin) is dict
        and _ADMIN_FIELDS <= admin.keys() <= _ADMIN_FIELDS | {"username", "monitoring"},
        "AUTHORIZATION_REQUIRED",
    )
    assert isinstance(admin, dict)
    username = _name(admin.get("username", "postgres"))
    if "monitoring" in admin:
        monitoring = admin["monitoring"]
        _require(
            type(monitoring) is dict
            and monitoring.keys() == {"extension", "digest"}
            and monitoring["extension"] == "pg_stat_statements"
            and type(monitoring["digest"]) is str
            and re.fullmatch(r"sha256:[a-f0-9]{64}", monitoring["digest"]) is not None,
            "AUTHORIZATION_REQUIRED",
        )
    for field in ("uid", "gid"):
        _require(
            type(admin[field]) is int and 1 <= admin[field] <= 2147483647, "AUTHORIZATION_REQUIRED"
        )
    _require(
        type(admin["connection_limit"]) is int and 1 <= admin["connection_limit"] <= 4,
        "AUTHORIZATION_REQUIRED",
    )
    _path(admin["pgdata"])
    _path(admin["socket_directory"])
    _name(binding.get("username"))
    profile = binding["request"]["profile"]
    database = profile["database"]
    _require(
        type(database) is str
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", database) is not None,
        "AUTHORIZATION_REQUIRED",
    )
    _require(
        binding["request"]["environment"] in ("local", "local-synthetic"), "UNSUPPORTED_OPERATION"
    )
    build_auth_rules(
        database, binding["username"], binding["expected_dn"], admin["network_cidr"], "passport"
    )
    return {**admin, "username": username}


def _operation(operation_id: str) -> str:
    _require(
        type(operation_id) is str and re.fullmatch(r"[a-f0-9]{32}", operation_id) is not None,
        "AUTHORIZATION_REQUIRED",
    )
    return "passport-" + operation_id


def _exec(binding: dict[str, Any], args: list[str], data: bytes, *, limit: int = 1048576) -> bytes:
    admin = _binding(binding)
    return executor.docker(
        [
            "exec",
            "--interactive",
            "--user",
            f"{admin['uid']}:{admin['gid']}",
            binding["container_id"],
            "/usr/bin/env",
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "LANG=C",
            "HOME=/nonexistent",
            *args,
        ],
        stdin=data,
        timeout=15,
        limit=limit,
    )


def _json(raw: bytes) -> dict[str, Any]:
    try:
        result = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as error:
        raise ContractError("EXECUTOR_FAILED") from error
    _require(type(result) is dict, "EXECUTOR_FAILED")
    if "error" in result:
        code = result["error"]
        _require(
            code in ("TARGET_DRIFT", "EXECUTOR_FAILED", "DB_CONFIG_WRITE_FAILED"), "EXECUTOR_FAILED"
        )
        raise ContractError(code)
    return dict(result)


def _sql(binding: dict[str, Any], statement: str) -> dict[str, Any]:
    admin = _binding(binding)
    # No connection URI, ambient service/.pgpass lookup, password prompt, or SQL
    # arguments. Even administrative error statements must not enter server logs.
    prefix = (
        "SET log_statement = 'none'; SET log_min_error_statement = 'panic'; "
        "SET client_min_messages = 'error'; SET search_path = pg_catalog; "
        "SET statement_timeout = '5s'; SET lock_timeout = '1s';\n"
    )
    raw = _exec(
        binding,
        [
            "psql",
            "--no-psqlrc",
            "--no-password",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--host",
            admin["socket_directory"],
            "--port",
            str(binding["request"]["profile"]["port"]),
            "--username",
            admin["username"],
            "--dbname",
            binding["request"]["profile"]["database"],
            "--file",
            "-",
        ],
        (prefix + statement).encode(),
    )
    return _json(raw)


# PostgreSQL 18's shipped extension 1.12 uses these two C entry points. Definitions
# and ACLs remain inside this single catalog snapshot; only their digest leaves DB.
# https://github.com/postgres/postgres/tree/REL_18_STABLE/contrib/pg_stat_statements
_MONITORING_CTE = """
WITH passport_extension AS MATERIALIZED (
  SELECT e.*, n.nspname, n.nspowner, n.nspacl FROM pg_extension e
  JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_stat_statements'
), passport_views AS MATERIALIZED (
  SELECT c.oid, c.relname,
    c.relkind='v' AND c.relnamespace=e.extnamespace AS valid,
    jsonb_build_object('oid',c.oid::bigint,'name',c.relname,'kind',c.relkind,
      'schema',jsonb_build_array(n.oid::bigint,n.nspname,n.nspowner::bigint,n.nspacl),
      'owner',c.relowner::bigint,'acl',c.relacl,'options',c.reloptions,
      'columns',(SELECT jsonb_agg(jsonb_build_array(a.attnum,a.attname,a.atttypid::bigint,
        a.atttypmod,a.attcollation::bigint,a.attacl,a.attisdropped) ORDER BY a.attnum)
        FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0),
      'definition',CASE WHEN c.relkind='v' THEN pg_get_viewdef(c.oid,false) ELSE NULL END,
      'rules',(SELECT jsonb_agg(to_jsonb(w) ORDER BY w.oid) FROM pg_rewrite w WHERE w.ev_class=c.oid),
      'dependencies',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.objid,d.refclassid,d.refobjid,d.refobjsubid,d.deptype)
        FROM pg_rewrite w JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=w.oid
        WHERE w.ev_class=c.oid)) AS metadata
  FROM passport_extension e JOIN pg_depend d ON d.refclassid='pg_extension'::regclass
    AND d.refobjid=e.oid AND d.classid='pg_class'::regclass AND d.objsubid=0 AND d.deptype='e'
  JOIN pg_class c ON c.oid=d.objid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.relname IN ('pg_stat_statements','pg_stat_statements_info')
), passport_functions AS MATERIALIZED (
  SELECT p.oid, p.proname,
    p.pronamespace=e.extnamespace AND l.lanname='c' AND p.prokind='f' AND NOT p.prosecdef
      AND p.proconfig IS NULL AND p.probin='$libdir/pg_stat_statements'
      AND p.prosupport=0 AND NOT p.proleakproof AND p.proisstrict
      AND p.provolatile='v' AND p.proparallel='s' AND p.pronargdefaults=0
      AND p.prorettype='record'::regtype
      AND ((p.proname='pg_stat_statements' AND p.proargtypes='16'::oidvector
            AND p.proretset AND p.prosrc='pg_stat_statements_1_12')
        OR (p.proname='pg_stat_statements_info' AND p.proargtypes=''::oidvector
            AND NOT p.proretset AND p.prosrc='pg_stat_statements_info')) AS valid,
    jsonb_build_object('catalog',to_jsonb(p),'language',jsonb_build_array(l.oid::bigint,l.lanname),
      'schema',jsonb_build_array(n.oid::bigint,n.nspname,n.nspowner::bigint,n.nspacl),
      'definition',CASE WHEN p.prokind='f' THEN pg_get_functiondef(p.oid) ELSE NULL END) AS metadata
  FROM passport_extension e JOIN pg_depend d ON d.refclassid='pg_extension'::regclass
    AND d.refobjid=e.oid AND d.classid='pg_proc'::regclass AND d.objsubid=0 AND d.deptype='e'
  JOIN pg_proc p ON p.oid=d.objid JOIN pg_namespace n ON n.oid=p.pronamespace
  JOIN pg_language l ON l.oid=p.prolang
  WHERE p.proname IN ('pg_stat_statements','pg_stat_statements_info')
), passport_monitoring AS MATERIALIZED (
  SELECT (
    (SELECT count(*)=1 AND bool_and(extversion='1.12') FROM passport_extension)
    AND (SELECT count(*)=2 AND count(DISTINCT relname)=2 AND bool_and(valid) FROM passport_views)
    AND (SELECT count(*)=2 AND count(DISTINCT proname)=2 AND bool_and(valid) FROM passport_functions)
    AND NOT EXISTS(SELECT 1 FROM passport_views v WHERE
      (SELECT count(*) FROM pg_rewrite w WHERE w.ev_class=v.oid AND w.rulename='_RETURN'
        AND w.ev_type='1' AND w.is_instead AND w.ev_enabled='O')<>1)
    AND NOT EXISTS(SELECT 1 FROM passport_views v JOIN pg_rewrite w ON w.ev_class=v.oid
      JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=w.oid
      WHERE w.rulename='_RETURN' AND NOT (
        (d.refclassid='pg_class'::regclass AND d.refobjid=v.oid)
        OR (d.refclassid='pg_proc'::regclass AND (
          d.refobjid IN (SELECT oid FROM passport_functions)
          OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE p.oid=d.refobjid AND n.nspname='pg_catalog')))))
  ) IS TRUE AS valid,
  'sha256:' || encode(sha256(convert_to(jsonb_build_object('format',1,
    'extension',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.oid) FROM passport_extension e),
    'views',(SELECT jsonb_agg(metadata ORDER BY oid) FROM passport_views),
    'functions',(SELECT jsonb_agg(metadata ORDER BY oid) FROM passport_functions)
  )::text,'UTF8')),'hex') AS digest
)
"""


def _audit(subject: str, *, role_oid: bool = False, monitoring: bool = False) -> str:
    # The caller passes either the fixed PUBLIC pseudo-role or a validated role
    # literal. Reject all user/extension routine EXECUTE, including functions that
    # could expose business data without an ordinary relation grant.
    user = "r.oid" if role_oid else f"'{subject}'"
    table_privileges = f"""has_table_privilege({user}, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
            OR has_any_column_privilege({user}, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')"""
    routine_guard = ""
    if monitoring:
        table_privileges = f"""has_table_privilege({user}, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
            OR has_any_column_privilege({user}, c.oid, 'INSERT,UPDATE,REFERENCES')
            OR ((has_table_privilege({user}, c.oid, 'SELECT')
              OR has_any_column_privilege({user}, c.oid, 'SELECT'))
              AND NOT ((SELECT valid FROM passport_monitoring)
                AND c.oid IN (SELECT oid FROM passport_views)))"""
        routine_guard = """AND NOT ((SELECT valid FROM passport_monitoring)
            AND p.oid IN (SELECT oid FROM passport_functions))"""
    return f"""json_build_object(
      'database_create', has_database_privilege({user}, current_database(), 'CREATE'),
      'database_temp', has_database_privilege({user}, current_database(), 'TEMP'),
      'schema_create', EXISTS(SELECT 1 FROM pg_namespace n
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
          AND has_schema_privilege({user}, n.oid, 'CREATE')),
      'table_access', EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE CASE WHEN n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
          AND c.relkind IN ('r','p','v','m','f') THEN
          ({table_privileges}) ELSE false END),
      'sequence_access', EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE CASE WHEN n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind='S'
          THEN has_sequence_privilege({user}, c.oid, 'SELECT,USAGE,UPDATE') ELSE false END),
      'routine_access', EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
          AND has_function_privilege({user}, p.oid, 'EXECUTE') {routine_guard}))
    """


def snapshot(binding: dict[str, Any]) -> dict[str, Any]:
    """Observe private config text and fixed catalog facts; never expose this dict."""
    admin = _binding(binding)
    target = executor.target_snapshot(binding)
    role = _name(binding["username"])
    monitoring = "monitoring" in admin
    monitoring_result = (
        ", 'monitoring', (SELECT json_build_object('valid',valid,'digest',digest) FROM passport_monitoring)"
        if monitoring
        else ""
    )
    sql = f"""
    {_MONITORING_CTE if monitoring else ""}
    SELECT json_build_object(
      'version', current_setting('server_version_num')::int, 'encoding', current_setting('server_encoding'),
      'database', current_database(),
      'admin', current_user = '{admin["username"]}' AND session_user = '{admin["username"]}'
        AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper),
      'ssl', current_setting('ssl') = 'on',
      'pgdata', current_setting('data_directory'), 'hba_path', current_setting('hba_file'),
      'ident_path', current_setting('ident_file'),
      'hba', pg_read_file(current_setting('hba_file'), 0, {MAX_CONFIG_BYTES + 1}),
      'ident', pg_read_file(current_setting('ident_file'), 0, {MAX_CONFIG_BYTES + 1}),
      'auto_size', (pg_stat_file(current_setting('data_directory') || '/postgresql.auto.conf')).size,
      'auto_digest', 'sha256:' || encode(sha256(pg_read_binary_file(
        current_setting('data_directory') || '/postgresql.auto.conf', 0, {MAX_CONFIG_BYTES + 1})), 'hex'),
      'ca', (SELECT json_build_object('setting', setting, 'source', source, 'sourcefile', sourcefile,
        'pending_restart', pending_restart) FROM pg_settings WHERE name='ssl_ca_file'),
      'ca_digest', CASE WHEN current_setting('ssl_ca_file') = '' THEN NULL ELSE 'sha256:' || encode(sha256(
        pg_read_binary_file(CASE WHEN left(current_setting('ssl_ca_file'),1)='/' THEN current_setting('ssl_ca_file')
          ELSE current_setting('data_directory') || '/' || current_setting('ssl_ca_file') END,
          0, {MAX_CONFIG_BYTES + 1})), 'hex') END,
      'ca_size', CASE WHEN current_setting('ssl_ca_file') = '' THEN 0 ELSE (pg_stat_file(
        CASE WHEN left(current_setting('ssl_ca_file'),1)='/' THEN current_setting('ssl_ca_file')
          ELSE current_setting('data_directory') || '/' || current_setting('ssl_ca_file') END)).size END,
      'parse_ok', NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL)
        AND NOT EXISTS(SELECT 1 FROM pg_ident_file_mappings WHERE error IS NOT NULL)
        AND NOT EXISTS(SELECT 1 FROM pg_file_settings WHERE error IS NOT NULL),
      'public_audit', {_audit("public", monitoring=monitoring)},
      'role', (SELECT json_build_object(
        'oid', r.oid::bigint, 'login', rolcanlogin, 'superuser', rolsuper, 'createdb', rolcreatedb,
        'createrole', rolcreaterole, 'inherit', rolinherit, 'replication', rolreplication,
        'bypassrls', rolbypassrls, 'connection_limit', rolconnlimit, 'password_set', rolpassword IS NOT NULL,
        'valid_until_set', rolvaliduntil IS NOT NULL,
        'memberships', (SELECT count(*) FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid),
        'marker', CASE WHEN shobj_description(r.oid,'pg_authid') ~ '^query-passport:[a-f0-9]{{32}}$'
          THEN shobj_description(r.oid,'pg_authid') ELSE NULL END,
        'settings', (SELECT coalesce(json_agg(json_build_object('database', d.datname, 'values', s.setconfig)), '[]')
          FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase WHERE s.setrole=r.oid),
        'audit', {_audit(role, role_oid=True, monitoring=monitoring)}) FROM pg_authid r WHERE rolname='{role}')
      {monitoring_result}
    );
    """
    result = _sql(binding, sql)
    _require(executor.target_snapshot(binding) == target)
    _require(
        set(result)
        == {
            "version",
            "encoding",
            "database",
            "admin",
            "ssl",
            "pgdata",
            "hba_path",
            "ident_path",
            "hba",
            "ident",
            "auto_size",
            "auto_digest",
            "ca",
            "ca_digest",
            "ca_size",
            "parse_ok",
            "public_audit",
            "role",
        }
        | ({"monitoring"} if monitoring else set()),
        "EXECUTOR_FAILED",
    )
    if monitoring:
        observed = result["monitoring"]
        _require(
            type(observed) is dict
            and observed.keys() == {"valid", "digest"}
            and type(observed["valid"]) is bool
            and type(observed["digest"]) is str
            and re.fullmatch(r"sha256:[a-f0-9]{64}", observed["digest"]) is not None,
            "EXECUTOR_FAILED",
        )
    for field in ("hba", "ident"):
        value = result[field]
        _require(type(value) is str and len(value.encode()) <= MAX_CONFIG_BYTES, "EXECUTOR_FAILED")
        # Authentication files can contain LDAP/RADIUS secrets. They are outside
        # this backend's non-secret config projection; do not journal them.
        _require(
            re.search(r"(?i)(ldapbindpasswd|radiussecrets)\s*=|-----BEGIN", value) is None,
            "UNSUPPORTED_OPERATION",
        )
    _require(
        type(result["auto_size"]) is int and 0 <= result["auto_size"] <= MAX_CONFIG_BYTES,
        "UNSUPPORTED_OPERATION",
    )
    _require(
        type(result["ca_size"]) is int and 0 <= result["ca_size"] <= MAX_CONFIG_BYTES,
        "UNSUPPORTED_OPERATION",
    )
    result["target_snapshot"] = target
    return result


def _clean_audit(audit: Any) -> bool:
    return (
        type(audit) is dict
        and audit.keys() == _AUDIT_FIELDS
        and all(value is False for value in audit.values())
    )


def _layout(binding: dict[str, Any], observed: dict[str, Any]) -> None:
    admin = _binding(binding)
    if "monitoring" in admin:
        monitoring = observed.get("monitoring")
        _require(type(monitoring) is dict and monitoring.keys() == {"valid", "digest"})
        assert isinstance(monitoring, dict)
        _require(
            monitoring["valid"] is True and monitoring["digest"] == admin["monitoring"]["digest"]
        )
    else:
        _require("monitoring" not in observed)
    pgdata = admin["pgdata"]
    _require(
        type(observed["version"]) is int and 180000 <= observed["version"] < 190000,
        "UNSUPPORTED_OPERATION",
    )
    _require(
        observed["encoding"] == "UTF8" and observed["admin"] is True and observed["ssl"] is True,
        "UNSUPPORTED_OPERATION",
    )
    _require(observed["database"] == binding["request"]["profile"]["database"])
    _require(
        observed["pgdata"] == pgdata
        and observed["hba_path"] == pgdata + "/pg_hba.conf"
        and observed["ident_path"] == pgdata + "/pg_ident.conf",
        "UNSUPPORTED_OPERATION",
    )
    ca = observed["ca"]
    _require(
        type(ca) is dict and ca.keys() == {"setting", "source", "sourcefile", "pending_restart"},
        "EXECUTOR_FAILED",
    )
    _require(
        ca["source"] in ("default", "configuration file") and ca["pending_restart"] is False,
        "UNSUPPORTED_OPERATION",
    )
    _ca_path(binding, observed)
    _require(observed["parse_ok"] is True, "VERIFICATION_FAILED")


def validate_provision(binding: dict[str, Any], before: dict[str, Any]) -> None:
    """Reject unsupported initial state without changing any preexisting role/grant."""
    _layout(binding, before)
    _require(before["role"] is None, "PERMISSION_DENIED")
    _require(_clean_audit(before["public_audit"]), "PERMISSION_DENIED")


def _ca_path(binding: dict[str, Any], observed: dict[str, Any]) -> str:
    setting = observed["ca"]["setting"]
    _require(type(setting) is str, "EXECUTOR_FAILED")
    if not setting:
        return ""
    return _path(setting if setting.startswith("/") else binding["admin"]["pgdata"] + "/" + setting)


def _rules(binding: dict[str, Any], before: dict[str, Any], operation_id: str) -> dict[str, str]:
    owner = _operation(operation_id)
    map_name = "passport_" + operation_id
    hba, ident = build_auth_rules(
        binding["request"]["profile"]["database"],
        binding["username"],
        binding["expected_dn"],
        binding["admin"]["network_cidr"],
        map_name,
    )
    _require(
        owned_block(before["hba"], owner) is None and owned_block(before["ident"], owner) is None
    )
    return {
        "hba": propose_config(before["hba"], owner, hba),
        "ident": propose_config(before["ident"], owner, ident),
        "map": map_name,
        "owner": owner,
        "ca": binding["admin"]["pgdata"] + "/query-passport-client-ca-" + operation_id + ".crt",
    }


_SHELL_PREFIX = r"""
set -efu
umask 077
fail() { printf '{"error":"%s"}\n' "$1"; exit 0; }
cd -- "$1"
[ "$(pwd -P)" = "$1" ] || fail TARGET_DRIFT
safe_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %h -- "$1")" = 1 ] || fail TARGET_DRIFT
}
owned_file() {
  safe_file "$1"
  [ "$(stat -c %u -- "$1")" = "$(id -u)" ] && [ "$(stat -c %g -- "$1")" = "$(id -g)" ] || fail TARGET_DRIFT
  mode=$(stat -c %a -- "$1")
  [ "$((0$mode & 022))" = 0 ] || fail TARGET_DRIFT
}
digest() { sha256sum < "$1" | cut -d ' ' -f 1; }
"""

_CAS_SCRIPT = (
    _SHELL_PREFIX
    + r"""
file=$2
expected=$3
owned_file "$file"
[ "$(digest "$file")" = "$expected" ] || fail TARGET_DRIFT
metadata=$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y:%Z' -- "$file")
stable_metadata=$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y' -- "$file")
temporary=$(mktemp -d .query-passport-write."$4".XXXXXXXXXX)
trap 'rm -f -- "$temporary/content"; if [ ! -e "$temporary/prior" ] && [ ! -L "$temporary/prior" ]; then rmdir -- "$temporary"; fi' EXIT HUP INT TERM
cat > "$temporary/content"
[ "$(wc -c < "$temporary/content")" -le 262144 ] || fail EXECUTOR_FAILED
chmod --reference="$file" -- "$temporary/content"
owned_file "$file"
[ "$(digest "$file")" = "$expected" ] || fail TARGET_DRIFT
[ "$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y:%Z' -- "$file")" = "$metadata" ] || fail TARGET_DRIFT
mv -T -- "$file" "$temporary/prior"
if [ ! -f "$temporary/prior" ] || [ -L "$temporary/prior" ] ||
   [ "$(digest "$temporary/prior")" != "$expected" ] ||
   [ "$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y' -- "$temporary/prior")" != "$stable_metadata" ]; then
  ln -P -- "$temporary/prior" "$file" 2>/dev/null || :
  fail DB_CONFIG_WRITE_FAILED
fi
ln -- "$temporary/content" "$file" 2>/dev/null || fail DB_CONFIG_WRITE_FAILED
rm -- "$temporary/content"
sync -f .
printf '{"status":"written"}\n'
"""
)

_AUTO_SCRIPT = (
    _SHELL_PREFIX
    + r"""
action=$2
operation=$3
expected=$4
file=postgresql.auto.conf
owned_file "$file"
current=$(digest "$file")
metadata=$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y:%Z' -- "$file")
stable_metadata=$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y' -- "$file")
temporary=$(mktemp -d .query-passport-auto."$operation".XXXXXXXXXX)
trap 'rm -f -- "$temporary/block" "$temporary/actual" "$temporary/base" "$temporary/new"; if [ ! -e "$temporary/prior" ] && [ ! -L "$temporary/prior" ]; then rmdir -- "$temporary"; fi' EXIT HUP INT TERM
cat > "$temporary/block"
offsets=$(awk -v wanted="$operation" -v size="$(wc -c < "$file")" '
function invalid() { bad=1; exit 2 }
BEGIN { offset=0; start=-1; finish=-1; active=""; previous="" }
{
  line=$0; sub(/\r$/, "", line)
  if (index(tolower(line), "query-passport-auto:")) {
    if (split(line, parts, ":") != 3 || parts[1] != "# query-passport-auto" ||
        length(parts[2]) != 32 || parts[2] !~ /^[a-f0-9]+$/ || previous ~ /\\$/) invalid()
    owner=parts[2]
    if (parts[3] == "begin") {
      if (active != "" || seen[owner]++) invalid()
      active=owner
      if (owner == wanted) start=offset-1
    } else if (parts[3] == "end") {
      if (active != owner) invalid()
      if (owner == wanted) finish=(offset+length($0)+1 < size ? offset+length($0)+1 : size)
      active=""
    } else invalid()
  }
  previous=line; offset+=length($0)+1
}
END { if (bad || active != "") exit 2; print start, finish }
' "$file") || fail TARGET_DRIFT
set -- $offsets
start=$1
finish=$2
state=absent
if [ "$finish" -ge 0 ]; then
  [ "$start" -ge 0 ] || fail TARGET_DRIFT
  dd if="$file" of="$temporary/actual" bs=1 skip="$start" count="$((finish-start))" 2>/dev/null
  cmp -s -- "$temporary/block" "$temporary/actual" || fail TARGET_DRIFT
  dd if="$file" of="$temporary/base" bs=1 count="$start" 2>/dev/null
  dd if="$file" bs=1 skip="$finish" 2>/dev/null >> "$temporary/base"
  state=present
else
  cp -- "$file" "$temporary/base"
fi
base=$(digest "$temporary/base")
if [ "$action" = install ]; then
  [ "$base" = "$expected" ] || fail TARGET_DRIFT
  if [ "$state" = absent ]; then
    cat "$file" "$temporary/block" > "$temporary/new"
  fi
elif [ "$action" != observe ]; then
  fail EXECUTOR_FAILED
fi
if [ -f "$temporary/new" ]; then
  chmod --reference="$file" -- "$temporary/new"
  safe_file "$file"
  [ "$(digest "$file")" = "$current" ] || fail TARGET_DRIFT
  [ "$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y:%Z' -- "$file")" = "$metadata" ] || fail TARGET_DRIFT
  mv -T -- "$file" "$temporary/prior"
  if [ ! -f "$temporary/prior" ] || [ -L "$temporary/prior" ] ||
     [ "$(digest "$temporary/prior")" != "$current" ] ||
     [ "$(stat -c '%d:%i:%a:%u:%g:%h:%s:%Y' -- "$temporary/prior")" != "$stable_metadata" ]; then
    ln -P -- "$temporary/prior" "$file" 2>/dev/null || :
    fail DB_CONFIG_WRITE_FAILED
  fi
  ln -- "$temporary/new" "$file" 2>/dev/null || fail DB_CONFIG_WRITE_FAILED
  rm -- "$temporary/new"
  sync -f .
fi
printf '{"state":"%s","base_digest":"sha256:%s","digest":"sha256:%s"}\n' "$state" "$base" "$(digest "$file")"
"""
)

_CA_SCRIPT = (
    _SHELL_PREFIX
    + r"""
original=$2
expected=$3
destination=$4
temporary=$(mktemp -d .query-passport-ca.XXXXXXXXXX)
trap 'rm -f -- "$temporary/new" "$temporary/bundle"; rmdir -- "$temporary"' EXIT HUP INT TERM
cat > "$temporary/new"
: > "$temporary/bundle"
if [ -n "$original" ]; then
  cursor=$original
  while [ "$cursor" != / ]; do
    [ ! -L "$cursor" ] || fail TARGET_DRIFT
    cursor=${cursor%/*}; [ -n "$cursor" ] || cursor=/
  done
  safe_file "$original"
  [ "$(digest "$original")" = "$expected" ] || fail TARGET_DRIFT
  cat "$original" > "$temporary/bundle"
  printf '\n' >> "$temporary/bundle"
fi
cat "$temporary/new" >> "$temporary/bundle"
if [ -n "$original" ]; then
  safe_file "$original"
  [ "$(digest "$original")" = "$expected" ] || fail TARGET_DRIFT
fi
if [ -e "$destination" ] || [ -L "$destination" ]; then
  safe_file "$destination"
  cmp -s -- "$destination" "$temporary/bundle" || fail TARGET_DRIFT
else
  ln -- "$temporary/bundle" "$destination"
  rm -- "$temporary/bundle"
  sync -f .
fi
printf '{"status":"present","digest":"sha256:%s"}\n' "$(digest "$destination")"
"""
)


def _shell(binding: dict[str, Any], script: str, args: list[str], data: bytes) -> dict[str, Any]:
    return _json(
        _exec(
            binding,
            ["/bin/sh", "-c", script, "query-passport", binding["admin"]["pgdata"], *args],
            data,
            limit=2048,
        )
    )


def _replace(
    binding: dict[str, Any], filename: str, current: str, desired: str, operation_id: str
) -> None:
    _require(filename in ("pg_hba.conf", "pg_ident.conf"), "EXECUTOR_FAILED")
    _operation(operation_id)
    result = _shell(
        binding, _CAS_SCRIPT, [filename, config_digest(current)[7:], operation_id], desired.encode()
    )
    _require(result == {"status": "written"}, "EXECUTOR_FAILED")


def _auto(
    binding: dict[str, Any], before: dict[str, Any], operation_id: str, action: str
) -> dict[str, Any]:
    _require(action in ("observe", "install"), "EXECUTOR_FAILED")
    path = _rules(binding, before, operation_id)["ca"]
    block = (
        f"\n# query-passport-auto:{operation_id}:begin\nssl_ca_file = '{path}'\n"
        f"# query-passport-auto:{operation_id}:end\n"
    )
    result = _shell(
        binding, _AUTO_SCRIPT, [action, operation_id, before["auto_digest"][7:]], block.encode()
    )
    _require(
        result.keys() == {"state", "base_digest", "digest"}
        and result["state"] in ("absent", "present"),
        "EXECUTOR_FAILED",
    )
    return result


def _safe_role(binding: dict[str, Any], role: Any, operation_id: str) -> bool:
    if type(role) is not dict or role.get("marker") != "query-passport:" + operation_id:
        return False
    if any(
        role.get(field) is not False
        for field in (
            "superuser",
            "createdb",
            "createrole",
            "inherit",
            "replication",
            "bypassrls",
            "password_set",
            "valid_until_set",
        )
    ):
        return False
    return (
        type(role.get("oid")) is int
        and role["oid"] > 0
        and type(role.get("login")) is bool
        and type(role.get("connection_limit")) is int
        and role["connection_limit"] == binding["admin"]["connection_limit"]
        and type(role.get("memberships")) is int
        and role["memberships"] == 0
        and _clean_audit(role.get("audit"))
        and role.get("settings")
        == [{"database": binding["request"]["profile"]["database"], "values": _ROLE_SETTINGS}]
    )


def _disable(binding: dict[str, Any], operation_id: str, role_oid: int) -> None:
    username = _name(binding["username"])
    marker = "query-passport:" + operation_id
    _require(type(role_oid) is int and role_oid > 0, "EXECUTOR_FAILED")
    result = _sql(
        binding,
        f"""BEGIN;
      DO $passport$ BEGIN
        PERFORM 1 FROM pg_authid WHERE oid={role_oid} AND rolname='{username}'
          AND shobj_description(oid,'pg_authid')='{marker}' FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'ownership mismatch'; END IF;
        ALTER ROLE "{username}" NOLOGIN;
      END; $passport$;
      COMMIT; SELECT json_build_object('status','disabled');""",
    )
    _require(result == {"status": "disabled"}, "EXECUTOR_FAILED")


def _create(binding: dict[str, Any], operation_id: str) -> None:
    username = _name(binding["username"])
    database = binding["request"]["profile"]["database"]
    limit = binding["admin"]["connection_limit"]
    settings = "\n".join(
        f'ALTER ROLE "{username}" IN DATABASE "{database}" SET {item.split("=", 1)[0]} = '
        f"'{item.split('=', 1)[1]}';"
        for item in _ROLE_SETTINGS
    )
    result = _sql(
        binding,
        f"""BEGIN;
      CREATE ROLE "{username}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
        NOBYPASSRLS CONNECTION LIMIT {limit};
      COMMENT ON ROLE "{username}" IS 'query-passport:{operation_id}';
      GRANT CONNECT ON DATABASE "{database}" TO "{username}";
      {settings}
      COMMIT; SELECT json_build_object('status','created');""",
    )
    _require(result == {"status": "created"}, "EXECUTOR_FAILED")


def _reload(binding: dict[str, Any], expected_ca: str) -> None:
    observed = _sql(
        binding, "SELECT json_build_object('loaded_at', extract(epoch FROM pg_conf_load_time()));"
    )
    before = observed.get("loaded_at")
    _require(type(before) in (int, float), "EXECUTOR_FAILED")
    result = _sql(binding, "SELECT json_build_object('reload',pg_reload_conf());")
    _require(result == {"reload": True}, "VERIFICATION_FAILED")
    for _ in range(12):
        result = _sql(
            binding,
            """SELECT json_build_object('setting', current_setting('ssl_ca_file'),
          'loaded_at', extract(epoch FROM pg_conf_load_time()),
          'valid', NOT EXISTS(SELECT 1 FROM pg_file_settings WHERE error IS NOT NULL)
            AND NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL)
            AND NOT EXISTS(SELECT 1 FROM pg_ident_file_mappings WHERE error IS NOT NULL));""",
        )
        if (
            result.get("setting") == expected_ca
            and result.get("valid") is True
            and type(result.get("loaded_at")) in (int, float)
            and result["loaded_at"] > before
        ):
            return
    raise ContractError("VERIFICATION_FAILED")


def _check_rules(binding: dict[str, Any], rules: dict[str, str]) -> None:
    # PostgreSQL 18 hbafuncs.c reports map/clientcert, but omits clientname from
    # the view. Exact owned text independently proves clientname=DN; actual
    # certificate acceptance/rejection belongs to the separate client verifier.
    database = binding["request"]["profile"]["database"]
    username = binding["username"]
    dn = binding["expected_dn"]
    mapping = rules["map"]
    result = _sql(
        binding,
        f"""SELECT json_build_object(
      'ident', (SELECT count(*)=1 AND bool_and(sys_name='{dn}' AND pg_username='{username}')
        FROM pg_ident_file_mappings WHERE map_name='{mapping}'),
      'hba', (SELECT count(*)=3 FROM pg_hba_file_rules WHERE rule_number<=3 AND
        ((rule_number=1 AND type='hostssl' AND database=ARRAY['{database}'] AND user_name=ARRAY['{username}']
          AND auth_method='cert' AND options @> ARRAY['clientcert=verify-full','map={mapping}']) OR
         (rule_number=2 AND type='host' AND database=ARRAY['all'] AND user_name=ARRAY['{username}'] AND auth_method='reject') OR
         (rule_number=3 AND type='local' AND database=ARRAY['all'] AND user_name=ARRAY['{username}'] AND auth_method='reject'))),
      'valid', NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL)
        AND NOT EXISTS(SELECT 1 FROM pg_ident_file_mappings WHERE error IS NOT NULL));""",
    )
    _require(result == {"ident": True, "hba": True, "valid": True}, "VERIFICATION_FAILED")


def _before(plan: dict[str, Any]) -> dict[str, Any]:
    _require(type(plan) is dict and type(plan.get("before")) is dict, "AUTHORIZATION_REQUIRED")
    return dict(plan["before"])


def _enable(binding: dict[str, Any], operation_id: str, role_oid: int) -> None:
    username = _name(binding["username"])
    _require(type(role_oid) is int and role_oid > 0, "EXECUTOR_FAILED")
    result = _sql(
        binding,
        f"""BEGIN;
      DO $passport$ BEGIN
        PERFORM 1 FROM pg_authid WHERE oid={role_oid} AND rolname='{username}'
          AND shobj_description(oid,'pg_authid')='query-passport:{operation_id}'
          AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
          AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls AND rolpassword IS NULL
          FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'ownership mismatch'; END IF;
        ALTER ROLE "{username}" LOGIN;
      END; $passport$;
      COMMIT; SELECT json_build_object('status','enabled');""",
    )
    _require(result == {"status": "enabled"}, "EXECUTOR_FAILED")


def verify_applied(
    binding: dict[str, Any], plan: dict[str, Any], operation_id: str
) -> dict[str, Any]:
    """Reconcile owned configuration/role before delivery; no live-client claim."""
    before = _before(plan)
    expected_ca_digest = plan.get("applied_ca_digest")
    _require(
        type(expected_ca_digest) is str
        and re.fullmatch(r"sha256:[a-f0-9]{64}", expected_ca_digest) is not None,
        "AUTHORIZATION_REQUIRED",
    )
    rules = _rules(binding, before, operation_id)
    current = snapshot(binding)
    _layout(binding, current)
    _require(current["target_snapshot"] == before["target_snapshot"])
    _require(
        _safe_role(binding, current["role"], operation_id) and current["role"]["login"] is True
    )
    for field in ("hba", "ident"):
        expected = owned_block(rules[field], rules["owner"])
        _require(owned_block(current[field], rules["owner"]) == expected)
        if field == "hba":
            _require(expected is not None and current[field].startswith(expected))
    _require(current["ca"]["setting"] == rules["ca"])
    _require(current["ca_digest"] == expected_ca_digest)
    _require(_auto(binding, before, operation_id, "observe")["state"] == "present")
    _check_rules(binding, rules)
    return {
        "status": "applied",
        "configuration": "reconciled",
        "role": "login",
        "db_connectivity": "not_checked",
    }


def apply(
    binding: dict[str, Any], plan: dict[str, Any], operation_id: str, client_ca: bytes
) -> dict[str, Any]:
    """Resume only this operation; keep its check identity closed until reload."""
    _binding(binding)
    before = _before(plan)
    validate_provision(binding, before)
    rules = _rules(binding, before, operation_id)
    _require(type(client_ca) is bytes and 0 < len(client_ca) <= 65536, "CREDENTIAL_ACCESS_DENIED")
    try:
        certificates = x509.load_pem_x509_certificates(client_ca)
        _require(
            len(certificates) == 1 and b"PRIVATE KEY" not in client_ca, "CREDENTIAL_ACCESS_DENIED"
        )
        ca = certificates[0]
        _require(
            ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            and ca.not_valid_before_utc <= datetime.now(UTC) < ca.not_valid_after_utc,
            "CREDENTIAL_ACCESS_DENIED",
        )
    except (ValueError, x509.ExtensionNotFound) as error:
        raise ContractError("CREDENTIAL_ACCESS_DENIED") from error
    current = snapshot(binding)
    _layout(binding, current)
    _require(current["target_snapshot"] == before["target_snapshot"])
    _require(_clean_audit(current["public_audit"]), "PERMISSION_DENIED")
    for field in ("hba", "ident"):
        _require(current[field] in (before[field], rules[field]))
    auto = _auto(binding, before, operation_id, "observe")
    _require(auto["base_digest"] == before["auto_digest"])
    _require(current["ca"]["setting"] in (before["ca"]["setting"], rules["ca"]))
    if current["role"] is not None:
        _require(_safe_role(binding, current["role"], operation_id), "PERMISSION_DENIED")
    if current["role"] is None:
        _create(binding, operation_id)
    else:
        _disable(binding, operation_id, current["role"]["oid"])
    result = _shell(
        binding,
        _CA_SCRIPT,
        [
            _ca_path(binding, before),
            (before["ca_digest"] or "sha256:-")[7:],
            PurePosixPath(rules["ca"]).name,
        ],
        client_ca,
    )
    _require(
        result.get("status") == "present" and type(result.get("digest")) is str,
        "EXECUTOR_FAILED",
    )
    applied_ca_digest = result["digest"]
    for field, filename in (("ident", "pg_ident.conf"), ("hba", "pg_hba.conf")):
        if current[field] != rules[field]:
            _replace(binding, filename, current[field], rules[field], operation_id)
    installed_auto = _auto(binding, before, operation_id, "install")
    _check_rules(binding, rules)
    _reload(binding, rules["ca"])
    checked = snapshot(binding)
    _layout(binding, checked)
    _require(_safe_role(binding, checked["role"], operation_id), "PERMISSION_DENIED")
    _require(checked["role"]["login"] is False)
    _require(checked["target_snapshot"] == before["target_snapshot"])
    _require(checked["ca_digest"] == applied_ca_digest and checked["ca"]["setting"] == rules["ca"])
    _require(checked["auto_digest"] == installed_auto["digest"])
    _require(checked["hba"] == rules["hba"] and checked["ident"] == rules["ident"])
    _enable(binding, operation_id, checked["role"]["oid"])
    verified = verify_applied(
        binding, {**plan, "applied_ca_digest": applied_ca_digest}, operation_id
    )
    return {**verified, "ca_digest": applied_ca_digest}
