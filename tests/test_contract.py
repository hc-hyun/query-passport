import copy
import json
from pathlib import Path

import jsonschema
import pytest

from query_passport.contract import ContractError, decode, respond, validate

ROOT = Path(__file__).resolve().parents[1]
REQUEST = json.loads((ROOT / "examples/request.json").read_text())
SCHEMA = json.loads((ROOT / "schemas/request-v1.schema.json").read_text())


@pytest.fixture
def request_data():
    return copy.deepcopy(REQUEST)


def test_schema_is_valid():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("command,status", [("inspect", "validated"), ("plan", "planned")])
@pytest.mark.parametrize("count", [0, 1, 1000000])
def test_offline_facts(request_data, command, status, count):
    request_data["source_count"] = count
    jsonschema.validate(request_data, SCHEMA)
    response = respond(command, decode(json.dumps(request_data).encode()))
    assert response["status"] == status
    assert response["errors"] == []
    result = response["result"]
    assert result["source_count"] == count
    assert result["profile_validation"] == "passed"
    for field in (
        "source_inventory",
        "query_man_validation",
        "target_identity",
        "db_connectivity",
        "certificate_validation",
        "authentication",
        "deployment",
        "reader_permissions",
        "source_admission",
        "application_readiness",
    ):
        assert result[field] == "not_checked"
    if command == "plan":
        assert result["executable"] is False
        assert result["actions"] == []
        assert result["differences"] == result["target_snapshot"] == "unknown"
        assert result["recovery"] == "no_changes_performed"


@pytest.mark.parametrize("field", list(REQUEST))
def test_required_fields(request_data, field):
    del request_data[field]
    with pytest.raises(ContractError):
        validate(request_data)


@pytest.mark.parametrize(
    "path,value",
    [
        (("contract_version",), "2"),
        (("contract_version",), 1),
        (("profile_version",), 2),
        (("profile_version",), True),
        (("profile_version",), "1"),
        (("scope",), "source"),
        (("environment",), "unbound-environment"),
        (("environment",), []),
        (("target_alias",), "host;id"),
        (("deployment_alias",), "../key"),
        (("source_count",), -1),
        (("source_count",), True),
        (("source_count",), 1000001),
        (("profile", "id"), "query_man"),
        (("profile", "id"), "Example-db"),
        (("profile", "id"), "a" * 64),
        (("profile", "host"), "db.example.test\n"),
        (("profile", "host"), "postgres://user:fake@db"),
        (("profile", "host"), "-db.test"),
        (("profile", "host"), "db..test"),
        (("profile", "host"), "a" * 64),
        (("profile", "host"), "db.test."),
        (("profile", "port"), 0),
        (("profile", "port"), 65536),
        (("profile", "port"), True),
        (("profile", "port"), "5432"),
        (("profile", "database"), "db-name"),
        (("profile", "database"), "a" * 64),
        (("profile", "sslmode"), "require"),
        (("profile", "authentication", "type"), "password"),
        (("required_capabilities",), ["certificate.issue.v1"]),
        (("required_capabilities",), ["plan.offline.v1", "plan.offline.v1"]),
        (("required_capabilities",), [None]),
    ],
)
def test_invalid_closed_projection(request_data, path, value):
    parent = request_data
    for field in path[:-1]:
        parent = parent[field]
    parent[path[-1]] = value
    with pytest.raises(ContractError):
        validate(request_data)
    assert not jsonschema.Draft202012Validator(SCHEMA).is_valid(request_data)


@pytest.mark.parametrize("value", [None, [], True, "input", 1])
def test_non_object(value):
    with pytest.raises(ContractError):
        validate(value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"secret":',
        b"\xff",
        b"{}{}",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"[" * 1000 + b"]" * 1000,
        b"[" * 9 + b"0" + b"]" * 9,
        b" " * 65537,
    ],
)
def test_malformed_and_bounded_json(raw):
    with pytest.raises(ContractError):
        decode(raw)


def test_profile_and_database_are_distinct_and_not_corrected(request_data):
    request_data["profile"]["database"] = "Mixed_DB"
    assert validate(request_data)["profile"] == request_data["profile"]
    assert request_data["profile"]["id"] != request_data["profile"]["database"]


def test_digest_binds_request_and_is_stable(request_data):
    first = respond("plan", request_data)["result"]
    assert first == respond("plan", dict(reversed(list(request_data.items()))))["result"]
    request_data["target_alias"] = "another-target"
    changed = respond("plan", request_data)["result"]
    assert first["input_digest"] != changed["input_digest"]
    assert first["plan_digest"] != changed["plan_digest"]


def test_capabilities_are_only_implemented():
    result = respond("capabilities")["result"]
    assert result["commands"] == ["capabilities", "inspect", "plan", "verify"]
    assert result["capabilities"] == [
        "profile.inspect.v1",
        "plan.offline.v1",
        "connection.verify.v1",
    ]
    assert result["backend_types"] == ["offline", "local-docker"]


@pytest.mark.parametrize("path", [("profile",), ("profile", "authentication")])
def test_nested_required_fields(request_data, path):
    parent = request_data
    for field in path:
        parent = parent[field]
    for field in list(parent):
        value = parent.pop(field)
        with pytest.raises(ContractError):
            validate(request_data)
        parent[field] = value


def test_supported_capabilities_and_protected_context(request_data):
    request_data["environment"] = "protected"
    request_data["required_capabilities"] = [
        "profile.inspect.v1",
        "plan.offline.v1",
        "connection.verify.v1",
    ]
    jsonschema.validate(request_data, SCHEMA)
    result = respond("plan", request_data)["result"]
    assert result["executable"] is False
    assert result["target_identity"] == "not_checked"


@pytest.mark.parametrize("path", [("profile_version",), ("source_count",), ("profile", "port")])
def test_wire_integers_reject_float_notation(request_data, path):
    parent = request_data
    for field in path[:-1]:
        parent = parent[field]
    parent[path[-1]] = float(parent[path[-1]])
    with pytest.raises(ContractError):
        decode(json.dumps(request_data).encode())


def test_documented_json_matches_implementation():
    import re

    document = (ROOT / "docs/tool-contract.md").read_text()
    examples = [json.loads(block) for block in re.findall(r"```json\n(.*?)\n```", document, re.S)]
    assert examples == [REQUEST, respond("plan", REQUEST)]
