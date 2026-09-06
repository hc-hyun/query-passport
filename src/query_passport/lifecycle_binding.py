"""Operator-only authorization for local issuance, DB changes and delivery.

The public request never supplies file paths, admin identities, arbitrary actions,
or an approval flag. A local binding cannot authorize protected environments.
"""

import ipaddress
from pathlib import Path
from typing import Any

from .contract import ContractError, matches, object_fields, require
from .executor import validate_binding

OPERATIONS = frozenset({"verify", "prepare", "issue", "apply", "deliver", "rotate", "status"})


def verification_projection(binding: dict[str, Any], credential_dir: str) -> dict[str, Any]:
    """Discard every mutation permission before handing a bundle to M2 verify."""
    return {
        **{key: value for key, value in binding.items() if key not in {"admin", "lifecycle"}},
        "binding_version": 1,
        "operations": ["verify"],
        "credential_dir": credential_dir,
    }


def _path(value: Any) -> Path:
    require(type(value) is str and 1 <= len(value) <= 4096)
    require(value.startswith("/") and not value.startswith("//"))
    require(all(32 <= ord(char) < 127 for char in value) and "," not in value)
    path = Path(value)
    require(".." not in path.parts and str(path) == value and path != Path("/"))
    return path


def validate_lifecycle_binding(binding: Any, request: dict[str, Any], operation: str) -> None:
    try:
        require(type(binding) is dict and type(binding.get("binding_version")) is int)
        require(binding["binding_version"] == 2)
        require(operation in OPERATIONS)
        require({"admin", "lifecycle"} <= binding.keys())
        # The existing closed validator also rejects unknown top-level fields.
        validate_binding(verification_projection(binding, binding["credential_dir"]), request)
        operations = binding["operations"]
        require(type(operations) is list and 1 <= len(operations) <= len(OPERATIONS))
        require(all(type(item) is str and item in OPERATIONS for item in operations))
        require(len(set(operations)) == len(operations) and operation in operations)
        required = {
            "deliver": {"verify"},
            "rotate": {"issue", "deliver", "verify"},
        }.get(operation, set())
        require(required <= set(operations))
        admin = binding["admin"]
        object_fields(
            admin,
            {"uid", "gid", "socket_directory", "pgdata", "network_cidr", "connection_limit"},
            {"username", "monitoring"},
        )
        require(matches(admin.get("username", "postgres"), r"[a-z_][a-z0-9_]{0,62}", 63))
        if "monitoring" in admin:
            monitoring = admin["monitoring"]
            object_fields(monitoring, {"extension", "digest"})
            require(monitoring["extension"] == "pg_stat_statements")
            require(matches(monitoring["digest"], r"sha256:[a-f0-9]{64}", 71))
        for name in ("uid", "gid"):
            require(type(admin[name]) is int and 1 <= admin[name] <= 2147483647)
        require(admin["socket_directory"] == "/var/run/postgresql")
        _path(admin["pgdata"])
        require(type(admin["network_cidr"]) is str)
        network = ipaddress.ip_network(admin["network_cidr"], strict=True)
        require(network.version == 4 and str(network) == admin["network_cidr"])
        require(network.prefixlen >= 16 and ipaddress.ip_address(binding["hostaddr"]) in network)
        require(type(admin["connection_limit"]) is int and admin["connection_limit"] == 2)
        lifecycle = binding["lifecycle"]
        object_fields(
            lifecycle,
            {
                "authority_dir",
                "authority_id",
                "generations_dir",
                "server_ca_file",
                "lifetime_days",
                "allow_initialize_authority",
                "allow_create_check_role",
            },
        )
        require(matches(lifecycle["authority_id"], r"[a-z][a-z0-9-]*", 63))
        require(type(lifecycle["lifetime_days"]) is int and 1 <= lifecycle["lifetime_days"] <= 90)
        require(type(lifecycle["allow_initialize_authority"]) is bool)
        require(lifecycle["allow_create_check_role"] is True)
        locations = [
            _path(lifecycle["authority_dir"]),
            _path(lifecycle["generations_dir"]),
            _path(binding["credential_dir"]),
        ]
        server_ca = _path(lifecycle["server_ca_file"])
        for index, location in enumerate(locations):
            require(server_ca != location and location not in server_ca.parents)
            for other in locations[index + 1 :]:
                require(
                    location != other
                    and location not in other.parents
                    and other not in location.parents
                )
    except (ContractError, ValueError, TypeError, KeyError) as error:
        if isinstance(error, ContractError) and error.code == "TARGET_MISMATCH":
            raise
        raise ContractError("AUTHORIZATION_REQUIRED") from error
