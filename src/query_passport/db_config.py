"""Pure, bounded HBA/ident changes for a single managed authentication owner.

No files, database connections, roles, grants, or reloads are performed here.
The executor must lock the target, verify its identity, compare the observed
digest immediately before writing, and validate PostgreSQL's loaded rules. A
new role must remain NOLOGIN until those rules are loaded. These helpers do not
establish those facts.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from .contract import ContractError

_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_ALIAS = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
_MARKER = re.compile(rf"# query-passport:({_ALIAS}):(begin|end)")
_MAX_CONFIG_BYTES = 1024 * 1024


def _require(condition: bool, code: str = "INVALID_INPUT") -> None:
    if not condition:
        raise ContractError(code)


def _name(value: str, pattern: str = _IDENTIFIER) -> None:
    _require(type(value) is str and len(value) <= 63 and re.fullmatch(pattern, value) is not None)


def _text(value: str) -> None:
    _require(type(value) is str and "\x00" not in value)
    try:
        _require(len(value.encode("utf-8")) <= _MAX_CONFIG_BYTES)
    except UnicodeError as error:
        raise ContractError() from error


def config_digest(content: str) -> str:
    """Digest exact UTF-8 bytes, retaining newlines and the final-newline state."""
    _text(content)
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def build_auth_rules(
    database: str, username: str, expected_dn: str, network_cidr: str, map_name: str
) -> tuple[str, str]:
    """Build exact-DN cert authentication and deny other DB/transport fallbacks.

    The caller must separately ensure NOSUPERUSER/NOREPLICATION and the intended
    role ownership/privileges. PostgreSQL's ``all`` database token does not match
    physical replication connections. No grant or source admission is implied.
    """
    for identifier in (database, username, map_name):
        _name(identifier)
    _require(type(expected_dn) is str and expected_dn.startswith("CN="))
    _name(expected_dn[3:], _ALIAS)
    _require(
        type(network_cidr) is str
        and len(network_cidr) <= 64
        and re.fullmatch(r"[0-9a-f.:]+/[0-9]+", network_cidr) is not None
    )
    try:
        network = ipaddress.ip_network(network_cidr, strict=True)
    except ValueError as error:
        raise ContractError() from error
    _require(str(network) == network_cidr)
    # Quoting preserves literal identifiers such as a database or role named
    # "all" or "replication" instead of activating HBA's special tokens.
    hba = (
        f'hostssl "{database}" "{username}" {network_cidr} cert clientname=DN map={map_name}\n'
        f'host all "{username}" all reject\n'
        f'local all "{username}" reject\n'
    )
    ident = f'{map_name} "{expected_dn}" "{username}"\n'
    return hba, ident


def _body(body: str) -> str:
    """Accept only rules emitted by build_auth_rules, allowing CRLF input."""
    _text(body)
    normalized = body.replace("\r\n", "\n")
    _require("\r" not in normalized)
    if not normalized.endswith("\n"):
        normalized += "\n"
    hba = re.fullmatch(
        rf'hostssl "({_IDENTIFIER})" "({_IDENTIFIER})" ([^ \n]+) '
        rf"cert clientname=DN map=({_IDENTIFIER})\n"
        r'host all "\2" all reject\nlocal all "\2" reject\n',
        normalized,
    )
    if hba is not None:
        database, username, cidr, map_name = hba.groups()
        expected, _ = build_auth_rules(database, username, "CN=passport", cidr, map_name)
        _require(expected == normalized)
        return normalized
    ident = re.fullmatch(rf'({_IDENTIFIER}) "(CN={_ALIAS})" "({_IDENTIFIER})"\n', normalized)
    _require(ident is not None)
    assert ident is not None
    map_name, dn, username = ident.groups()
    _, expected = build_auth_rules("passport", username, dn, "127.0.0.1/32", map_name)
    _require(expected == normalized)
    return normalized


@dataclass(frozen=True)
class _Block:
    start: int
    end: int
    text: str


def _blocks(content: str) -> dict[str, _Block]:
    _text(content)
    result: dict[str, _Block] = {}
    active: tuple[str, int] | None = None
    offset = 0
    previous_line = ""
    for segment in content.split("\n"):
        end = offset + len(segment)
        if end < len(content):
            end += 1
        line = segment.removesuffix("\r")
        if "query-passport:" in line.lower():
            match = _MARKER.fullmatch(line)
            _require(match is not None)
            assert match is not None
            owner, kind = match.groups()
            _name(owner, _ALIAS)
            _require(not previous_line.endswith("\\"))
            if kind == "begin":
                _require(active is None and owner not in result)
                active = (owner, offset)
            else:
                _require(active is not None and active[0] == owner)
                assert active is not None
                start = active[1]
                result[owner] = _Block(start, end, content[start:end])
                active = None
        previous_line = line
        offset = end
    _require(active is None)
    return result


def owned_block(content: str, owner: str) -> str | None:
    """Return exact managed bytes as text, rejecting ambiguous markers globally."""
    _name(owner, _ALIAS)
    block = _blocks(content).get(owner)
    return None if block is None else block.text


def propose_config(
    original: str,
    owner: str,
    body: str,
    *,
    expected_before_digest: str | None = None,
) -> str:
    """Prepend a new block or replace the first block after an exact digest check.

    Save ``owned_block(original, owner)`` and ``owned_block(proposed, owner)`` for
    inspection. A replacement requires an observed full-file digest. Supplying the
    digest for insertion also rejects all drift. This is a proposal, not an
    atomic file write: the executor must repeat its CAS under the target lock.
    """
    _name(owner, _ALIAS)
    normalized = _body(body)
    blocks = _blocks(original)
    previous = blocks.get(owner)
    if expected_before_digest is not None:
        _require(expected_before_digest == config_digest(original), "TARGET_DRIFT")
    if previous is not None:
        _require(expected_before_digest is not None and previous.start == 0, "TARGET_DRIFT")
    # New blocks use the first line's newline style; unowned bytes are never
    # normalized, including mixed newlines and a missing final newline.
    first_newline = original.find("\n")
    newline = "\r\n" if first_newline > 0 and original[first_newline - 1] == "\r" else "\n"
    block = (
        f"# query-passport:{owner}:begin{newline}"
        + normalized.replace("\n", newline)
        + f"# query-passport:{owner}:end{newline}"
    )
    proposed = block + (original if previous is None else original[previous.end :])
    _text(proposed)
    return proposed
