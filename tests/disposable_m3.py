"""Fresh, opt-in PostgreSQL target with writable authentication files for M3.

All PKI material is generated under a new private /var/tmp directory. Only this
fixture's labeled containers/network and its pinned directory are cleaned up.
The database starts with a separate existing identity; Passport has no role yet.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from disposable import (
    OWNER_LABEL,
    ROOT,
    FixtureFailure,
    _certificate,
    _key,
    _key_bytes,
    _private_file,
)

from query_passport.contract import ContractError
from query_passport.executor import docker as executor_docker

PGDATA = "/var/lib/postgresql/data"
SOCKET_DIRECTORY = "/var/run/postgresql"
DATABASE = "query_man"
EXISTING_USER = "fixture_existing"
EXISTING_DN = "CN=fixture-existing"


def docker(args: list[str], *, stdin: bytes | None = None, timeout: float = 25) -> bytes:
    """Bound stdout and time; never expose original Docker or PostgreSQL errors."""
    try:
        return executor_docker(args, stdin=stdin, timeout=timeout, limit=8192)
    except ContractError:
        raise FixtureFailure("Disposable M3 Docker operation failed") from None


@dataclass
class M3Database:
    base_directory: Path
    owner: str
    database_image: str
    runtime_image: str
    network_name: str
    container_name: str
    helper_name: str
    request: dict[str, Any] = field(default_factory=dict)
    binding: dict[str, Any] = field(default_factory=dict)
    admin: dict[str, Any] = field(default_factory=dict)
    initial_digests: dict[str, str] = field(default_factory=dict)
    postgres_uid: int = 0
    postgres_gid: int = 0
    network_created: bool = False
    container_created: bool = False
    helper_created: bool = False
    directory_identity: tuple[int, int] = (0, 0)
    closed: bool = False

    @property
    def server_ca_file(self) -> Path:
        return self.base_directory / "server-ca.crt"

    @property
    def authority_dir(self) -> Path:
        return self.base_directory / "passport-authority"

    @property
    def generations_dir(self) -> Path:
        return self.base_directory / "passport-generations"

    @property
    def credential_dir(self) -> Path:
        return self.base_directory / "runtime" / "example-db"

    @property
    def existing_credential_dir(self) -> Path:
        return self.base_directory / "existing-credential"

    @classmethod
    def create(cls) -> M3Database:
        image_ids = (
            docker(
                [
                    "image",
                    "inspect",
                    "postgres:18.6-bookworm",
                    "query-man:local",
                    "--format",
                    "{{.Id}}",
                ]
            )
            .decode("ascii")
            .splitlines()
        )
        if len(image_ids) != 2 or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in image_ids
        ):
            raise FixtureFailure("Pinned disposable M3 images unavailable")
        owner = uuid.uuid4().hex
        directory = Path(
            tempfile.mkdtemp(prefix="query-passport-m3-" + owner + "-", dir="/var/tmp")
        )
        info = directory.stat()
        fixture = cls(
            base_directory=directory,
            owner=owner,
            database_image=image_ids[0],
            runtime_image=image_ids[1],
            network_name="query-passport-m3-net-" + owner,
            container_name="query-passport-m3-db-" + owner,
            helper_name="query-passport-m3-files-" + owner,
            directory_identity=(info.st_dev, info.st_ino),
        )
        _private_file(directory / "fixture-owner", owner.encode("ascii"))
        try:
            fixture._start()
        except BaseException:
            fixture.close()
            raise
        return fixture

    def _start(self) -> None:
        # No image pulls, discovered credentials, published ports or host PGDATA.
        self.network_created = True
        network_id = (
            docker(
                [
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    OWNER_LABEL + "=" + self.owner,
                    self.network_name,
                ]
            )
            .decode("ascii")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", network_id) is None:
            raise FixtureFailure("Disposable M3 network identity invalid")
        network_settings = json.loads(
            docker(["network", "inspect", "--format", "{{json .IPAM.Config}}", network_id])
        )
        subnet = str(ipaddress.ip_network(network_settings[0]["Subnet"], strict=True))
        if ipaddress.ip_network(subnet).version != 4:
            raise FixtureFailure("Disposable M3 network must be IPv4")
        self.helper_created = True
        postgres_ids = (
            docker(
                [
                    "run",
                    "--rm",
                    "--pull=never",
                    "--name",
                    self.helper_name,
                    "--label",
                    OWNER_LABEL + "=" + self.owner,
                    "--network",
                    "none",
                    "--log-driver",
                    "none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--entrypoint",
                    "id",
                    self.database_image,
                    "postgres",
                ]
            )
            .decode("ascii")
            .strip()
        )
        self.helper_created = False
        match = re.fullmatch(r"uid=(\d+)\(postgres\) gid=(\d+)\(postgres\) groups=.*", postgres_ids)
        if match is None or int(match[1]) == 0 or int(match[2]) == 0:
            raise FixtureFailure("Disposable M3 PostgreSQL identity unavailable")
        self.postgres_uid, self.postgres_gid = int(match[1]), int(match[2])
        self._pki(subnet)
        self._ownership(f"{self.postgres_uid}:{self.postgres_gid}", "/fixture/server")
        self._ownership("0:10001", "/fixture/existing-credential")
        script = (
            "set -eu; "
            "initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=reject "
            "--username=postgres --encoding=UTF8 --no-locale --no-sync >/dev/null 2>&1; "
            "cp /fixture-server/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf; "
            "cp /fixture-server/pg_ident.conf /var/lib/postgresql/data/pg_ident.conf; "
            "cp /fixture-server/postgresql.auto.conf /var/lib/postgresql/data/postgresql.auto.conf; "
            "cp /fixture-server/server.crt /var/lib/postgresql/data/server.crt; "
            "cp /fixture-server/server.key /var/lib/postgresql/data/server.key; "
            "cp /fixture-server/client-ca.crt /var/lib/postgresql/data/client-ca.crt; "
            "chmod 600 /var/lib/postgresql/data/server.key; "
            "exec postgres -D /var/lib/postgresql/data"
        )
        ownership = f"{self.postgres_uid}:{self.postgres_gid}"
        tmpfs_owner = f",uid={self.postgres_uid},gid={self.postgres_gid}"
        self.container_created = True
        container_id = (
            docker(
                [
                    "run",
                    "--detach",
                    "--pull=never",
                    "--name",
                    self.container_name,
                    "--label",
                    OWNER_LABEL + "=" + self.owner,
                    "--network",
                    network_id,
                    "--network-alias",
                    "db.example.test",
                    "--log-driver",
                    "none",
                    "--user",
                    ownership,
                    "--security-opt=no-new-privileges",
                    "--cap-drop=ALL",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "256m",
                    "--tmpfs",
                    PGDATA + ":rw,size=128m,mode=0700" + tmpfs_owner,
                    "--tmpfs",
                    SOCKET_DIRECTORY + ":rw,size=1m,mode=0700" + tmpfs_owner,
                    "--mount",
                    "type=bind,src="
                    + str(self.base_directory / "server")
                    + ",dst=/fixture-server,readonly",
                    "--entrypoint",
                    "/bin/sh",
                    self.database_image,
                    "-c",
                    script,
                ]
            )
            .decode("ascii")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            raise FixtureFailure("Disposable M3 container identity invalid")
        deadline = time.monotonic() + 30
        while True:
            try:
                if self.sql("SELECT 1").strip() == b"1":
                    break
            except FixtureFailure:
                pass
            if time.monotonic() >= deadline:
                raise FixtureFailure("Disposable M3 PostgreSQL startup timed out")
            time.sleep(0.1)
        self.sql(
            "CREATE DATABASE query_man; "
            "CREATE ROLE fixture_existing LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2; "
            "REVOKE ALL ON DATABASE query_man FROM PUBLIC; "
            "GRANT CONNECT ON DATABASE query_man TO fixture_existing; "
            "ALTER ROLE fixture_existing IN DATABASE query_man SET default_transaction_read_only=on; "
            "ALTER ROLE fixture_existing IN DATABASE query_man SET statement_timeout='2s'; "
            "ALTER ROLE fixture_existing IN DATABASE query_man SET search_path=pg_catalog;"
        )
        self.sql("REVOKE ALL ON SCHEMA public FROM PUBLIC", database=DATABASE)
        address_template = (
            '{"hostaddr":{{json (index .NetworkSettings.Networks "'
            + self.network_name
            + '").IPAddress}},"started_at":{{json .State.StartedAt}}}'
        )
        observed = json.loads(
            docker(["inspect", "--type", "container", "--format", address_template, container_id])
        )
        request = json.loads((ROOT / "examples/request.json").read_bytes())
        request.update(
            {
                "target_alias": "fixture-m3-" + self.owner,
                "deployment_alias": "fixture-m3-runtime-" + self.owner,
            }
        )
        self.request = request
        self.admin = {
            "uid": self.postgres_uid,
            "gid": self.postgres_gid,
            "socket_directory": SOCKET_DIRECTORY,
            "pgdata": PGDATA,
            "network_cidr": subnet,
            "connection_limit": 2,
        }
        self.binding = {
            "binding_version": 1,
            "allowed_uid": os.geteuid(),
            "expires_at": int(time.time()) + 3600,
            "operations": ["verify"],
            "request": copy.deepcopy(request),
            "container_id": container_id,
            "container_started_at": observed["started_at"],
            "database_image_id": self.database_image,
            "network_name": self.network_name,
            "network_id": network_id,
            "hostaddr": observed["hostaddr"],
            "runtime_image_id": self.runtime_image,
            "runtime_uid": 10001,
            "runtime_gid": 10001,
            "username": "passport_check",
            "expected_dn": "CN=query-passport-test",
            "credential_dir": str(self.credential_dir),
            "admin": copy.deepcopy(self.admin),
        }

    def _pki(self, subnet: str) -> None:
        # Keys and certificate bytes remain in this test boundary, never output.
        authority_directory = self.base_directory / "fixture-authority"
        authority_directory.mkdir(mode=0o700)
        server_key = _key()
        server_ca = _certificate(server_key, "fixture-m3-server-ca")
        client_key = _key()
        client_ca = _certificate(client_key, "fixture-m3-existing-client-ca")
        for name, key, certificate in (
            ("server", server_key, server_ca),
            ("existing-client", client_key, client_ca),
        ):
            _private_file(authority_directory / (name + ".key"), _key_bytes(key))
            _private_file(
                authority_directory / (name + ".crt"),
                certificate.public_bytes(serialization.Encoding.PEM),
            )
        _private_file(self.server_ca_file, server_ca.public_bytes(serialization.Encoding.PEM))
        server_directory = self.base_directory / "server"
        server_directory.mkdir(mode=0o755)
        key = _key()
        certificate = _certificate(
            key, "db.example.test", issuer=(server_key, server_ca), server=True
        )
        _private_file(server_directory / "server.key", _key_bytes(key))
        for name, cert in (("server.crt", certificate), ("client-ca.crt", client_ca)):
            raw = cert.public_bytes(serialization.Encoding.PEM)
            _private_file(server_directory / name, raw, 0o644)
            self.initial_digests[name] = "sha256:" + hashlib.sha256(raw).hexdigest()
        configuration = {
            "pg_hba.conf": (
                "# Existing fixture authentication; preserve this byte-for-byte.\n"
                "local all postgres trust\n"
                "local all all reject\n"
                "hostssl query_man fixture_existing " + subnet + " cert "
                "clientname=DN map=fixture_existing\n"
                "host all all 0.0.0.0/0 reject\n"
                "host all all ::/0 reject\n"
            ),
            "pg_ident.conf": (
                "# Existing fixture mapping; preserve this byte-for-byte.\n"
                'fixture_existing "CN=fixture-existing" fixture_existing\n'
            ),
            "postgresql.auto.conf": (
                "# Existing fixture server settings; preserve unrelated values.\n"
                "listen_addresses = '*'\n"
                "ssl = on\n"
                "ssl_cert_file = 'server.crt'\n"
                "ssl_key_file = 'server.key'\n"
                "ssl_ca_file = 'client-ca.crt'\n"
                "ssl_min_protocol_version = 'TLSv1.2'\n"
                "unix_socket_directories = '/var/run/postgresql'\n"
                "max_connections = 12\n"
                "shared_buffers = '16MB'\n"
                "log_statement = 'none'\n"
            ),
        }
        for name, content in configuration.items():
            raw = content.encode()
            _private_file(server_directory / name, raw, 0o600)
            self.initial_digests[name] = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.existing_credential_dir.mkdir(mode=0o755)
        existing_key = _key()
        existing_certificate = _certificate(
            existing_key, "fixture-existing", issuer=(client_key, client_ca)
        )
        _private_file(
            self.existing_credential_dir / "ca.crt",
            server_ca.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        _private_file(
            self.existing_credential_dir / "client.crt",
            existing_certificate.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        _private_file(self.existing_credential_dir / "client.key", _key_bytes(existing_key), 0o640)
        (self.base_directory / "runtime").mkdir(mode=0o700)

    def _ownership(self, ownership: str, path: str) -> None:
        self.helper_created = True
        docker(
            [
                "run",
                "--rm",
                "--pull=never",
                "--name",
                self.helper_name,
                "--label",
                OWNER_LABEL + "=" + self.owner,
                "--network",
                "none",
                "--log-driver",
                "none",
                "--user",
                "0:0",
                "--cap-drop=ALL",
                "--cap-add=CHOWN",
                "--cap-add=DAC_READ_SEARCH",
                "--security-opt=no-new-privileges",
                "--read-only",
                "--mount",
                "type=bind,src=" + str(self.base_directory) + ",dst=/fixture",
                "--entrypoint",
                "chown",
                self.database_image,
                "-R",
                ownership,
                path,
            ]
        )
        self.helper_created = False

    def sql(self, statement: str, *, database: str = "postgres") -> bytes:
        """Fixture-only setup/catalog SQL on the newly owned admin socket."""
        if database not in ("postgres", DATABASE):
            raise FixtureFailure("Disposable M3 database selection invalid")
        return docker(
            [
                "exec",
                "-i",
                "--user",
                f"{self.postgres_uid}:{self.postgres_gid}",
                self.container_name,
                "/usr/bin/env",
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "LANG=C.UTF-8",
                "psql",
                "-X",
                "-qAt",
                "--no-password",
                "-h",
                SOCKET_DIRECTORY,
                "-U",
                "postgres",
                "-d",
                database,
                "-v",
                "ON_ERROR_STOP=1",
            ],
            stdin=statement.encode(),
            timeout=5,
        )

    def existing_binding(self) -> dict[str, Any]:
        """M2-compatible verification binding for the unrelated initial identity."""
        binding = copy.deepcopy(self.binding)
        binding.pop("admin")
        binding["operations"] = ["verify"]
        binding["username"] = EXISTING_USER
        binding["expected_dn"] = EXISTING_DN
        binding["credential_dir"] = str(self.existing_credential_dir)
        return binding

    def snapshot(self) -> dict[str, Any]:
        """Sanitized fixture preconditions only; no credential/config contents."""
        return json.loads(
            self.sql(
                "SELECT json_build_object("
                "'version', current_setting('server_version_num')::int, "
                "'encoding', current_setting('server_encoding'), "
                "'ssl', current_setting('ssl'), "
                "'pgdata', current_setting('data_directory'), "
                "'hba_file', current_setting('hba_file'), "
                "'ident_file', current_setting('ident_file'), "
                "'ssl_ca_file', current_setting('ssl_ca_file'), "
                "'command_line_auth_settings', (SELECT count(*) FROM pg_settings WHERE "
                "name IN ('hba_file','ident_file','ssl_ca_file') AND source='command line'), "
                "'passport_roles', (SELECT count(*) FROM pg_roles WHERE rolname='passport_check'), "
                "'existing_roles', (SELECT count(*) FROM pg_roles WHERE rolname='fixture_existing' "
                "AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole "
                "AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls), "
                "'public_database_grants', (SELECT count(*) FROM pg_database d, "
                "LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a "
                "WHERE d.datname=current_database() AND a.grantee=0), "
                "'public_schema_grants', (SELECT count(*) FROM pg_namespace n, "
                "LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a "
                "WHERE n.nspname='public' AND a.grantee=0), "
                "'business_relations', (SELECT count(*) FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='public'), "
                "'hba_errors', (SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL), "
                "'ident_errors', (SELECT count(*) FROM pg_ident_file_mappings WHERE error IS NOT NULL))",
                database=DATABASE,
            )
        )

    def _remove_resource(self, kind: str, name: str) -> None:
        template = '{{index .Labels "' + OWNER_LABEL + '"}}'
        if kind == "container":
            template = '{{index .Config.Labels "' + OWNER_LABEL + '"}}'
        # A timed-out --rm helper may already have gone; prove absence by its
        # exact UUID name without inspecting any unrelated container fields.
        if kind == "container":
            present = docker(["ps", "-aq", "--filter", "name=^/" + name + "$"]).strip()
            if not present:
                return
        else:
            names = (
                docker(["network", "ls", "--filter", "name=" + name, "--format", "{{.Name}}"])
                .decode("ascii")
                .splitlines()
            )
            if name not in names:
                return
        owner = docker([kind, "inspect", "--format", template, name]).decode("ascii").strip()
        if owner != self.owner:
            raise FixtureFailure("Disposable M3 cleanup ownership mismatch")
        docker([kind, "rm", *(["-f"] if kind == "container" else []), name])

    def close(self) -> None:
        if self.closed:
            return
        failures = False
        for created, kind, name in (
            (self.helper_created, "container", self.helper_name),
            (self.container_created, "container", self.container_name),
            (self.network_created, "network", self.network_name),
        ):
            if created:
                try:
                    self._remove_resource(kind, name)
                except FixtureFailure:
                    failures = True
        if failures:
            # Retain the owned private directory when resources are uncertain.
            raise FixtureFailure("Disposable M3 cleanup requires attention")
        try:
            info = self.base_directory.lstat()
            if (
                self.base_directory.is_symlink()
                or (info.st_dev, info.st_ino) != self.directory_identity
            ):
                raise FixtureFailure("Disposable M3 directory ownership mismatch")
            marker = os.open(
                self.base_directory / "fixture-owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            try:
                info = os.fstat(marker)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_size != 32
                    or os.read(marker, 33) != self.owner.encode("ascii")
                ):
                    raise FixtureFailure("Disposable M3 directory ownership mismatch")
            finally:
                os.close(marker)
            self._ownership(f"{os.geteuid()}:{os.getegid()}", "/fixture")
            shutil.rmtree(self.base_directory)
        except (FixtureFailure, OSError):
            failures = True
        if failures:
            raise FixtureFailure("Disposable M3 cleanup requires attention")
        self.closed = True
