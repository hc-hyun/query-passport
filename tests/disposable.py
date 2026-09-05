"""Owned, opt-in PostgreSQL fixture; private material never leaves its temp directory.

This helper creates fresh resources and never discovers or consumes existing DBs,
host credentials, environments, or Docker configuration. It inspects only the
selected image and owned container/network identity fields needed for binding.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
    "LANG": "C.UTF-8",
}
OWNER_LABEL = "io.query-passport.disposable-owner"
ROOT = Path(__file__).resolve().parents[1]


class FixtureFailure(RuntimeError):
    """Only the fixed operation phase is reported, never raw provider output."""


def docker(args: list[str], *, stdin: bytes | None = None, timeout: float = 25) -> bytes:
    try:
        result = subprocess.run(
            DOCKER + args,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=ENVIRONMENT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise FixtureFailure("Disposable Docker operation failed") from None
    if result.returncode or len(result.stdout) > 8192:
        raise FixtureFailure("Disposable Docker operation failed")
    return result.stdout


def _private_file(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _certificate(
    key: rsa.RSAPrivateKey,
    common_name: str,
    *,
    issuer: tuple[rsa.RSAPrivateKey, x509.Certificate] | None = None,
    server: bool = False,
    expired: bool = False,
) -> x509.Certificate:
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    authority_key = issuer[0] if issuer else key
    authority_name = issuer[1].subject if issuer else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(authority_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 2))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
    )
    if issuer:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("db.example.test")]), critical=False
        )
    return builder.sign(authority_key, hashes.SHA256())


def _key_bytes(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class DisposableDatabase:
    directory: Path
    owner: str
    database_image: str
    runtime_image: str
    network_name: str
    container_name: str
    request: dict[str, Any]
    binding: dict[str, Any]
    bundles: dict[str, Path]
    fault_evidence: dict[str, bool] = field(default_factory=dict)
    network_created: bool = False
    container_created: bool = False

    @classmethod
    def create(cls) -> DisposableDatabase:
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
            not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in image_ids
        ):
            raise FixtureFailure("Pinned disposable image unavailable")
        owner = uuid.uuid4().hex
        fixture = cls(
            directory=Path(tempfile.mkdtemp(prefix="query-passport-fixture-")),
            owner=owner,
            database_image=image_ids[0],
            runtime_image=image_ids[1],
            network_name="query-passport-test-" + owner,
            container_name="query-passport-db-" + owner,
            request={},
            binding={},
            bundles={},
        )
        try:
            fixture._start()
        except BaseException:
            fixture.close()
            raise
        return fixture

    def _start(self) -> None:
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
        subnet = json.loads(
            docker(["network", "inspect", "--format", "{{json .IPAM.Config}}", network_id])
        )[0]["Subnet"]
        if ipaddress.ip_network(subnet).version != 4:
            raise FixtureFailure("Disposable network must be IPv4")
        self._pki(subnet)
        postgres_ids = docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--log-driver",
                "none",
                "--entrypoint",
                "id",
                self.database_image,
                "postgres",
            ]
        ).decode("ascii")
        match = re.fullmatch(
            r"uid=(\d+)\(postgres\) gid=(\d+)\(postgres\) groups=.*\n", postgres_ids
        )
        if match is None:
            raise FixtureFailure("Disposable PostgreSQL UID unavailable")
        postgres_uid, postgres_gid = match.groups()
        self._ownership("0:10001", "/fixture/bundles")
        self._ownership(postgres_uid + ":" + postgres_gid, "/fixture/server")
        # initdb is restricted to this container's new tmpfs. Host access always
        # starts at reject; certificate rules are present before any LOGIN role.
        script = (
            "initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=reject "
            "--username=postgres --encoding=UTF8 --no-locale --no-sync >/dev/null 2>&1 "
            "&& exec postgres -D /var/lib/postgresql/data "
            "-c listen_addresses='*' -c ssl=on "
            "-c ssl_cert_file=/fixture-server/server.crt "
            "-c ssl_key_file=/fixture-server/server.key "
            "-c ssl_ca_file=/fixture-server/client-ca.crt "
            "-c hba_file=/fixture-server/pg_hba.conf "
            "-c ident_file=/fixture-server/pg_ident.conf "
            "-c unix_socket_directories=/tmp -c max_connections=12 "
            "-c shared_buffers=16MB -c log_statement=none "
            "-c ssl_min_protocol_version=TLSv1.2"
        )
        self.container_created = True
        container_id = (
            docker(
                [
                    "run",
                    "--detach",
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
                    postgres_uid + ":" + postgres_gid,
                    "--security-opt=no-new-privileges",
                    "--cap-drop=ALL",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "256m",
                    "--tmpfs",
                    "/var/lib/postgresql/data:rw,size=128m,mode=0700,uid="
                    + postgres_uid
                    + ",gid="
                    + postgres_gid,
                    "--mount",
                    "type=bind,src="
                    + str(self.directory / "server")
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
        deadline = time.monotonic() + 30
        while True:
            try:
                self.sql("SELECT 1")
                break
            except FixtureFailure:
                if time.monotonic() >= deadline:
                    raise FixtureFailure("Disposable PostgreSQL startup timed out") from None
                time.sleep(0.1)
        self.sql(
            "CREATE DATABASE query_man; "
            "CREATE ROLE passport_check NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2; "
            "REVOKE ALL ON DATABASE query_man FROM PUBLIC; "
            "GRANT CONNECT ON DATABASE query_man TO passport_check; "
            "ALTER ROLE passport_check IN DATABASE query_man SET default_transaction_read_only=on; "
            "ALTER ROLE passport_check IN DATABASE query_man SET statement_timeout='2s'; "
            "ALTER ROLE passport_check IN DATABASE query_man SET search_path=pg_catalog;"
        )
        if (
            self.sql("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL").strip()
            != b"0"
        ):
            raise FixtureFailure("Disposable authentication rules failed validation")
        self.sql("ALTER ROLE passport_check LOGIN")
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
                "target_alias": "fixture-" + self.owner,
                "deployment_alias": "fixture-runtime-" + self.owner,
            }
        )
        request["profile"]["host"] = "db.example.test"
        self.request = request
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
            "credential_dir": str(self.bundles["valid"]),
        }

    def _pki(self, subnet: str) -> None:
        authority_directory = self.directory / "authority"
        authority_directory.mkdir(mode=0o700)
        authority: dict[str, tuple[rsa.RSAPrivateKey, x509.Certificate]] = {}
        for name in ("server", "client", "untrusted"):
            key = _key()
            certificate = _certificate(key, "query-passport-" + name + "-ca")
            authority[name] = (key, certificate)
            _private_file(authority_directory / (name + ".key"), _key_bytes(key))
            _private_file(
                authority_directory / (name + ".crt"),
                certificate.public_bytes(serialization.Encoding.PEM),
            )
        server_directory = self.directory / "server"
        server_directory.mkdir(mode=0o755)
        server_key = _key()
        server_certificate = _certificate(
            server_key, "db.example.test", issuer=authority["server"], server=True
        )
        _private_file(server_directory / "server.key", _key_bytes(server_key))
        for name, certificate in (
            ("server.crt", server_certificate),
            ("client-ca.crt", authority["client"][1]),
        ):
            _private_file(
                server_directory / name, certificate.public_bytes(serialization.Encoding.PEM), 0o644
            )
        hba = (
            "local all postgres trust\n"
            "hostssl query_man passport_check " + subnet + " cert map=passport clientname=DN\n"
            "host all all 0.0.0.0/0 reject\n"
            "host all all ::/0 reject\n"
        )
        _private_file(server_directory / "pg_hba.conf", hba.encode(), 0o644)
        _private_file(
            server_directory / "pg_ident.conf",
            b'passport "CN=query-passport-test" passport_check\n',
            0o644,
        )
        bundles_root = self.directory / "bundles"
        bundles_root.mkdir(mode=0o755)
        for probe in (
            "valid",
            "wrong-server-ca",
            "wrong-client-ca",
            "wrong-dn",
            "wrong-key",
            "expired",
            "missing-certificate",
            "world-readable-key",
        ):
            directory = bundles_root / probe
            directory.mkdir(mode=0o755)
            key = _key()
            certificate = _certificate(
                key,
                "query-passport-unmapped" if probe == "wrong-dn" else "query-passport-test",
                issuer=authority["untrusted" if probe == "wrong-client-ca" else "client"],
                expired=probe == "expired",
            )
            # Validate each injected fault before serialization, using only this
            # fresh fixture's in-memory material. Negative connection results
            # must not accidentally be explained by a mismatched key or issuer.
            now = datetime.now(UTC)
            assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
            assert certificate.not_valid_before_utc < now
            if probe == "expired":
                assert certificate.not_valid_after_utc < now
                certificate.verify_directly_issued_by(authority["client"][1])
                assert certificate.subject == x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "query-passport-test")]
                )
                self.fault_evidence[probe] = True
            else:
                assert certificate.not_valid_after_utc > now
            if probe == "wrong-client-ca":
                certificate.verify_directly_issued_by(authority["untrusted"][1])
                assert certificate.issuer != authority["client"][1].subject
                try:
                    authority["client"][0].public_key().verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        certificate.signature_hash_algorithm,
                    )
                except InvalidSignature:
                    self.fault_evidence[probe] = True
                else:
                    raise FixtureFailure("Wrong-CA fixture unexpectedly has a trusted signature")
            ca = authority["untrusted" if probe == "wrong-server-ca" else "server"][1]
            _private_file(directory / "ca.crt", ca.public_bytes(serialization.Encoding.PEM), 0o644)
            if probe != "missing-certificate":
                _private_file(
                    directory / "client.crt",
                    certificate.public_bytes(serialization.Encoding.PEM),
                    0o644,
                )
            _private_file(
                directory / "client.key",
                _key_bytes(_key() if probe == "wrong-key" else key),
                0o644 if probe == "world-readable-key" else 0o640,
            )
            self.bundles[probe] = directory

    def _ownership(self, ownership: str, path: str) -> None:
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--log-driver",
                "none",
                "--user",
                "0:0",
                "--mount",
                "type=bind,src=" + str(self.directory) + ",dst=/fixture",
                "--entrypoint",
                "chown",
                self.database_image,
                "-R",
                ownership,
                path,
            ]
        )

    def sql(self, statement: str) -> bytes:
        # This fixture-only admin socket is inside the freshly created container.
        # Test code supplies only fixed setup/catalog statements and sees no rows.
        return docker(
            [
                "exec",
                "-i",
                self.container_name,
                "psql",
                "-X",
                "-qAt",
                "--no-password",
                "-h",
                "/tmp",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
            ],
            stdin=statement.encode(),
            timeout=5,
        )

    def for_probe(self, probe: str) -> tuple[dict[str, Any], dict[str, Any]]:
        request = copy.deepcopy(self.request)
        binding = copy.deepcopy(self.binding)
        if probe in self.bundles:
            binding["credential_dir"] = str(self.bundles[probe])
        elif probe == "wrong-hostname":
            request["profile"]["host"] = "unmatched.example.test"
        elif probe == "wrong-database":
            request["profile"]["database"] = "not_authorized"
        elif probe == "wrong-user":
            binding["username"] = "not_authorized"
        else:
            raise FixtureFailure("Unknown disposable probe")
        binding["request"] = copy.deepcopy(request)
        return binding, request

    def authentication_probe(self, probe: str) -> dict[str, str]:
        """Deliberate test-only missing-cert/plaintext attempt on the owned DB.

        The public executor cannot weaken TLS or omit credentials. These probes
        verify the server's refusal without adding a production downgrade option.
        """
        if probe not in ("missing-certificate", "plaintext"):
            raise FixtureFailure("Unknown disposable authentication probe")
        payload = {"probe": probe, "hostaddr": self.binding["hostaddr"]}
        worker_source = (ROOT / "src/query_passport/verify_worker.py").read_text()
        source = (
            "import sys, types\n"
            "module = types.ModuleType('query_passport_probe')\n"
            "sys.modules[module.__name__] = module\n"
            "namespace = module.__dict__\n"
            "exec(compile(" + repr(worker_source) + ", '<worker>', 'exec'), namespace)\n"
            "namespace['sanitize_environment']()\n"
            "import json, sys, psycopg\n"
            "payload = json.load(sys.stdin)\n"
            "parameters = dict(host='db.example.test', hostaddr=payload['hostaddr'], port=5432, "
            "dbname='query_man', user='passport_check', password='', "
            "passfile='/nonexistent/passfile', connect_timeout=2, gssencmode='disable', "
            "sslmode='verify-full', sslrootcert='/fixture-client/ca.crt', "
            "sslcert='/nonexistent/client.crt', sslkey='/nonexistent/client.key')\n"
            "if payload['probe'] == 'plaintext': parameters['sslmode'] = 'disable'\n"
            "try:\n"
            "    connection = psycopg.connect(**parameters)\n"
            "    connection.close()\n"
            "    result = {'outcome': 'unexpectedly_accepted', 'error': 'VERIFICATION_FAILED'}\n"
            "except Exception as error:\n"
            "    result = {'outcome': 'rejected', 'error': namespace['classify_error'](error)}\n"
            "print(json.dumps(result))\n"
        )
        return json.loads(
            docker(
                [
                    "run",
                    "--rm",
                    "--network",
                    self.binding["network_id"],
                    "--user",
                    "10001:10001",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--log-driver",
                    "none",
                    "--pids-limit",
                    "32",
                    "--memory",
                    "128m",
                    "--mount",
                    "type=bind,src=" + str(self.bundles["valid"]) + ",dst=/fixture-client,readonly",
                    "--entrypoint",
                    "/usr/bin/env",
                    "-i",
                    self.runtime_image,
                    "-i",
                    "PATH=/usr/bin:/bin",
                    "LANG=C.UTF-8",
                    "/app/.venv/bin/python",
                    "-I",
                    "-c",
                    source,
                ],
                stdin=json.dumps(payload).encode(),
                timeout=10,
            )
        )

    def close(self) -> None:
        failures = False
        # UUID names and owner labels are both checked before resource deletion.
        for created, kind, name in (
            (self.container_created, "container", self.container_name),
            (self.network_created, "network", self.network_name),
        ):
            if not created:
                continue
            template = '{{index .Labels "' + OWNER_LABEL + '"}}'
            if kind == "container":
                template = '{{index .Config.Labels "' + OWNER_LABEL + '"}}'
            try:
                owner = docker([kind, "inspect", "--format", template, name]).decode().strip()
                if owner != self.owner:
                    raise FixtureFailure("Disposable cleanup ownership mismatch")
                docker([kind, "rm", *(["-f"] if kind == "container" else []), name])
            except FixtureFailure:
                failures = True
        try:
            self._ownership(str(os.geteuid()) + ":" + str(os.getegid()), "/fixture")
            shutil.rmtree(self.directory)
        except (FixtureFailure, OSError):
            failures = True
        if failures:
            raise FixtureFailure("Disposable cleanup requires attention")
