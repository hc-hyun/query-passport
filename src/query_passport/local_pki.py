"""Local-synthetic issuer; private material stays inside this process and its files.

This module owns only authorities it created itself. It is not a production PKI
adapter. Public commands must call it through the authorized executor boundary;
its stdin protocol is internal and accepts paths, never keys or certificates.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import signal
import stat
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OWNER = "query-passport-local-pki-v1"
MAX_INPUT_BYTES = 8192
MAX_FILE_BYTES = 65536
ERROR_CODES = frozenset(
    {
        "PKI_INVALID_INPUT",
        "PKI_ACCESS_DENIED",
        "PKI_PARTIAL_STATE",
        "PKI_INPUT_CONFLICT",
        "PKI_VALIDATION_FAILED",
        "PKI_EXPIRED",
        "PKI_OPERATION_FAILED",
        "PKI_TIMEOUT",
        "INTERNAL_ERROR",
    }
)
PEM_CERTIFICATES = re.compile(
    rb"(?:\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----\s*)+"
)
AUTHORITY_FIELDS = {
    "owner",
    "version",
    "authority_id",
    "certificate_sha256",
    "not_before",
    "not_after",
}
OPERATION_FIELDS = {
    "owner",
    "version",
    "operation_id",
    "input_digest",
    "spec_digest",
    "common_name",
    "lifetime_days",
    "authority_sha256",
    "server_ca_sha256",
    "certificate_sha256",
    "not_before",
    "not_after",
}


class PkiError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code if code in ERROR_CODES else "INTERNAL_ERROR"
        super().__init__(self.code)


class Result(TypedDict):
    status: str
    metadata: dict[str, Any]
    error: str | None


def _require(condition: bool, code: str = "PKI_VALIDATION_FAILED") -> None:
    if not condition:
        raise PkiError(code)


def _name(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value) is not None
        and len(value) <= 63
    )


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _parse(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result, "PKI_INVALID_INPUT")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise PkiError("PKI_INVALID_INPUT")

    _require(len(raw) <= MAX_INPUT_BYTES, "PKI_INVALID_INPUT")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError):
        raise PkiError("PKI_INVALID_INPUT") from None
    _require(type(result) is dict, "PKI_INVALID_INPUT")
    return dict(result)


def _path(value: Path | str) -> Path:
    _require(isinstance(value, (Path, str)), "PKI_INVALID_INPUT")
    path = Path(value)
    _require(
        path.is_absolute()
        and ".." not in path.parts
        and len(str(path)) <= 4096
        and all(ord(char) >= 32 and ord(char) != 127 for char in str(path)),
        "PKI_INVALID_INPUT",
    )
    return path


def _directory_info(descriptor: int, *, private: bool = False) -> None:
    info = os.fstat(descriptor)
    mode = stat.S_IMODE(info.st_mode)
    _require(stat.S_ISDIR(info.st_mode), "PKI_ACCESS_DENIED")
    if private:
        _require(info.st_uid == os.geteuid() and mode == 0o700, "PKI_ACCESS_DENIED")
    else:
        # Root's sticky /tmp is safe for traversing caller-owned private children.
        root_sticky = info.st_uid == 0 and mode == 0o1777
        _require(
            info.st_uid in (0, os.geteuid()) and (not mode & 0o7022 or root_sticky),
            "PKI_ACCESS_DENIED",
        )
    try:
        os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise PkiError("PKI_ACCESS_DENIED")


@contextlib.contextmanager
def _directory(path: Path, *, private: bool = False) -> Iterator[int]:
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _directory_info(descriptor)
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            _directory_info(descriptor)
        if private:
            _directory_info(descriptor, private=True)
        yield descriptor
    finally:
        os.close(descriptor)


def _mkdir(parent: int, name: str) -> bool:
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        return False
    os.fsync(parent)
    return True


def _read(directory: int, name: str, *, private: bool = True) -> bytes:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
    )
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        _require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid in (0, os.geteuid())
            and info.st_size <= MAX_FILE_BYTES,
            "PKI_ACCESS_DENIED",
        )
        _require(mode == 0o600 if private else not mode & 0o7022, "PKI_ACCESS_DENIED")
        chunks = bytearray()
        while len(chunks) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_FILE_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        _require(len(chunks) <= MAX_FILE_BYTES, "PKI_ACCESS_DENIED")
        after = os.fstat(descriptor)
        _require(
            (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "PKI_INPUT_CONFLICT",
        )
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _write_exclusive(directory: int, name: str, data: bytes) -> None:
    """Publish a complete fsynced inode without replacing any previous pathname.

    On interruption the temporary name and/or published files remain as partial
    evidence. Only a staging hardlink from this successful write is unlinked.
    """
    temporary = ".pending-" + uuid.uuid4().hex
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, "PKI_OPERATION_FAILED")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    os.fsync(directory)
    os.unlink(temporary, dir_fd=directory)
    os.fsync(directory)


def _entries(directory: int, expected: set[str]) -> None:
    _require(set(os.listdir(directory)) == expected, "PKI_PARTIAL_STATE")


def _fingerprint(certificate: x509.Certificate) -> str:
    return "sha256:" + certificate.fingerprint(hashes.SHA256()).hex()


def _metadata(certificate: x509.Certificate) -> dict[str, str]:
    return {
        "certificate_sha256": _fingerprint(certificate),
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
    }


def _valid_now(certificate: x509.Certificate) -> None:
    _require(
        certificate.not_valid_before_utc <= _now() < certificate.not_valid_after_utc, "PKI_EXPIRED"
    )


def _certificates(raw: bytes) -> list[x509.Certificate]:
    _require(PEM_CERTIFICATES.fullmatch(raw) is not None)
    return x509.load_pem_x509_certificates(raw)


def _public_key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _key_matches(key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate) -> None:
    _require(
        _public_key_bytes(key)
        == certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def _private_key(raw: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(raw, password=None)
    _require(isinstance(key, ec.EllipticCurvePrivateKey))
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PkiError("PKI_VALIDATION_FAILED")
    _require(isinstance(key.curve, ec.SECP256R1))
    return key


def _key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _load_authority(
    directory: int, authority_id: str | None = None
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, dict[str, Any]]:
    # Establish tool ownership before reading any pre-existing CA key or cert.
    _entries(directory, {"authority.json", "ca.crt", "ca.key"})
    metadata = _parse(_read(directory, "authority.json"))
    _require(
        set(metadata) == AUTHORITY_FIELDS
        and metadata.get("owner") == OWNER
        and type(metadata.get("version")) is int
        and metadata["version"] == 1,
        "PKI_ACCESS_DENIED",
    )
    _require(_name(metadata["authority_id"]), "PKI_ACCESS_DENIED")
    if authority_id is not None:
        _require(metadata["authority_id"] == authority_id, "PKI_INPUT_CONFLICT")
    certificates = _certificates(_read(directory, "ca.crt"))
    _require(len(certificates) == 1)
    certificate = certificates[0]
    _require(
        certificate.subject
        == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, metadata["authority_id"])])
    )
    certificate.verify_directly_issued_by(certificate)
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    _require(
        constraints.critical and constraints.value == x509.BasicConstraints(ca=True, path_length=0)
    )
    _require(usage.critical and usage.value == _usage(ca=True))
    _require(
        certificate.not_valid_after_utc - certificate.not_valid_before_utc <= timedelta(days=365)
    )
    _require(all(metadata.get(key) == value for key, value in _metadata(certificate).items()))
    _valid_now(certificate)
    key = _private_key(_read(directory, "ca.key"))
    _key_matches(key, certificate)
    return key, certificate, metadata


def _initialize_authority(authority_dir: Path, authority_id: str) -> dict[str, Any]:
    authority_dir = _path(authority_dir)
    _require(_name(authority_id), "PKI_INVALID_INPUT")
    with _directory(authority_dir.parent) as parent:
        created = _mkdir(parent, authority_dir.name)
        with _directory(authority_dir, private=True) as directory:
            if not created:
                _, _, metadata = _load_authority(directory, authority_id)
                return {**metadata, "reused": True}
            _entries(directory, set())
            key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, authority_id)])
            start = _now() - timedelta(minutes=1)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(start)
                .not_valid_after(start + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(_usage(ca=True), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            metadata = {
                "owner": OWNER,
                "version": 1,
                "authority_id": authority_id,
                **_metadata(certificate),
            }
            _write_exclusive(directory, "ca.key", _key_bytes(key))
            _write_exclusive(
                directory, "ca.crt", certificate.public_bytes(serialization.Encoding.PEM)
            )
            _write_exclusive(directory, "authority.json", _json(metadata))
            _load_authority(directory, authority_id)
            return {**metadata, "reused": False}


def initialize_authority(authority_dir: Path, authority_id: str) -> dict[str, Any]:
    try:
        return _initialize_authority(authority_dir, authority_id)
    except PkiError:
        raise
    except OSError:
        raise PkiError("PKI_ACCESS_DENIED") from None
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        raise PkiError("PKI_VALIDATION_FAILED") from None
    except Exception:  # noqa: BLE001 - callable issuer boundary must redact unknown failures
        raise PkiError("INTERNAL_ERROR") from None


def _server_trust(path: Path) -> bytes:
    with _directory(path.parent) as directory:
        raw = _read(directory, path.name, private=False)
    certificates = _certificates(raw)
    _require(len(certificates) <= 8)
    for certificate in certificates:
        _valid_now(certificate)
        _require(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        try:
            _require(
                certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            )
        except x509.ExtensionNotFound:
            pass
        # Check signatures where the file supplies the issuer. An explicitly
        # provided intermediate trust anchor need not include its parent root.
        issuers = [
            candidate for candidate in certificates if candidate.subject == certificate.issuer
        ]
        if issuers:
            valid_signature = False
            for issuer in issuers:
                try:
                    certificate.verify_directly_issued_by(issuer)
                    valid_signature = True
                    break
                except (InvalidSignature, ValueError):
                    continue
            _require(valid_signature)
    return raw


def _validate_generation(
    directory: int, specification: dict[str, Any], authority: x509.Certificate, server_trust: bytes
) -> dict[str, Any]:
    _entries(directory, {"operation.json", "bundle"})
    metadata = _parse(_read(directory, "operation.json"))
    _require(
        set(metadata) == OPERATION_FIELDS
        and metadata.get("owner") == OWNER
        and type(metadata.get("version")) is int
        and metadata["version"] == 1,
        "PKI_ACCESS_DENIED",
    )
    _require(
        all(metadata.get(key) == value for key, value in specification.items()),
        "PKI_INPUT_CONFLICT",
    )
    bundle_fd = os.open(
        "bundle", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
    )
    try:
        _directory_info(bundle_fd, private=True)
        _entries(bundle_fd, {"ca.crt", "client.crt", "client.key"})
        _require(_read(bundle_fd, "ca.crt") == server_trust)
        certificates = _certificates(_read(bundle_fd, "client.crt"))
        _require(len(certificates) == 1)
        certificate = certificates[0]
        certificate.verify_directly_issued_by(authority)
        _require(
            certificate.subject
            == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, specification["common_name"])])
        )
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        _require(
            constraints.critical
            and constraints.value == x509.BasicConstraints(ca=False, path_length=None)
        )
        _require(usage.critical and usage.value == _usage(ca=False))
        _require(list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH])
        _require(
            authority.not_valid_before_utc <= certificate.not_valid_before_utc
            and certificate.not_valid_after_utc <= authority.not_valid_after_utc
            and certificate.not_valid_after_utc - certificate.not_valid_before_utc
            <= timedelta(days=specification["lifetime_days"])
        )
        _valid_now(certificate)
        _key_matches(_private_key(_read(bundle_fd, "client.key")), certificate)
        _require(all(metadata.get(key) == value for key, value in _metadata(certificate).items()))
    finally:
        os.close(bundle_fd)
    return metadata


def _issue_client(
    authority_dir: Path,
    generations_dir: Path,
    operation_id: str,
    input_digest: str,
    common_name: str,
    server_ca_file: Path,
    lifetime_days: int,
) -> dict[str, Any]:
    authority_dir, generations_dir, server_ca_file = map(
        _path, (authority_dir, generations_dir, server_ca_file)
    )
    _require(
        type(operation_id) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", operation_id) is not None,
        "PKI_INVALID_INPUT",
    )
    _require(
        type(input_digest) is str
        and re.fullmatch(r"sha256:[a-f0-9]{64}", input_digest) is not None,
        "PKI_INVALID_INPUT",
    )
    _require(
        _name(common_name) and type(lifetime_days) is int and 1 <= lifetime_days <= 90,
        "PKI_INVALID_INPUT",
    )
    _require(
        authority_dir != generations_dir
        and authority_dir not in generations_dir.parents
        and generations_dir not in authority_dir.parents,
        "PKI_ACCESS_DENIED",
    )
    server_trust = _server_trust(server_ca_file)
    with _directory(authority_dir, private=True) as authority_fd:
        issuer_key, authority, _ = _load_authority(authority_fd)
        specification: dict[str, Any] = {
            "operation_id": operation_id,
            "input_digest": input_digest,
            "common_name": common_name,
            "lifetime_days": lifetime_days,
            "authority_sha256": _fingerprint(authority),
            "server_ca_sha256": _digest(server_trust),
        }
        specification["spec_digest"] = _digest(
            _json(
                {
                    **specification,
                    "authority_dir": str(authority_dir),
                    "generations_dir": str(generations_dir),
                    "server_ca_file": str(server_ca_file),
                }
            )
        )
        with _directory(generations_dir.parent) as parent:
            _mkdir(parent, generations_dir.name)
        with _directory(generations_dir, private=True) as generations:
            created = _mkdir(generations, operation_id)
            operation_fd = os.open(
                operation_id,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=generations,
            )
            try:
                _directory_info(operation_fd, private=True)
                if not created:
                    metadata = _validate_generation(
                        operation_fd, specification, authority, server_trust
                    )
                    return {**metadata, "reused": True}
                _entries(operation_fd, set())
                key = ec.generate_private_key(ec.SECP256R1())
                start = max(_now() - timedelta(minutes=1), authority.not_valid_before_utc)
                end = min(start + timedelta(days=lifetime_days), authority.not_valid_after_utc)
                _require(end > _now(), "PKI_EXPIRED")
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                    .issuer_name(authority.subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(start)
                    .not_valid_after(end)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(_usage(ca=False), critical=True)
                    .add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
                    )
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                    )
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False,
                    )
                    .sign(issuer_key, hashes.SHA256())
                )
                _mkdir(operation_fd, "bundle")
                bundle_fd = os.open(
                    "bundle",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=operation_fd,
                )
                try:
                    _write_exclusive(bundle_fd, "client.key", _key_bytes(key))
                    _write_exclusive(
                        bundle_fd,
                        "client.crt",
                        certificate.public_bytes(serialization.Encoding.PEM),
                    )
                    _write_exclusive(bundle_fd, "ca.crt", server_trust)
                finally:
                    os.close(bundle_fd)
                metadata = {"owner": OWNER, "version": 1, **specification, **_metadata(certificate)}
                _write_exclusive(operation_fd, "operation.json", _json(metadata))
                _validate_generation(operation_fd, specification, authority, server_trust)
                return {**metadata, "reused": False}
            finally:
                os.close(operation_fd)


def issue_client(
    authority_dir: Path,
    generations_dir: Path,
    operation_id: str,
    input_digest: str,
    common_name: str,
    server_ca_file: Path,
    lifetime_days: int = 30,
) -> dict[str, Any]:
    try:
        return _issue_client(
            authority_dir,
            generations_dir,
            operation_id,
            input_digest,
            common_name,
            server_ca_file,
            lifetime_days,
        )
    except PkiError:
        raise
    except FileNotFoundError:
        raise PkiError("PKI_PARTIAL_STATE") from None
    except OSError:
        raise PkiError("PKI_ACCESS_DENIED") from None
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        raise PkiError("PKI_VALIDATION_FAILED") from None
    except Exception:  # noqa: BLE001 - callable issuer boundary must redact unknown failures
        raise PkiError("INTERNAL_ERROR") from None


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    _require(type(request) is dict, "PKI_INVALID_INPUT")
    command = request.get("command")
    if command == "initialize-authority":
        _require(set(request) == {"command", "authority_dir", "authority_id"}, "PKI_INVALID_INPUT")
        return initialize_authority(request["authority_dir"], request["authority_id"])
    if command == "issue-client":
        _require(
            set(request)
            == {
                "command",
                "authority_dir",
                "generations_dir",
                "operation_id",
                "input_digest",
                "common_name",
                "server_ca_file",
                "lifetime_days",
            },
            "PKI_INVALID_INPUT",
        )
        return issue_client(**{key: value for key, value in request.items() if key != "command"})
    raise PkiError("PKI_INVALID_INPUT")


def _alarm(_signum: int, _frame: object) -> None:
    raise PkiError("PKI_TIMEOUT")


def main() -> int:
    try:
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), 2)
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(15)
        result: Result = {
            "status": "succeeded",
            "metadata": dispatch(_parse(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))),
            "error": None,
        }
    except PkiError as error:
        result = {"status": "failed", "metadata": {}, "error": error.code}
    except BaseException:  # noqa: BLE001 - final subprocess redaction boundary
        result = {"status": "failed", "metadata": {}, "error": "INTERNAL_ERROR"}
    finally:
        signal.alarm(0)
    try:
        os.write(sys.stdout.fileno(), _json(result) + b"\n")
    except (OSError, ValueError, AttributeError):
        return 1
    return 0 if result["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
