"""Real cryptographic checks with newly generated, disposable external materials."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from query_passport import local_pki as pki


@pytest.fixture
def store() -> Iterator[Path]:
    # /tmp may itself contain repository sentinels in a shared development host.
    # A new private /var/tmp directory keeps all generated material external.
    with tempfile.TemporaryDirectory(
        prefix="query-passport-pki-test-", dir="/var/tmp"
    ) as temporary:
        path = Path(temporary)
        assert Path(__file__).resolve().parents[1] not in path.resolve().parents
        yield path


def make_server_ca(path: Path, *, ca: bool = True, expired: bool = False) -> x509.Certificate:
    """Generate this test's independent server trust; never reuse a host CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-server-ca")])
    now = datetime.now(UTC).replace(microsecond=0)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 730))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)
    return certificate


@pytest.fixture
def issuance(store: Path) -> dict[str, Any]:
    pki.initialize_authority(store / "authority", "fixture-client-ca")
    make_server_ca(store / "server-ca.crt")
    return {
        "authority_dir": store / "authority",
        "generations_dir": store / "generations",
        "operation_id": "0123456789abcdef0123456789abcdef",
        "input_digest": "sha256:" + "1" * 64,
        "common_name": "fixture-service",
        "server_ca_file": store / "server-ca.crt",
        "lifetime_days": 30,
    }


def bundle(issuance: dict[str, Any]) -> Path:
    return issuance["generations_dir"] / issuance["operation_id"] / "bundle"


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(path: Path) -> dict[str, tuple[int, int, str]]:
    return {
        str(child.relative_to(path)): (
            child.stat().st_ino,
            child.stat().st_mtime_ns,
            digest_file(child),
        )
        for child in path.rglob("*")
        if child.is_file()
    }


def test_initialize_authority_real_self_signature_and_private_storage(store: Path) -> None:
    metadata = pki.initialize_authority(store / "authority", "fixture-client-ca")
    directory = store / "authority"
    assert set(child.name for child in directory.iterdir()) == {
        "authority.json",
        "ca.crt",
        "ca.key",
    }
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(child.stat().st_mode) == 0o600 for child in directory.iterdir())
    certificate = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
    certificate.verify_directly_issued_by(certificate)
    key = serialization.load_pem_private_key((directory / "ca.key").read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.public_key().public_numbers() == certificate.public_key().public_numbers()
    assert certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value == x509.BasicConstraints(ca=True, path_length=0)
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert (
        metadata["certificate_sha256"] == "sha256:" + certificate.fingerprint(hashes.SHA256()).hex()
    )
    assert metadata["reused"] is False
    assert str(store) not in json.dumps(metadata)
    assert "BEGIN" not in json.dumps(metadata)


def test_authority_initialization_reuses_only_valid_complete_material(store: Path) -> None:
    first = pki.initialize_authority(store / "authority", "fixture-client-ca")
    before = snapshot(store)
    second = pki.initialize_authority(store / "authority", "fixture-client-ca")
    assert snapshot(store) == before
    assert first["certificate_sha256"] == second["certificate_sha256"]
    assert second["reused"] is True
    with pytest.raises(pki.PkiError, match="^PKI_INPUT_CONFLICT$"):
        pki.initialize_authority(store / "authority", "different-ca")
    assert snapshot(store) == before


def test_issue_real_client_certificate_and_keep_server_and_client_ca_distinct(
    issuance: dict[str, Any],
) -> None:
    metadata = pki.issue_client(**issuance)
    directory = bundle(issuance)
    assert set(path.name for path in directory.iterdir()) == {"ca.crt", "client.crt", "client.key"}
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir())
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o700
        for path in (directory, directory.parent, directory.parent.parent)
    )
    certificate = x509.load_pem_x509_certificate((directory / "client.crt").read_bytes())
    authority = x509.load_pem_x509_certificate((issuance["authority_dir"] / "ca.crt").read_bytes())
    certificate.verify_directly_issued_by(authority)
    key = serialization.load_pem_private_key((directory / "client.key").read_bytes(), None)
    assert key.public_key().public_numbers() == certificate.public_key().public_numbers()
    assert certificate.subject == x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuance["common_name"])]
    )
    assert list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.CLIENT_AUTH
    ]
    assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert certificate.not_valid_after_utc - certificate.not_valid_before_utc <= timedelta(days=30)
    assert certificate.not_valid_after_utc <= authority.not_valid_after_utc
    assert digest_file(directory / "ca.crt") == digest_file(issuance["server_ca_file"])
    assert digest_file(directory / "ca.crt") != digest_file(issuance["authority_dir"] / "ca.crt")
    assert digest_file(directory / "client.key") != digest_file(
        issuance["authority_dir"] / "ca.key"
    )
    assert metadata["reused"] is False
    assert str(directory) not in json.dumps(metadata)
    assert "BEGIN" not in json.dumps(metadata)


def test_identical_operation_reuses_original_key_and_certificate(issuance: dict[str, Any]) -> None:
    first = pki.issue_client(**issuance)
    before = snapshot(issuance["generations_dir"])
    second = pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before
    assert first["certificate_sha256"] == second["certificate_sha256"]
    assert second["reused"] is True


@pytest.mark.parametrize(
    "changes",
    [
        {"input_digest": "sha256:" + "2" * 64},
        {"common_name": "different-service"},
        {"lifetime_days": 60},
    ],
)
def test_same_operation_rejects_changed_input_without_overwrite(
    issuance: dict[str, Any], changes: dict[str, Any]
) -> None:
    pki.issue_client(**issuance)
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_INPUT_CONFLICT$"):
        pki.issue_client(**{**issuance, **changes})
    assert snapshot(issuance["generations_dir"]) == before


def test_replaced_server_ca_requires_new_operation(issuance: dict[str, Any]) -> None:
    pki.issue_client(**issuance)
    before = snapshot(issuance["generations_dir"])
    make_server_ca(issuance["server_ca_file"])
    with pytest.raises(pki.PkiError, match="^PKI_INPUT_CONFLICT$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


def test_new_operation_keeps_old_generation(issuance: dict[str, Any]) -> None:
    first = pki.issue_client(**issuance)
    before = snapshot(bundle(issuance))
    second = pki.issue_client(**{**issuance, "operation_id": "second-operation"})
    assert snapshot(bundle(issuance)) == before
    assert first["certificate_sha256"] != second["certificate_sha256"]


def test_leaf_lifetime_is_clamped_to_remaining_authority_validity(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = x509.load_pem_x509_certificate((issuance["authority_dir"] / "ca.crt").read_bytes())
    near_expiry = authority.not_valid_after_utc - timedelta(days=1)
    monkeypatch.setattr(pki, "_now", lambda: near_expiry)
    metadata = pki.issue_client(**{**issuance, "lifetime_days": 90})
    assert datetime.fromisoformat(metadata["not_after"]) == authority.not_valid_after_utc


def test_expired_authority_is_not_reissued_or_extended(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = x509.load_pem_x509_certificate((issuance["authority_dir"] / "ca.crt").read_bytes())
    monkeypatch.setattr(pki, "_now", lambda: authority.not_valid_after_utc + timedelta(seconds=1))
    before = snapshot(issuance["authority_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_EXPIRED$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["authority_dir"]) == before
    assert not issuance["generations_dir"].exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_id": "../escape"},
        {"operation_id": "."},
        {"operation_id": "nested/path"},
        {"input_digest": "secret-canary"},
        {"common_name": "CN=service"},
        {"common_name": "service/O=other"},
        {"common_name": "service,OU=other"},
        {"common_name": "secret-canary\n"},
        {"lifetime_days": True},
        {"lifetime_days": 0},
        {"lifetime_days": 91},
        {"lifetime_days": "30"},
    ],
)
def test_invalid_issuance_inputs_fail_before_material_changes(
    issuance: dict[str, Any], changes: dict[str, Any]
) -> None:
    before = snapshot(issuance["authority_dir"].parent)
    with pytest.raises(pki.PkiError, match="^PKI_INVALID_INPUT$"):
        pki.issue_client(**{**issuance, **changes})
    assert snapshot(issuance["authority_dir"].parent) == before


def test_partial_generation_retains_key_and_does_not_reissue(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    write = pki._write_exclusive

    def interrupt(directory: int, name: str, data: bytes) -> None:
        if name == "client.crt":
            raise OSError("secret-canary interruption")
        write(directory, name, data)

    with monkeypatch.context() as partial:
        partial.setattr(pki, "_write_exclusive", interrupt)
        with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
            pki.issue_client(**issuance)
    directory = bundle(issuance)
    assert (directory / "client.key").is_file()
    assert not (directory / "client.crt").exists()
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_PARTIAL_STATE$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


def test_partial_authority_retains_generated_key(
    store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write = pki._write_exclusive

    def interrupt(directory: int, name: str, data: bytes) -> None:
        if name == "ca.crt":
            raise OSError("secret-canary interruption")
        write(directory, name, data)

    with monkeypatch.context() as partial:
        partial.setattr(pki, "_write_exclusive", interrupt)
        with pytest.raises(pki.PkiError):
            pki.initialize_authority(store / "authority", "fixture-client-ca")
    before = snapshot(store)
    assert (store / "authority" / "ca.key").is_file()
    with pytest.raises(pki.PkiError, match="^PKI_PARTIAL_STATE$"):
        pki.initialize_authority(store / "authority", "fixture-client-ca")
    assert snapshot(store) == before


def test_unowned_existing_authority_does_not_read_key(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = issuance["authority_dir"] / "authority.json"
    metadata = json.loads(path.read_bytes())
    metadata["owner"] = "other-issuer"
    path.write_text(json.dumps(metadata))
    read = pki._read
    names = []

    def inspect_read(directory: int, name: str, *, private: bool = True) -> bytes:
        names.append(name)
        return read(directory, name, private=private)

    monkeypatch.setattr(pki, "_read", inspect_read)
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.initialize_authority(issuance["authority_dir"], "fixture-client-ca")
    assert names == ["authority.json"]


def test_existing_unmarked_pki_is_not_imported(
    store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = store / "unowned-authority"
    directory.mkdir(mode=0o700)
    (directory / "ca.key").touch(mode=0o600)
    (directory / "ca.crt").touch(mode=0o600)
    monkeypatch.setattr(
        pki, "_read", lambda *_args, **_kwargs: pytest.fail("unowned PKI must not be read")
    )
    with pytest.raises(pki.PkiError, match="^PKI_PARTIAL_STATE$"):
        pki.initialize_authority(directory, "fixture-client-ca")


@pytest.mark.parametrize("target", ["client.key", "client.crt", "ca.crt", "extra-file"])
def test_changed_generation_material_fails_closed(issuance: dict[str, Any], target: str) -> None:
    pki.issue_client(**issuance)
    directory = bundle(issuance)
    if target == "client.key":
        key = ec.generate_private_key(ec.SECP256R1())
        (directory / target).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    elif target == "extra-file":
        (directory / target).touch(mode=0o600)
    else:
        make_server_ca(directory / target)
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


def test_invalid_signature_is_detected_without_replacing_material(issuance: dict[str, Any]) -> None:
    pki.issue_client(**issuance)
    path = bundle(issuance) / "client.crt"
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    der = bytearray(certificate.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    corrupted = x509.load_der_x509_certificate(bytes(der))
    path.write_bytes(corrupted.public_bytes(serialization.Encoding.PEM))
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_VALIDATION_FAILED$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


@pytest.mark.parametrize("field", ["authority_dir", "generations_dir", "server_ca_file"])
def test_symlink_paths_are_rejected(issuance: dict[str, Any], field: str) -> None:
    original = issuance[field]
    target = original.with_name(original.name + "-target")
    if original.exists():
        original.rename(target)
    else:
        target.mkdir(mode=0o700)
    original.symlink_to(target, target_is_directory=field != "server_ca_file")
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.issue_client(**issuance)


@pytest.mark.parametrize("filename", ["ca.key", "ca.crt", "authority.json"])
def test_authority_hardlinks_rejected(issuance: dict[str, Any], filename: str) -> None:
    path = issuance["authority_dir"] / filename
    os.link(path, path.with_name(filename + "-link"))
    # Keep the authority's exact entry check focused on the inode's link count.
    path.with_name(filename + "-link").rename(path.parent.parent / (filename + "-link"))
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.initialize_authority(issuance["authority_dir"], "fixture-client-ca")


def test_server_ca_hardlink_rejected(issuance: dict[str, Any]) -> None:
    os.link(issuance["server_ca_file"], issuance["server_ca_file"].with_suffix(".link"))
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.issue_client(**issuance)


@pytest.mark.parametrize("kind", ["authority-directory", "key", "ancestor", "server-ca"])
def test_unsafe_permissions_rejected(issuance: dict[str, Any], kind: str) -> None:
    path = {
        "authority-directory": issuance["authority_dir"],
        "key": issuance["authority_dir"] / "ca.key",
        "ancestor": issuance["authority_dir"].parent,
        "server-ca": issuance["server_ca_file"],
    }[kind]
    path.chmod(0o770 if path.is_dir() else 0o666)
    try:
        with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
            pki.issue_client(**issuance)
    finally:
        path.chmod(0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize("as_file", [False, True])
def test_repository_destination_is_rejected_before_creation(store: Path, as_file: bool) -> None:
    repository = store / "repository"
    repository.mkdir(mode=0o700)
    if as_file:
        (repository / ".git").write_text("gitdir: elsewhere\n")
    else:
        (repository / ".git").mkdir()
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.initialize_authority(repository / "authority", "fixture-client-ca")
    assert not (repository / "authority").exists()


@pytest.mark.parametrize("relative", [".", "inside"])
def test_authority_cannot_be_inside_generation_tree(
    issuance: dict[str, Any], relative: str
) -> None:
    directory = (
        issuance["authority_dir"] if relative == "." else issuance["authority_dir"] / "inside"
    )
    with pytest.raises(pki.PkiError, match="^PKI_ACCESS_DENIED$"):
        pki.issue_client(**{**issuance, "generations_dir": directory})


@pytest.mark.parametrize("kind", ["expired", "leaf", "non-pem", "private-key"])
def test_server_trust_must_be_valid_ca_material(issuance: dict[str, Any], kind: str) -> None:
    path = issuance["server_ca_file"]
    if kind == "expired":
        make_server_ca(path, expired=True)
    elif kind == "leaf":
        make_server_ca(path, ca=False)
    elif kind == "non-pem":
        path.write_bytes(b"secret-canary")
    else:
        path.write_bytes((issuance["authority_dir"] / "ca.key").read_bytes())
    with pytest.raises(pki.PkiError):
        pki.issue_client(**issuance)
    assert not issuance["generations_dir"].exists()


def test_atomic_exclusive_publication_does_not_overwrite(store: Path) -> None:
    path = store / "existing.json"
    path.write_bytes(b"existing evidence")
    path.chmod(0o600)
    before = digest_file(path)
    with pki._directory(store, private=True) as descriptor:
        with pytest.raises(FileExistsError):
            pki._write_exclusive(descriptor, "existing.json", b"new evidence")
    assert digest_file(path) == before
    assert any(child.name.startswith(".pending-") for child in store.iterdir())


@pytest.mark.parametrize(
    "internal_request",
    [
        {"command": "unknown", "secret": "secret-canary"},
        {
            "command": "initialize-authority",
            "authority_dir": "relative-secret-canary",
            "authority_id": "probe",
        },
        {
            "command": "initialize-authority",
            "authority_dir": "/secret-canary",
            "authority_id": "probe",
            "password": "secret-canary",
        },
    ],
)
def test_internal_subprocess_returns_fixed_errors_without_input_reflection(
    internal_request: dict[str, Any],
) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "query_passport.local_pki"],
        input=json.dumps(internal_request).encode(),
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stderr == b""
    assert b"secret-canary" not in completed.stdout
    result = json.loads(completed.stdout)
    assert result == {"status": "failed", "metadata": {}, "error": "PKI_INVALID_INPUT"}


def test_subprocess_authority_initialization_returns_only_metadata(store: Path) -> None:
    internal_request = {
        "command": "initialize-authority",
        "authority_dir": str(store / "authority"),
        "authority_id": "fixture-client-ca",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "query_passport.local_pki"],
        input=json.dumps(internal_request).encode(),
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert str(store).encode() not in completed.stdout
    assert b"BEGIN" not in completed.stdout
    result = json.loads(completed.stdout)
    assert result["status"] == "succeeded"
    assert result["error"] is None
    assert set(result["metadata"]) == pki.AUTHORITY_FIELDS | {"reused"}


def test_reuse_rejects_signed_certificate_with_wrong_eku(issuance: dict[str, Any]) -> None:
    pki.issue_client(**issuance)
    directory = bundle(issuance)
    leaf = x509.load_pem_x509_certificate((directory / "client.crt").read_bytes())
    issuer_key = serialization.load_pem_private_key(
        (issuance["authority_dir"] / "ca.key").read_bytes(), None
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf.subject)
        .issuer_name(leaf.issuer)
        .public_key(leaf.public_key())
        .serial_number(leaf.serial_number)
        .not_valid_before(leaf.not_valid_before_utc)
        .not_valid_after(leaf.not_valid_after_utc)
    )
    for extension in leaf.extensions:
        value = (
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
            if isinstance(extension.value, x509.ExtendedKeyUsage)
            else extension.value
        )
        builder = builder.add_extension(value, critical=extension.critical)
    wrong = builder.sign(issuer_key, hashes.SHA256())
    (directory / "client.crt").write_bytes(wrong.public_bytes(serialization.Encoding.PEM))
    metadata_path = directory.parent / "operation.json"
    metadata = json.loads(metadata_path.read_bytes())
    metadata["certificate_sha256"] = "sha256:" + wrong.fingerprint(hashes.SHA256()).hex()
    metadata_path.write_text(json.dumps(metadata))
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_VALIDATION_FAILED$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


def test_expired_generation_is_preserved_and_requires_new_operation(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = pki.issue_client(**issuance)
    after_expiry = datetime.fromisoformat(metadata["not_after"]) + timedelta(seconds=1)
    monkeypatch.setattr(pki, "_now", lambda: after_expiry)
    before = snapshot(issuance["generations_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_EXPIRED$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["generations_dir"]) == before


def test_authority_key_mismatch_is_not_repaired(issuance: dict[str, Any]) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    (issuance["authority_dir"] / "ca.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    before = snapshot(issuance["authority_dir"])
    with pytest.raises(pki.PkiError, match="^PKI_VALIDATION_FAILED$"):
        pki.issue_client(**issuance)
    assert snapshot(issuance["authority_dir"]) == before


def test_concurrent_identical_requests_issue_only_one_generation(issuance: dict[str, Any]) -> None:
    from concurrent.futures import ThreadPoolExecutor

    def attempt() -> dict[str, Any] | str:
        try:
            return pki.issue_client(**issuance)
        except pki.PkiError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    successes = [result for result in results if isinstance(result, dict)]
    assert len(successes) >= 1
    assert sum(not result["reused"] for result in successes) == 1
    assert all(isinstance(result, dict) or result == "PKI_PARTIAL_STATE" for result in results)
    final = pki.issue_client(**issuance)
    assert final["reused"] is True
    assert all(result["certificate_sha256"] == final["certificate_sha256"] for result in successes)


def test_unexpected_issuer_exception_is_normalized(
    issuance: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("secret-canary provider details")

    monkeypatch.setattr(pki.ec, "generate_private_key", broken)
    with pytest.raises(pki.PkiError) as caught:
        pki.issue_client(**issuance)
    assert str(caught.value) == "INTERNAL_ERROR"
    assert "secret-canary" not in str(caught.value)
