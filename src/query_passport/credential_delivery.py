"""Versioned local credential delivery behind an authorized executor boundary.

The destination is a private operator-owned store. Its active.json is an atomic
pointer to an immutable real directory, never a symlink. An executor resolves
``destination/versions/<generation_id>/bundle`` for the runtime bind mount.
Existing versions and failed staging files are never removed by this module.

A permission setter may operate ONLY on the newly created bundle it receives.
The caller must supply a fixed privileged helper when it cannot itself assign
runtime ownership. Inspect/reuse validate stored digests against pinned inode,
mode, size and nanosecond timestamps; they do not reopen an unreadable key. This
is local filesystem evidence, not protected immutable evidence against root or
another process running as the same trusted operator.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import local_pki as pki
from .contract import ContractError

OWNER = "query-passport-credential-delivery-v1"
BUNDLE_FILES = {"ca.crt", "client.crt", "client.key"}
REVISION_FIELDS = {"generation_id", "revision", "certificate_sha256"}
RECEIPT_FIELDS = {
    "owner",
    "version",
    "generation_id",
    "spec_digest",
    "source_spec_digest",
    "certificate_sha256",
    "content_digests",
    "runtime_uid",
    "runtime_gid",
    "bundle_stat",
    "file_stats",
    "previous",
}
ERROR_CODES = frozenset(
    {
        "DELIVERY_INVALID_INPUT",
        "DELIVERY_ACCESS_DENIED",
        "DELIVERY_OWNERSHIP_REQUIRED",
        "DELIVERY_INPUT_CONFLICT",
        "DELIVERY_DRIFT",
        "DELIVERY_PARTIAL_STATE",
        "DELIVERY_PERMISSION_DENIED",
        "DELIVERY_BUSY",
        "DELIVERY_ROLLED_BACK",
        "DELIVERY_VALIDATION_FAILED",
        "INTERNAL_ERROR",
    }
)
PermissionSetter = Callable[[Path], None]
Validator = Callable[[Path], None]


class DeliveryError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code if code in ERROR_CODES else "INTERNAL_ERROR"
        super().__init__(self.code)


def _require(condition: bool, code: str = "DELIVERY_VALIDATION_FAILED") -> None:
    if not condition:
        raise DeliveryError(code)


def _id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is not None


def _hash(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _empty() -> dict[str, Any]:
    return dict.fromkeys(REVISION_FIELDS)


def _revision(value: object) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == REVISION_FIELDS, "DELIVERY_INVALID_INPUT")
    assert isinstance(value, dict)
    if value["generation_id"] is None:
        _require(all(item is None for item in value.values()), "DELIVERY_INVALID_INPUT")
    else:
        _require(
            _id(value["generation_id"])
            and _hash(value["revision"])
            and _hash(value["certificate_sha256"]),
            "DELIVERY_INVALID_INPUT",
        )
    return dict(value)


def _stat(info: os.stat_result) -> list[int]:
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    ]


def _stat_shape(value: object) -> bool:
    return type(value) is list and len(value) == 9 and all(type(item) is int for item in value)


def _child(directory: int, name: str) -> int:
    return os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
    )


def _owns(directory: int) -> None:
    pki._directory_info(directory, private=True)
    try:
        owner = pki._parse(pki._read(directory, "owner.json"))
    except (pki.PkiError, OSError):
        raise DeliveryError("DELIVERY_OWNERSHIP_REQUIRED") from None
    _require(
        owner == {"owner": OWNER, "version": 1} and type(owner.get("version")) is int,
        "DELIVERY_OWNERSHIP_REQUIRED",
    )


def _create_store(destination: Path) -> None:
    with pki._directory(destination.parent) as parent:
        created = pki._mkdir(parent, destination.name)
    with pki._directory(destination, private=True) as directory:
        if not created:
            _owns(directory)
            return
        pki._entries(directory, set())
        pki._mkdir(directory, "versions")
        pki._mkdir(directory, "rollbacks")
        pki._write_exclusive(directory, "lock", b"")
        pki._write_exclusive(directory, "active.json", _json(_empty()))
        pki._write_exclusive(directory, "owner.json", _json({"owner": OWNER, "version": 1}))


@contextlib.contextmanager
def _store(destination: Path) -> Iterator[int]:
    with pki._directory(destination, private=True) as directory:
        _owns(directory)
        lock = os.open(
            "lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
        try:
            info = os.fstat(lock)
            _require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600,
                "DELIVERY_OWNERSHIP_REQUIRED",
            )
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeliveryError("DELIVERY_BUSY") from None
            yield directory
            # A legitimate concurrent rename must not make a successful return
            # refer to a different pathname than the descriptor we changed.
            with pki._directory(destination, private=True) as current:
                before, after = os.fstat(directory), os.fstat(current)
                _require(
                    (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "DELIVERY_DRIFT"
                )
        finally:
            os.close(lock)


def _permissions(
    bundle: int, runtime_uid: int, runtime_gid: int
) -> tuple[list[int], dict[str, list[int]]]:
    info = os.fstat(bundle)
    _require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid in (0, runtime_uid)
        and stat.S_IMODE(info.st_mode) in (0o700, 0o750, 0o755),
        "DELIVERY_PERMISSION_DENIED",
    )
    _require(set(os.listdir(bundle)) == BUNDLE_FILES, "DELIVERY_PARTIAL_STATE")
    files = {}
    for name in sorted(BUNDLE_FILES):
        info = os.stat(name, dir_fd=bundle, follow_symlinks=False)
        mode = stat.S_IMODE(info.st_mode)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "DELIVERY_PERMISSION_DENIED")
        if name == "client.key":
            permitted = (info.st_uid == runtime_uid and mode == 0o600) or (
                info.st_uid == 0 and info.st_gid == runtime_gid and mode == 0o640
            )
        else:
            permitted = info.st_uid in (0, runtime_uid) and mode in (0o600, 0o640, 0o644)
        _require(permitted, "DELIVERY_PERMISSION_DENIED")
        files[name] = _stat(info)
    return _stat(os.fstat(bundle)), files


def _default_permissions(path: Path, runtime_uid: int, runtime_gid: int) -> None:
    if os.geteuid() == runtime_uid and os.getegid() == runtime_gid:
        return  # The new bundle already has caller-owned 0700 directories/0600 files.
    _require(os.geteuid() == 0, "DELIVERY_PERMISSION_DENIED")
    os.chown(path, 0, runtime_gid, follow_symlinks=False)
    os.chmod(path, 0o755, follow_symlinks=False)
    for name in BUNDLE_FILES:
        os.chown(path / name, 0, runtime_gid, follow_symlinks=False)
        os.chmod(path / name, 0o640 if name == "client.key" else 0o644, follow_symlinks=False)


def _source(source_bundle: Path) -> tuple[dict[str, bytes], str, str]:
    _require(source_bundle.name == "bundle", "DELIVERY_INVALID_INPUT")
    with pki._directory(source_bundle.parent, private=True) as generation:
        pki._entries(generation, {"operation.json", "bundle"})
        metadata = pki._parse(pki._read(generation, "operation.json"))
        _require(
            set(metadata) == pki.OPERATION_FIELDS
            and metadata.get("owner") == pki.OWNER
            and type(metadata.get("version")) is int
            and metadata["version"] == 1,
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            metadata["operation_id"] == source_bundle.parent.name
            and _id(metadata["operation_id"])
            and pki._name(metadata["common_name"]),
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            all(
                _hash(metadata[name])
                for name in (
                    "spec_digest",
                    "input_digest",
                    "authority_sha256",
                    "server_ca_sha256",
                    "certificate_sha256",
                )
            ),
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            type(metadata["lifetime_days"]) is int and 1 <= metadata["lifetime_days"] <= 90,
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        descriptor = _child(generation, "bundle")
        try:
            pki._directory_info(descriptor, private=True)
            pki._entries(descriptor, BUNDLE_FILES)
            content = {name: pki._read(descriptor, name) for name in sorted(BUNDLE_FILES)}
        finally:
            os.close(descriptor)
    _require(_digest(content["ca.crt"]) == metadata["server_ca_sha256"])
    server_certificates = pki._certificates(content["ca.crt"])
    for certificate in server_certificates:
        pki._valid_now(certificate)
        _require(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    leaves = pki._certificates(content["client.crt"])
    _require(len(leaves) == 1)
    certificate = leaves[0]
    _require(
        certificate.subject
        == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, metadata["common_name"])])
    )
    _require(all(metadata[name] == value for name, value in pki._metadata(certificate).items()))
    _require(not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    _require(
        list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        == [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    _require(
        certificate.not_valid_after_utc - certificate.not_valid_before_utc
        <= timedelta(days=metadata["lifetime_days"])
    )
    _require(
        certificate.not_valid_before_utc <= datetime.now(UTC) < certificate.not_valid_after_utc
    )
    pki._key_matches(pki._private_key(content["client.key"]), certificate)
    return content, metadata["spec_digest"], metadata["certificate_sha256"]


def _read_intent(generation: int, generation_id: str) -> dict[str, Any]:
    intent = pki._parse(pki._read(generation, "intent.json"))
    _require(
        set(intent) == {"owner", "version", "generation_id", "spec_digest", "previous"}
        and intent.get("owner") == OWNER
        and type(intent.get("version")) is int
        and intent["version"] == 1
        and intent["generation_id"] == generation_id
        and _hash(intent["spec_digest"]),
        "DELIVERY_OWNERSHIP_REQUIRED",
    )
    _revision(intent["previous"])
    return intent


def _intent(directory: int, generation_id: str) -> dict[str, Any]:
    versions = _child(directory, "versions")
    generation = -1
    try:
        pki._directory_info(versions, private=True)
        generation = _child(versions, generation_id)
        pki._directory_info(generation, private=True)
        return _read_intent(generation, generation_id)
    finally:
        if generation >= 0:
            os.close(generation)
        os.close(versions)


def _receipt(directory: int, generation_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    versions = _child(directory, "versions")
    generation = bundle = -1
    try:
        pki._directory_info(versions, private=True)
        generation = _child(versions, generation_id)
        pki._directory_info(generation, private=True)
        pki._entries(generation, {"intent.json", "receipt.json", "bundle"})
        intent = _read_intent(generation, generation_id)
        receipt = pki._parse(pki._read(generation, "receipt.json"))
        _require(
            set(receipt) == RECEIPT_FIELDS
            and receipt.get("owner") == OWNER
            and type(receipt.get("version")) is int
            and receipt["version"] == 1
            and receipt["generation_id"] == generation_id,
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            all(
                _hash(receipt[name])
                for name in ("spec_digest", "source_spec_digest", "certificate_sha256")
            ),
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            type(receipt["content_digests"]) is dict
            and set(receipt["content_digests"]) == BUNDLE_FILES
            and all(_hash(value) for value in receipt["content_digests"].values()),
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(
            type(receipt["runtime_uid"]) is int
            and 0 < receipt["runtime_uid"] < 2**31
            and type(receipt["runtime_gid"]) is int
            and 0 <= receipt["runtime_gid"] < 2**31,
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _revision(receipt["previous"])
        _require(
            receipt["previous"] == intent["previous"]
            and receipt["spec_digest"] == intent["spec_digest"],
            "DELIVERY_DRIFT",
        )
        _require(
            _stat_shape(receipt["bundle_stat"])
            and type(receipt["file_stats"]) is dict
            and set(receipt["file_stats"]) == BUNDLE_FILES
            and all(_stat_shape(value) for value in receipt["file_stats"].values()),
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        bundle = _child(generation, "bundle")
        bundle_stat, file_stats = _permissions(
            bundle, receipt["runtime_uid"], receipt["runtime_gid"]
        )
        _require(
            receipt["bundle_stat"] == bundle_stat and receipt["file_stats"] == file_stats,
            "DELIVERY_DRIFT",
        )
        revision = {
            "generation_id": generation_id,
            "revision": _digest(_json(receipt)),
            "certificate_sha256": receipt["certificate_sha256"],
        }
        return receipt, revision
    finally:
        for descriptor in (bundle, generation, versions):
            if descriptor >= 0:
                os.close(descriptor)


def _active(directory: int) -> dict[str, Any]:
    raw = pki._read(directory, "active.json")
    active = _revision(pki._parse(raw))
    if active["generation_id"] is not None:
        _, current = _receipt(directory, active["generation_id"])
        _require(active == current, "DELIVERY_DRIFT")
    return active


def _publish(directory: int, previous: dict[str, Any], target: dict[str, Any]) -> None:
    _require(_active(directory) == previous, "DELIVERY_DRIFT")
    temporary = ".active-pending-" + uuid.uuid4().hex
    pki._write_exclusive(directory, temporary, _json(target))
    # Only the mutable pointer is replaced. Every credential version/receipt and
    # the predecessor record remain in their original immutable locations.
    _require(_active(directory) == previous, "DELIVERY_DRIFT")
    os.replace(temporary, "active.json", src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)


def _rollback_intent(directory: int, operation_id: str) -> dict[str, Any] | None:
    rollbacks = _child(directory, "rollbacks")
    try:
        pki._directory_info(rollbacks, private=True)
        try:
            raw = pki._read(rollbacks, operation_id + ".json")
        except FileNotFoundError:
            return None
        intent = pki._parse(raw)
        _require(
            set(intent) == {"owner", "version", "operation_id", "spec_digest", "from", "to"}
            and intent.get("owner") == OWNER
            and type(intent.get("version")) is int
            and intent["version"] == 1
            and intent["operation_id"] == operation_id,
            "DELIVERY_OWNERSHIP_REQUIRED",
        )
        _require(_hash(intent["spec_digest"]), "DELIVERY_OWNERSHIP_REQUIRED")
        if intent["from"] is not None:
            _revision(intent["from"])
        _revision(intent["to"])
        return intent
    finally:
        os.close(rollbacks)


def _inspect_delivery(destination: Path) -> dict[str, Any]:
    destination = pki._path(destination)
    try:
        with _store(destination) as directory:
            return _active(directory)
    except FileNotFoundError:
        # Only a missing destination means no delivery. Missing files in an
        # existing store are corruption or partial state, never an empty slot.
        with pki._directory(destination.parent) as parent:
            try:
                os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return _empty()
        raise DeliveryError("DELIVERY_PARTIAL_STATE") from None


def _deliver(
    source_bundle: Path,
    destination: Path,
    operation_id: str,
    expected_revision: dict[str, Any] | None,
    permission_setter: PermissionSetter | None,
    validator: Validator | None,
    runtime_uid: int,
    runtime_gid: int,
) -> dict[str, Any]:
    source_bundle, destination = pki._path(source_bundle), pki._path(destination)
    _require(_id(operation_id), "DELIVERY_INVALID_INPUT")
    _require(
        type(runtime_uid) is int
        and 0 < runtime_uid < 2**31
        and type(runtime_gid) is int
        and 0 <= runtime_gid < 2**31,
        "DELIVERY_INVALID_INPUT",
    )
    _require(
        destination != source_bundle
        and destination not in source_bundle.parents
        and source_bundle not in destination.parents,
        "DELIVERY_ACCESS_DENIED",
    )
    previous = _empty() if expected_revision is None else _revision(expected_revision)
    # Read only explicitly supplied, tool-marked issued materials; never discover
    # host credentials or import an existing live runtime directory.
    content, source_spec, certificate_sha256 = _source(source_bundle)
    specification = _digest(
        _json(
            {
                "source_bundle": str(source_bundle),
                "destination": str(destination),
                "operation_id": operation_id,
                "source_spec_digest": source_spec,
                "runtime_uid": runtime_uid,
                "runtime_gid": runtime_gid,
                "previous": previous,
                "content_digests": {name: _digest(raw) for name, raw in content.items()},
            }
        )
    )
    _create_store(destination)
    with _store(destination) as directory:
        active = _active(directory)
        _require(_rollback_intent(directory, operation_id) is None, "DELIVERY_ROLLED_BACK")
        versions = _child(directory, "versions")
        generation = descriptor = -1
        pinned_files: dict[str, int] = {}
        try:
            pki._directory_info(versions, private=True)
            _require(
                active == previous or active["generation_id"] == operation_id, "DELIVERY_DRIFT"
            )
            created = pki._mkdir(versions, operation_id)
            if not created:
                receipt, revision = _receipt(directory, operation_id)
                _require(receipt["spec_digest"] == specification, "DELIVERY_INPUT_CONFLICT")
                if active == revision:
                    _validate_candidate(destination, operation_id, validator)
                    _require(_active(directory) == revision, "DELIVERY_DRIFT")
                    return {**revision, "previous": receipt["previous"], "reused": True}
                _require(active == previous, "DELIVERY_DRIFT")
                _validate_candidate(destination, operation_id, validator)
                _, rechecked = _receipt(directory, operation_id)
                _require(rechecked == revision, "DELIVERY_DRIFT")
                _publish(directory, previous, revision)
                return {**revision, "previous": previous, "reused": True}
            _require(active == previous, "DELIVERY_DRIFT")
            generation = _child(versions, operation_id)
            pki._directory_info(generation, private=True)
            pki._entries(generation, set())
            pki._write_exclusive(
                generation,
                "intent.json",
                _json(
                    {
                        "owner": OWNER,
                        "version": 1,
                        "generation_id": operation_id,
                        "spec_digest": specification,
                        "previous": previous,
                    }
                ),
            )
            pki._mkdir(generation, "bundle")
            descriptor = _child(generation, "bundle")
            for name in sorted(BUNDLE_FILES):
                pki._write_exclusive(descriptor, name, content[name])
                pinned_files[name] = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
                )
            new_bundle = destination / "versions" / operation_id / "bundle"
            if permission_setter is None:
                _default_permissions(new_bundle, runtime_uid, runtime_gid)
            else:
                permission_setter(new_bundle)
            # The helper must not redirect its input path to another inode.
            named = os.stat("bundle", dir_fd=generation, follow_symlinks=False)
            held = os.fstat(descriptor)
            _require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino), "DELIVERY_DRIFT")
            for filename, file_descriptor in pinned_files.items():
                named_file = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
                held_file = os.fstat(file_descriptor)
                _require(
                    (named_file.st_dev, named_file.st_ino) == (held_file.st_dev, held_file.st_ino),
                    "DELIVERY_DRIFT",
                )
                actual = bytearray()
                while len(actual) <= pki.MAX_FILE_BYTES:
                    chunk = os.read(file_descriptor, 4096)
                    if not chunk:
                        break
                    actual.extend(chunk)
                _require(_digest(bytes(actual)) == _digest(content[filename]), "DELIVERY_DRIFT")
            bundle_stat, file_stats = _permissions(descriptor, runtime_uid, runtime_gid)
            receipt = {
                "owner": OWNER,
                "version": 1,
                "generation_id": operation_id,
                "spec_digest": specification,
                "source_spec_digest": source_spec,
                "certificate_sha256": certificate_sha256,
                "content_digests": {name: _digest(raw) for name, raw in content.items()},
                "runtime_uid": runtime_uid,
                "runtime_gid": runtime_gid,
                "bundle_stat": bundle_stat,
                "file_stats": file_stats,
                "previous": previous,
            }
            pki._write_exclusive(generation, "receipt.json", _json(receipt))
            _, revision = _receipt(directory, operation_id)
            _validate_candidate(destination, operation_id, validator)
            _, rechecked = _receipt(directory, operation_id)
            _require(rechecked == revision, "DELIVERY_DRIFT")
            _publish(directory, previous, revision)
            return {**revision, "previous": previous, "reused": False}
        finally:
            for file_descriptor in pinned_files.values():
                os.close(file_descriptor)
            for descriptor_to_close in (descriptor, generation, versions):
                if descriptor_to_close >= 0:
                    os.close(descriptor_to_close)


def _validate_candidate(destination: Path, operation_id: str, validator: Validator | None) -> None:
    if validator is not None:
        try:
            validator(destination / "versions" / operation_id / "bundle")
        except ContractError as error:
            if error.code in ("TIMEOUT", "INTERRUPTED"):
                raise
            raise DeliveryError("DELIVERY_VALIDATION_FAILED") from None
        except Exception:  # noqa: BLE001 - a provider callback may contain secret diagnostics
            raise DeliveryError("DELIVERY_VALIDATION_FAILED") from None


def _rollback(
    destination: Path, operation_id: str, previous: dict[str, Any] | None
) -> dict[str, Any]:
    destination = pki._path(destination)
    _require(_id(operation_id), "DELIVERY_INVALID_INPUT")
    target = _empty() if previous is None else _revision(previous)
    with _store(destination) as directory:
        delivery_intent = _intent(directory, operation_id)
        _require(delivery_intent["previous"] == target, "DELIVERY_INPUT_CONFLICT")
        if target["generation_id"] is not None:
            _, observed_previous = _receipt(directory, target["generation_id"])
            _require(observed_previous == target, "DELIVERY_DRIFT")
        active = _active(directory)
        # A failed staging or candidate verification did not change the pointer.
        # Its persisted intent still proves ownership and the expected predecessor.
        current = None
        if active != target:
            _, current = _receipt(directory, operation_id)
            _require(active == current, "DELIVERY_DRIFT")
        intent = _rollback_intent(directory, operation_id)
        if intent is not None:
            _require(
                intent["spec_digest"] == delivery_intent["spec_digest"] and intent["to"] == target,
                "DELIVERY_INPUT_CONFLICT",
            )
            if active == target:
                return {**target, "rolled_back_operation": operation_id, "reused": True}
            _require(intent["from"] == current, "DELIVERY_DRIFT")
        else:
            expected = {
                "owner": OWNER,
                "version": 1,
                "operation_id": operation_id,
                "spec_digest": delivery_intent["spec_digest"],
                "from": current,
                "to": target,
            }
            rollbacks = _child(directory, "rollbacks")
            try:
                pki._write_exclusive(rollbacks, operation_id + ".json", _json(expected))
            finally:
                os.close(rollbacks)
        if active != target:
            assert current is not None
            _publish(directory, current, target)
        return {**target, "rolled_back_operation": operation_id, "reused": intent is not None}


def _normalize(error: BaseException) -> DeliveryError | ContractError:
    if isinstance(error, ContractError) and error.code in ("TIMEOUT", "INTERRUPTED"):
        return error
    if isinstance(error, DeliveryError):
        return error
    if isinstance(error, pki.PkiError):
        code = {
            "PKI_INVALID_INPUT": "DELIVERY_INVALID_INPUT",
            "PKI_ACCESS_DENIED": "DELIVERY_ACCESS_DENIED",
            "PKI_PARTIAL_STATE": "DELIVERY_PARTIAL_STATE",
            "PKI_INPUT_CONFLICT": "DELIVERY_DRIFT",
            "PKI_VALIDATION_FAILED": "DELIVERY_VALIDATION_FAILED",
            "PKI_EXPIRED": "DELIVERY_VALIDATION_FAILED",
        }.get(error.code, "INTERNAL_ERROR")
        return DeliveryError(code)
    if isinstance(error, FileNotFoundError):
        return DeliveryError("DELIVERY_PARTIAL_STATE")
    if isinstance(error, OSError):
        return DeliveryError("DELIVERY_ACCESS_DENIED")
    if isinstance(error, (ValueError, TypeError, x509.ExtensionNotFound)):
        return DeliveryError("DELIVERY_VALIDATION_FAILED")
    return DeliveryError("INTERNAL_ERROR")


def inspect_delivery(destination: Path) -> dict[str, Any]:
    try:
        return _inspect_delivery(destination)
    except Exception as error:  # noqa: BLE001 - credential boundary emits fixed codes only
        raise _normalize(error) from None


def deliver(
    source_bundle: Path,
    destination: Path,
    operation_id: str,
    expected_revision: dict[str, Any] | None = None,
    *,
    permission_setter: PermissionSetter | None = None,
    validator: Validator | None = None,
    runtime_uid: int = 10001,
    runtime_gid: int = 10001,
) -> dict[str, Any]:
    try:
        return _deliver(
            source_bundle,
            destination,
            operation_id,
            expected_revision,
            permission_setter,
            validator,
            runtime_uid,
            runtime_gid,
        )
    except Exception as error:  # noqa: BLE001 - credential boundary emits fixed codes only
        raise _normalize(error) from None


def rollback(
    destination: Path, operation_id: str, previous: dict[str, Any] | None
) -> dict[str, Any]:
    try:
        return _rollback(destination, operation_id, previous)
    except Exception as error:  # noqa: BLE001 - credential boundary emits fixed codes only
        raise _normalize(error) from None
