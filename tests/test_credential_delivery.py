"""Synthetic external materials only; real ownership is covered by Docker E2E."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from query_passport import credential_delivery as delivery
from query_passport import local_pki as pki
from query_passport.contract import ContractError


@pytest.fixture
def material() -> Iterator[dict[str, Any]]:
    with tempfile.TemporaryDirectory(
        prefix="query-passport-delivery-test-", dir="/var/tmp"
    ) as temporary:
        root = Path(temporary)
        pki.initialize_authority(root / "client-authority", "fixture-client-ca")
        pki.initialize_authority(root / "server-authority", "fixture-server-ca")
        for operation_id in ("source-first", "source-second"):
            pki.issue_client(
                root / "client-authority",
                root / "issued",
                operation_id,
                "sha256:" + "1" * 64,
                "fixture-service",
                root / "server-authority" / "ca.crt",
            )
        yield {
            "root": root,
            "source_bundle": root / "issued" / "source-first" / "bundle",
            "second_source": root / "issued" / "source-second" / "bundle",
            "destination": root / "delivery",
            "runtime_uid": os.geteuid() or 10001,
            "runtime_gid": os.getegid() if os.geteuid() else 10001,
        }


def issue(material: dict[str, Any], operation_id: str = "first", **changes: Any) -> dict[str, Any]:
    arguments = {
        key: material[key] for key in ("source_bundle", "destination", "runtime_uid", "runtime_gid")
    }
    return delivery.deliver(**{**arguments, "operation_id": operation_id, **changes})


def revision(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in delivery.REVISION_FIELDS}


def snapshot(path: Path) -> dict[str, tuple[int, int, str]]:
    return {
        str(child.relative_to(path)): (
            child.stat().st_ino,
            child.stat().st_mtime_ns,
            hashlib.sha256(child.read_bytes()).hexdigest(),
        )
        for child in path.rglob("*")
        if child.is_file()
    }


def active_file(material: dict[str, Any]) -> dict[str, Any]:
    path = material["destination"] / "active.json"
    return json.loads(path.read_bytes()) if path.exists() else delivery._empty()


def candidate(material: dict[str, Any], operation_id: str) -> Path:
    return material["destination"] / "versions" / operation_id / "bundle"


def test_initial_delivery_publishes_only_three_files_and_safe_revision(
    material: dict[str, Any],
) -> None:
    assert delivery.inspect_delivery(material["destination"]) == delivery._empty()
    result = issue(material)
    assert result["generation_id"] == "first"
    assert result["previous"] == delivery._empty()
    assert result["reused"] is False
    assert delivery.inspect_delivery(material["destination"]) == revision(result)
    assert not candidate(material, "first").is_symlink()
    assert (
        set(path.name for path in candidate(material, "first").iterdir()) == delivery.BUNDLE_FILES
    )
    assert set(path.name for path in candidate(material, "first").parent.iterdir()) == {
        "receipt.json",
        "bundle",
    }
    assert str(material["root"]) not in json.dumps(result)
    assert "BEGIN" not in json.dumps(result)
    assert "client.key" not in json.dumps(result)
    source = snapshot(material["source_bundle"])
    copied = snapshot(candidate(material, "first"))
    assert {name: value[2] for name, value in source.items()} == {
        name: value[2] for name, value in copied.items()
    }
    assert all(source[name][0] != copied[name][0] for name in source)


def test_repeated_delivery_keeps_original_files_and_reruns_validator(
    material: dict[str, Any],
) -> None:
    validations = []

    def callback(path: Path) -> None:
        validations.append(path)

    first = issue(material, validator=callback)
    before = snapshot(material["destination"])
    second = issue(material, validator=callback)
    assert second["reused"] is True
    assert revision(first) == revision(second)
    assert validations == [candidate(material, "first"), candidate(material, "first")]
    assert snapshot(material["destination"]) == before


def test_rotation_preserves_original_version_and_returns_predecessor(
    material: dict[str, Any],
) -> None:
    first = issue(material)
    before = snapshot(candidate(material, "first"))
    second = issue(
        material,
        "second",
        source_bundle=material["second_source"],
        expected_revision=revision(first),
    )
    assert second["previous"] == revision(first)
    assert second["certificate_sha256"] != first["certificate_sha256"]
    assert snapshot(candidate(material, "first")) == before
    assert delivery.inspect_delivery(material["destination"]) == revision(second)


def test_stale_revision_rejects_rotation_before_new_version_creation(
    material: dict[str, Any],
) -> None:
    issue(material)
    before = snapshot(material["destination"])
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_DRIFT$"):
        issue(material, "second", source_bundle=material["second_source"])
    assert snapshot(material["destination"]) == before
    assert not candidate(material, "second").parent.exists()


def test_same_operation_rejects_changed_source(material: dict[str, Any]) -> None:
    issue(material)
    before = snapshot(material["destination"])
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_INPUT_CONFLICT$"):
        issue(material, source_bundle=material["second_source"])
    assert snapshot(material["destination"]) == before


def test_validator_failure_preserves_current_and_reuses_complete_candidate_on_retry(
    material: dict[str, Any],
) -> None:
    first = issue(material)
    before = snapshot(candidate(material, "first"))
    permissions = []

    def reject(path: Path) -> None:
        assert path == candidate(material, "second")
        assert active_file(material) == revision(first)
        raise RuntimeError("secret-canary driver details")

    with pytest.raises(delivery.DeliveryError) as caught:
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
            validator=reject,
            permission_setter=lambda path: permissions.append(path),
        )
    assert str(caught.value) == "DELIVERY_VALIDATION_FAILED"
    assert active_file(material) == revision(first)
    staged = snapshot(candidate(material, "second"))
    second = issue(
        material,
        "second",
        source_bundle=material["second_source"],
        expected_revision=revision(first),
        permission_setter=lambda _path: pytest.fail(
            "existing candidate permissions must not be reapplied"
        ),
        validator=lambda _path: None,
    )
    assert second["reused"] is True
    assert snapshot(candidate(material, "second")) == staged
    assert snapshot(candidate(material, "first")) == before
    assert permissions == [candidate(material, "second")]
    assert active_file(material) == revision(second)


def test_validator_cannot_mutate_candidate_and_publish_it(material: dict[str, Any]) -> None:
    first = issue(material)

    def mutate(path: Path) -> None:
        with (path / "client.key").open("ab") as stream:
            stream.write(b"changed")

    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_DRIFT$"):
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
            validator=mutate,
        )
    assert active_file(material) == revision(first)


def test_permission_setter_receives_only_new_bundle_and_cannot_change_content(
    material: dict[str, Any],
) -> None:
    first = issue(material)
    previous = snapshot(candidate(material, "first"))

    def mutate(path: Path) -> None:
        assert path == candidate(material, "second")
        assert set(child.name for child in path.iterdir()) == delivery.BUNDLE_FILES
        with (path / "client.key").open("ab") as stream:
            stream.write(b"changed")

    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_DRIFT$"):
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
            permission_setter=mutate,
        )
    assert active_file(material) == revision(first)
    assert snapshot(candidate(material, "first")) == previous


def test_permission_setter_cannot_replace_checked_file_inode(material: dict[str, Any]) -> None:
    def replace(path: Path) -> None:
        old = path / "client.key"
        # Synthetic test key only; retain its old inode as failure evidence.
        old.rename(material["root"] / "preserved-key")
        old.write_bytes((material["root"] / "preserved-key").read_bytes())
        old.chmod(0o600)

    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_DRIFT$"):
        issue(material, permission_setter=replace)
    assert active_file(material) == delivery._empty()


def test_wrong_final_permissions_reject_without_publication(material: dict[str, Any]) -> None:
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_PERMISSION_DENIED$"):
        issue(material, permission_setter=lambda path: (path / "client.key").chmod(0o644))
    assert active_file(material) == delivery._empty()
    assert (candidate(material, "first") / "client.key").exists()


def test_unprivileged_default_cannot_claim_different_runtime_uid(material: dict[str, Any]) -> None:
    if os.geteuid() == 0:
        pytest.skip("host is privileged; Docker E2E covers real UID ownership")
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_PERMISSION_DENIED$"):
        issue(material, runtime_uid=10001, runtime_gid=10001)
    assert active_file(material) == delivery._empty()


def test_inspect_never_reopens_runtime_private_key(
    material: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    first = issue(material)
    read = pki._read

    def guarded(directory: int, name: str, *, private: bool = True) -> bytes:
        assert name != "client.key", (
            "inspection must use the pinned stat receipt, not private key reads"
        )
        return read(directory, name, private=private)

    monkeypatch.setattr(pki, "_read", guarded)
    assert delivery.inspect_delivery(material["destination"]) == revision(first)


@pytest.mark.parametrize("kind", ["content", "mode", "hardlink", "symlink"])
def test_inspect_detects_changed_active_material(material: dict[str, Any], kind: str) -> None:
    issue(material)
    key = candidate(material, "first") / "client.key"
    if kind == "content":
        with key.open("ab") as stream:
            stream.write(b"changed")
    elif kind == "mode":
        key.chmod(0o644)
    elif kind == "hardlink":
        os.link(key, material["root"] / "extra-key-link")
    else:
        key.rename(material["root"] / "original-key")
        key.symlink_to(material["root"] / "original-key")
    with pytest.raises(delivery.DeliveryError):
        delivery.inspect_delivery(material["destination"])


def test_unowned_existing_live_directory_is_never_imported_or_overwritten(
    material: dict[str, Any],
) -> None:
    directory = material["destination"]
    directory.mkdir(mode=0o700)
    (directory / "existing.txt").write_text("existing host evidence")
    before = snapshot(directory)
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_OWNERSHIP_REQUIRED$"):
        issue(material)
    assert snapshot(directory) == before


def test_source_requires_owned_issuance_manifest_before_key_read(
    material: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = material["source_bundle"].parent / "operation.json"
    value = json.loads(metadata.read_bytes())
    value["owner"] = "another-provider"
    metadata.write_text(json.dumps(value))
    read = pki._read

    def guarded(directory: int, name: str, *, private: bool = True) -> bytes:
        assert name != "client.key"
        return read(directory, name, private=private)

    monkeypatch.setattr(pki, "_read", guarded)
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_OWNERSHIP_REQUIRED$"):
        issue(material)
    assert not material["destination"].exists()


@pytest.mark.parametrize("field", ["source_bundle", "destination"])
def test_symlink_storage_paths_are_rejected(material: dict[str, Any], field: str) -> None:
    path = material[field]
    target = material["root"] / (field + "-target")
    if path.exists():
        path.rename(target)
    else:
        target.mkdir(mode=0o700)
    path.symlink_to(target, target_is_directory=True)
    with pytest.raises(delivery.DeliveryError):
        issue(material)


def test_git_destination_rejects_before_material_copy(material: dict[str, Any]) -> None:
    repository = material["root"] / "repository"
    repository.mkdir(mode=0o700)
    (repository / ".git").mkdir()
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_ACCESS_DENIED$"):
        issue(material, destination=repository / "delivery")
    assert not (repository / "delivery").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_id": "../escape"},
        {"runtime_uid": True},
        {"runtime_gid": -1},
        {"expected_revision": {"secret": "secret-canary"}},
    ],
)
def test_invalid_input_is_fixed_and_does_not_create_store(
    material: dict[str, Any], changes: dict[str, Any]
) -> None:
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_INVALID_INPUT$"):
        issue(material, **changes)
    assert not material["destination"].exists()


def test_partial_copy_preserves_old_active_and_can_be_aborted(
    material: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    first = issue(material)
    write = pki._write_exclusive

    def fail(directory: int, name: str, data: bytes) -> None:
        if name == "client.key":
            raise OSError("secret-canary disk failure")
        write(directory, name, data)

    with monkeypatch.context() as partial:
        partial.setattr(pki, "_write_exclusive", fail)
        with pytest.raises(delivery.DeliveryError):
            issue(
                material,
                "second",
                source_bundle=material["second_source"],
                expected_revision=revision(first),
            )
    staged = snapshot(candidate(material, "second"))
    assert staged
    assert active_file(material) == revision(first)
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_PARTIAL_STATE$"):
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
        )
    assert snapshot(candidate(material, "second")) == staged


def test_store_lock_rejects_competing_transition(material: dict[str, Any]) -> None:
    issue(material)
    with delivery._store(material["destination"]):
        with pytest.raises(delivery.DeliveryError, match="^DELIVERY_BUSY$"):
            delivery.inspect_delivery(material["destination"])


@pytest.mark.parametrize("callback_name", ["permission_setter", "validator"])
def test_safe_timeout_classification_survives_callback_boundary(
    material: dict[str, Any], callback_name: str
) -> None:
    first = issue(material)

    def timeout(_path: Path) -> None:
        raise ContractError("TIMEOUT")

    with pytest.raises(ContractError) as caught:
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
            **{callback_name: timeout},
        )
    assert caught.value.code == "TIMEOUT"
    assert active_file(material) == revision(first)
    assert candidate(material, "second").is_dir()


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_interrupts_propagate_for_coordinator_unknown_outcome(
    material: dict[str, Any], exception: type[BaseException]
) -> None:
    first = issue(material)

    def interrupt(_path: Path) -> None:
        raise exception

    with pytest.raises(exception):
        issue(
            material,
            "second",
            source_bundle=material["second_source"],
            expected_revision=revision(first),
            permission_setter=interrupt,
        )
    assert active_file(material) == revision(first)
    assert candidate(material, "second").is_dir()


def test_missing_active_pointer_is_corruption_not_an_empty_slot(material: dict[str, Any]) -> None:
    issue(material)
    (material["destination"] / "active.json").unlink()
    before = snapshot(material["destination"])
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_PARTIAL_STATE$"):
        delivery.inspect_delivery(material["destination"])
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_PARTIAL_STATE$"):
        issue(material, "second", source_bundle=material["second_source"])
    assert snapshot(material["destination"]) == before
    assert not candidate(material, "second").parent.exists()


def test_owner_version_requires_integer_not_boolean(material: dict[str, Any]) -> None:
    issue(material)
    owner_path = material["destination"] / "owner.json"
    owner_path.write_text(json.dumps({"owner": delivery.OWNER, "version": True}))
    with pytest.raises(delivery.DeliveryError, match="^DELIVERY_OWNERSHIP_REQUIRED$"):
        delivery.inspect_delivery(material["destination"])
