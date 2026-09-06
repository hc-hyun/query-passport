import json
import os
from types import SimpleNamespace

import pytest

from query_passport import operation_store as store


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(store.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(tmp_path)))
    return tmp_path


def test_executor_state_does_not_repair_or_read_legacy_namespace(state_home):
    legacy = state_home / ".local/state/query-passport"
    legacy.mkdir(parents=True)
    legacy.parent.chmod(0o700)
    legacy.parent.parent.chmod(0o700)
    legacy.chmod(0o775)
    sentinel = legacy / "review.txt"
    sentinel.write_text("preserve synthetic handoff")
    before = (legacy.stat(), sentinel.stat())
    with store.operation() as operation:
        operation.record("prepared")
    assert store.state_directory() == state_home / ".local/state/query-passport-executor/operations"
    assert (legacy.stat(), sentinel.stat()) == before
    assert sentinel.read_text() == "preserve synthetic handoff"
    assert not (legacy / "operations").exists()


def test_unsafe_executor_namespace_is_refused_without_fallback(state_home):
    namespace = store.state_directory().parent
    namespace.mkdir(parents=True)
    namespace.parent.chmod(0o700)
    namespace.parent.parent.chmod(0o700)
    namespace.chmod(0o775)
    before = namespace.stat()
    with pytest.raises(store.StateError, match="STATE_ACCESS_DENIED"):
        with store.operation():
            pytest.fail("Unsafe namespace was accepted")
    assert namespace.stat() == before
    assert not store.state_directory().exists()
    assert not (state_home / ".local/state/query-passport").exists()


def test_state_backup_and_history_survive_reopening(state_home):
    with store.operation() as operation:
        operation_id = operation.operation_id
        operation.write_artifact("hba.before", b"# synthetic baseline\n")
        operation.record("prepared")
        operation.record("issuing")
    with store.operation(operation_id) as reopened:
        assert reopened.read_artifact("hba.before") == b"# synthetic baseline\n"
        assert [event["phase"] for event in reopened.events()] == ["prepared", "issuing"]
        reopened.record("issuing")
        assert reopened.events()[-1]["error"] is None
    directory = store.state_directory() / operation_id
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "hba.before").stat().st_mode & 0o777 == 0o600
    assert (directory / "events.jsonl").read_bytes().count(b"\n") == 3


def test_backup_is_never_overwritten(state_home):
    with store.operation() as operation:
        operation.write_artifact("hba.before", b"original")
        with pytest.raises(store.StateError, match="STATE_CONFLICT"):
            operation.write_artifact("hba.before", b"replacement")
        assert operation.read_artifact("hba.before") == b"original"


def test_same_operation_is_locked_across_independent_descriptors(state_home):
    with store.operation() as operation:
        with pytest.raises(store.StateError, match="OPERATION_BUSY"):
            with store.operation(operation.operation_id):
                pytest.fail("Concurrent writer acquired an existing lock")
    with store.operation(operation.operation_id) as reopened:
        reopened.record("prepared")


@pytest.mark.parametrize("value", ["../outside", "a" * 31, "x" * 32, "a" * 33, "/tmp/path"])
def test_operation_id_cannot_select_arbitrary_path(state_home, value):
    with pytest.raises(store.StateError, match="STATE_INVALID"):
        with store.operation(value):
            pytest.fail("Invalid operation ID was accepted")


@pytest.mark.parametrize("name", ["../other", "client.key", "lock", "events.jsonl", "unknown.json"])
def test_artifact_name_allowlist(state_home, name):
    with store.operation() as operation:
        with pytest.raises(store.StateError, match="STATE_INVALID"):
            operation.write_artifact(name, b"synthetic")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "world-readable"])
def test_reopening_unsafe_artifact_fails(state_home, kind):
    with store.operation() as operation:
        directory = store.state_directory() / operation.operation_id
        target = directory / "hba.before"
        if kind == "symlink":
            (directory / "other").write_bytes(b"synthetic")
            target.symlink_to(directory / "other")
        else:
            operation.write_artifact("hba.before", b"synthetic")
            if kind == "hardlink":
                os.link(target, directory / "other")
            else:
                target.chmod(0o644)
        with pytest.raises(store.StateError):
            operation.read_artifact("hba.before")


def test_partial_journal_is_preserved_and_cannot_be_appended(state_home):
    with store.operation() as operation:
        operation.record("prepared")
        journal = store.state_directory() / operation.operation_id / "events.jsonl"
        with journal.open("ab") as stream:
            stream.write(b'{"sequence":1')
        before = journal.read_bytes()
        with pytest.raises(store.StateError, match="STATE_PARTIAL"):
            operation.record("issued")
        assert journal.read_bytes() == before


@pytest.mark.parametrize("value", [b"not-json\n", b'{"phase":[]}\n', b"{}\n"])
def test_malformed_history_is_not_reinterpreted(state_home, value):
    with store.operation() as operation:
        journal = store.state_directory() / operation.operation_id / "events.jsonl"
        descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(descriptor, value)
        os.close(descriptor)
        with pytest.raises(store.StateError, match="STATE_INVALID"):
            operation.events()


def test_external_event_sequence_change_is_rejected(state_home):
    with store.operation() as operation:
        operation.record("prepared")
        journal = store.state_directory() / operation.operation_id / "events.jsonl"
        event = json.loads(journal.read_bytes())
        event["sequence"] = 3
        journal.write_text(json.dumps(event) + "\n")
        with pytest.raises(store.StateError, match="STATE_INVALID"):
            operation.events()


def test_state_parent_symlink_does_not_redirect_creation(state_home):
    destination = state_home / "outside"
    destination.mkdir()
    (state_home / ".local").symlink_to(destination, target_is_directory=True)
    with pytest.raises(store.StateError, match="STATE_ACCESS_DENIED"):
        with store.operation():
            pytest.fail("State was created through a symlink")
    assert list(destination.iterdir()) == []


def test_world_writable_state_ancestor_is_rejected(state_home):
    parent = state_home / ".local"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    with pytest.raises(store.StateError, match="STATE_ACCESS_DENIED"):
        with store.operation():
            pytest.fail("Untrusted state directory accepted")
    assert list(parent.iterdir()) == []


def test_different_operations_cannot_mutate_same_server(state_home):
    with store.target_lock("a" * 64):
        with store.operation():
            with pytest.raises(store.StateError, match="OPERATION_BUSY"):
                with store.target_lock("a" * 64):
                    pytest.fail("Competing operation acquired shared server lock")
            with store.target_lock("b" * 64):
                pass
    with store.target_lock("a" * 64):
        pass


def test_failed_artifact_write_preserves_partial_evidence(state_home, monkeypatch):
    with store.operation() as operation:
        write = os.write
        calls = 0

        def interrupted(descriptor, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return write(descriptor, data[:2])
            raise OSError("synthetic-private-provider-diagnostic")

        with monkeypatch.context() as patch:
            patch.setattr(os, "write", interrupted)
            with pytest.raises(store.StateError, match="STATE_WRITE_FAILED") as error:
                operation.write_artifact("hba.before", b"synthetic baseline")
        assert "synthetic-private-provider-diagnostic" not in str(error.value)
        assert operation.read_artifact("hba.before") == b"sy"
        with pytest.raises(store.StateError, match="STATE_CONFLICT"):
            operation.write_artifact("hba.before", b"replacement")
