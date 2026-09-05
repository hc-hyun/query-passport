"""Private local operation plans, backups, locks and append-only observations.

These filesystem records are not protected immutable evidence. No existing record
or backup is deleted, and this module never prints the private contents it holds.
"""

import contextlib
import fcntl
import json
import os
import pwd
import re
import stat
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .contract import ContractError, parse_json
from .executor import private_directory

MAX_ARTIFACT_BYTES = 1048576
ARTIFACTS = frozenset(
    {
        "plan.json",
        "hba.before",
        "ident.before",
        "settings.before.json",
        "hba.applied",
        "ident.applied",
        "credential.previous.json",
        "trust.previous.crt",
        "issuance.json",
        "delivery.json",
        "db.applied.json",
    }
)
PHASES = frozenset(
    {
        "prepared",
        "issuing",
        "issued",
        "applying",
        "applied",
        "delivering",
        "checking_delivery",
        "delivered",
        "verifying",
        "verified",
        "rolling_back",
        "rolled_back",
        "partial_failure",
        "unknown",
    }
)


class StateError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def state_directory() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/query-passport/operations"


def _open_root() -> int:
    root = state_directory()
    directory = private_directory(str(Path(pwd.getpwuid(os.geteuid()).pw_dir)))
    try:
        # Only create the fixed state subtree under the authenticated OS account.
        relative = root.relative_to(Path(pwd.getpwuid(os.geteuid()).pw_dir))
        for part in relative.parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            info = os.fstat(child)
            if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                os.close(child)
                raise StateError("STATE_ACCESS_DENIED")
            os.close(directory)
            directory = child
        if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
            raise StateError("STATE_ACCESS_DENIED")
        return directory
    except BaseException:
        os.close(directory)
        raise


def _file(directory: int, name: str, flags: int) -> int:
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > MAX_ARTIFACT_BYTES
    ):
        os.close(descriptor)
        raise StateError("STATE_ACCESS_DENIED")
    return descriptor


def _write(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise StateError("STATE_WRITE_FAILED")
        view = view[written:]
    os.fsync(descriptor)


class Operation:
    """One operation directory while its process-owned exclusive lock is held."""

    def __init__(self, operation_id: str, directory: int) -> None:
        self.operation_id = operation_id
        self.directory = directory

    def write_artifact(self, name: str, data: bytes) -> None:
        if name not in ARTIFACTS or len(data) > MAX_ARTIFACT_BYTES:
            raise StateError("STATE_INVALID")
        descriptor = -1
        try:
            descriptor = _file(self.directory, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            _write(descriptor, data)
            os.fsync(self.directory)
        except FileExistsError as error:
            raise StateError("STATE_CONFLICT") from error
        except OSError as error:
            raise StateError("STATE_WRITE_FAILED") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def read_artifact(self, name: str) -> bytes:
        if name not in ARTIFACTS:
            raise StateError("STATE_INVALID")
        descriptor = -1
        try:
            descriptor = _file(self.directory, name, os.O_RDONLY)
            chunks = bytearray()
            while len(chunks) <= MAX_ARTIFACT_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_ARTIFACT_BYTES + 1 - len(chunks)))
                if not chunk:
                    return bytes(chunks)
                chunks.extend(chunk)
            raise StateError("STATE_INVALID")
        except OSError as error:
            raise StateError("STATE_INVALID") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def events(self) -> list[dict[str, Any]]:
        descriptor = -1
        try:
            descriptor = _file(self.directory, "events.jsonl", os.O_RDONLY)
            raw = os.read(descriptor, MAX_ARTIFACT_BYTES + 1)
            if len(raw) > MAX_ARTIFACT_BYTES or (raw and not raw.endswith(b"\n")):
                raise StateError("STATE_PARTIAL")
            events = []
            for sequence, line in enumerate(raw.splitlines()):
                event = parse_json(line)
                if (
                    type(event) is not dict
                    or set(event) != {"sequence", "phase", "time", "error"}
                    or event["sequence"] != sequence
                    or type(event["sequence"]) is not int
                    or event["phase"] not in PHASES
                    or type(event["time"]) is not int
                    or (
                        event["error"] is not None
                        and (
                            type(event["error"]) is not str
                            or re.fullmatch(r"[A-Z_]{1,64}", event["error"]) is None
                        )
                    )
                ):
                    raise StateError("STATE_INVALID")
                events.append(event)
            return events
        except FileNotFoundError:
            return []
        except (ContractError, TypeError, ValueError) as error:
            raise StateError("STATE_INVALID") from error
        except OSError as error:
            raise StateError("STATE_INVALID") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def record(self, phase: str, error: str | None = None) -> None:
        if (
            type(phase) is not str
            or phase not in PHASES
            or (
                error is not None
                and (type(error) is not str or re.fullmatch(r"[A-Z_]{1,64}", error) is None)
            )
        ):
            raise StateError("STATE_INVALID")
        events = self.events()
        data = (
            json.dumps(
                {"sequence": len(events), "phase": phase, "time": int(time.time()), "error": error},
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        descriptor = -1
        try:
            descriptor = _file(
                self.directory, "events.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT
            )
            if os.fstat(descriptor).st_size + len(data) > MAX_ARTIFACT_BYTES:
                raise StateError("STATE_INVALID")
            _write(descriptor, data)
            os.fsync(self.directory)
        except OSError as failure:
            raise StateError("STATE_WRITE_FAILED") from failure
        finally:
            if descriptor >= 0:
                os.close(descriptor)


@contextlib.contextmanager
def operation(operation_id: str | None = None) -> Iterator[Operation]:
    """Create a new opaque operation or lock an existing one; never auto-delete."""
    if operation_id is not None and (
        type(operation_id) is not str or re.fullmatch(r"[a-f0-9]{32}", operation_id) is None
    ):
        raise StateError("STATE_INVALID")
    root = directory = lock = -1
    try:
        root = _open_root()
        if operation_id is None:
            operation_id = uuid.uuid4().hex
            os.mkdir(operation_id, mode=0o700, dir_fd=root)
            os.fsync(root)
        directory = os.open(operation_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise StateError("STATE_ACCESS_DENIED")
        lock = _file(directory, "lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StateError("OPERATION_BUSY") from error
        yield Operation(operation_id, directory)
    except OSError as error:
        raise StateError("STATE_ACCESS_DENIED") from error
    finally:
        for descriptor in (lock, directory, root):
            if descriptor >= 0:
                os.close(descriptor)


@contextlib.contextmanager
def target_lock(container_id: str) -> Iterator[None]:
    """Serialize different operations touching the same server's shared auth files.

    Callers acquire this before the operation lock and revalidate the bound target
    after acquiring both. Taking a filesystem lock does not authorize an action.
    """
    if type(container_id) is not str or re.fullmatch(r"[a-f0-9]{64}", container_id) is None:
        raise StateError("STATE_INVALID")
    root = directory = lock = -1
    try:
        root = _open_root()
        try:
            os.mkdir("locks", mode=0o700, dir_fd=root)
        except FileExistsError:
            pass
        directory = os.open("locks", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise StateError("STATE_ACCESS_DENIED")
        lock = _file(directory, container_id, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StateError("OPERATION_BUSY") from error
        yield
    except OSError as error:
        raise StateError("STATE_ACCESS_DENIED") from error
    finally:
        for descriptor in (lock, directory, root):
            if descriptor >= 0:
                os.close(descriptor)
