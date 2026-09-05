"""POSIX CLI with bounded public-file/stdin input and fixed JSON diagnostics."""

import argparse
import json
import os
import signal
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from types import FrameType
from typing import Never

from .contract import (
    COMMANDS,
    ERRORS,
    LIFECYCLE_COMMANDS,
    LIFECYCLE_TIMEOUT_SECONDS,
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    TIMEOUT_SECONDS,
    ContractError,
    envelope,
    respond,
)
from .lifecycle_contract import decode_request, failure_result


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ContractError()


def open_directory(path: str) -> int:
    """Open each directory component without following symlinks; caller closes FD.

    Preserve ``..`` components during the walk so a preceding symlink cannot be
    hidden by lexical normalization. Directory descriptors keep later opens tied
    to the directories already checked even if their names are replaced.
    """
    if not path:
        raise ValueError("Empty directory path")
    parsed = Path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(parsed.anchor or ".", flags)
    try:
        parts = parsed.parts[1:] if parsed.anchor else parsed.parts
        for part in parts:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def read_request(filename: str, workspace: str) -> bytes:
    if filename == "-":
        return sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    # Walk from an explicit directory descriptor; no symlink resolution or
    # recursive discovery. O_NONBLOCK prevents a FIFO race from blocking open.
    path = Path(filename)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.suffix != ".json"
        or any(
            part.startswith(".")
            or part
            in {
                "credentials",
                "authority",
                "artifacts",
                "probes",
                "local",
            }
            for part in path.parts
        )
    ):
        raise ContractError("INPUT_ACCESS_DENIED")
    directory = -1
    descriptor = -1
    try:
        directory = open_directory(workspace)
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ContractError("INPUT_ACCESS_DENIED")
        if info.st_size > MAX_INPUT_BYTES:
            raise ContractError("INPUT_TOO_LARGE")
        chunks = bytearray()
        while len(chunks) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, MAX_INPUT_BYTES + 1 - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)
    except (OSError, ValueError) as error:
        raise ContractError("INPUT_ACCESS_DENIED") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def timeout_handler(signum: int, frame: FrameType | None) -> None:
    raise ContractError("TIMEOUT")


def main(argv: Sequence[str] | None = None) -> int:
    command = None
    failure: dict[str, object] = {}
    exit_code = 0
    previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        if args and args[0] in COMMANDS:
            command = args[0]
        if args in (["--version"], ["--help"]):
            command = "capabilities"
            response = respond(command)
            if args == ["--help"]:
                response["result"]["usage"] = (
                    "query-passport capabilities [--format json]; "
                    "query-passport inspect|plan|verify|prepare|issue|apply|deliver|rotate|rollback|status "
                    "--request FILE|- "
                    "[--workspace DIR] [--format json]"
                )
        else:
            if command not in COMMANDS:
                raise ContractError("UNSUPPORTED_OPERATION")
            parser = Parser(add_help=False, allow_abbrev=False)
            parser.add_argument("command", choices=COMMANDS)
            parser.add_argument("--format", choices=["json"], default="json")
            if command != "capabilities":
                parser.add_argument("--request", required=True)
                parser.add_argument("--workspace", default=".")
            options = parser.parse_args(args)
            request = (
                None
                if command == "capabilities"
                else decode_request(command, read_request(options.request, options.workspace))
            )
            failure = failure_result(command, request)
            if command == "verify":
                signal.setitimer(signal.ITIMER_REAL, 60)
            elif command in LIFECYCLE_COMMANDS:
                signal.setitimer(signal.ITIMER_REAL, LIFECYCLE_TIMEOUT_SECONDS)
            response = respond(command, request)
            if response["errors"]:
                exit_code = ERRORS[response["errors"][0]["code"]][0]
    except ContractError as error:
        exit_code = ERRORS[error.code][0]
        response = envelope(command, "failed", failure, code=error.code)
    except (KeyboardInterrupt, SystemExit):
        exit_code = ERRORS["INTERRUPTED"][0]
        response = envelope(command, "failed", failure, code="INTERRUPTED")
    except Exception:  # noqa: BLE001 - public boundary must never leak raw exceptions
        exit_code = ERRORS["INTERNAL_ERROR"][0]
        response = envelope(command, "failed", failure, code="INTERNAL_ERROR")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    output = json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(output.encode()) > MAX_OUTPUT_BYTES:
        exit_code = ERRORS["OUTPUT_TOO_LARGE"][0]
        output = json.dumps(envelope(command, "failed", failure, code="OUTPUT_TOO_LARGE")) + "\n"
    try:
        # One bounded write. No diagnostics, tracebacks, or user strings on stderr.
        if sys.stdout is None:
            return 1
        os.write(sys.stdout.fileno(), output.encode())
    except (OSError, ValueError, AttributeError):
        return 1
    return exit_code
