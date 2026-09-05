import copy
import io
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from query_passport import cli
from query_passport.contract import ContractError, decode, respond

ROOT = Path(__file__).resolve().parents[1]
REQUEST_BYTES = (ROOT / "examples/request.json").read_bytes()
REQUEST = json.loads(REQUEST_BYTES)
MARKER = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"


def run(*args, data=None, cwd=ROOT):
    completed = subprocess.run(
        [sys.executable, "-m", "query_passport", *args],
        input=data,
        capture_output=True,
        cwd=cwd,
        timeout=10,
        check=False,
    )
    assert completed.stderr == b""
    assert len(completed.stdout) <= 16384
    assert completed.stdout.count(b"\n") == 1
    response = json.loads(completed.stdout)
    assert set(response) == {
        "contract_version",
        "tool_version",
        "command",
        "status",
        "scope",
        "result",
        "errors",
    }
    assert response["contract_version"] == "1"
    assert response["tool_version"] == "0.1.0"
    assert MARKER.encode() not in completed.stdout
    return completed.returncode, response


@pytest.mark.parametrize("command", ["inspect", "plan"])
def test_file_and_stdin(command):
    file_code, file_result = run(command, "--request", "examples/request.json", "--format", "json")
    stdin_code, stdin_result = run(command, "--request", "-", data=REQUEST_BYTES)
    assert file_code == stdin_code == 0
    assert file_result == stdin_result


@pytest.mark.parametrize("args", [("capabilities",), ("--version",), ("--help",)])
def test_discovery(args):
    code, result = run(*args)
    assert code == 0
    assert result["command"] == "capabilities"


@pytest.mark.parametrize(
    "command", ["verify", "issue", "apply", "deliver", "rotate", "rollback", MARKER, "psql"]
)
def test_unsupported_does_not_read_request(command):
    code, response = run(command, "--request", MARKER)
    assert code == 3
    assert response["errors"][0]["code"] == "UNSUPPORTED_OPERATION"


@pytest.mark.parametrize(
    "args",
    [
        ("plan",),
        ("plan", "--request", "-", "--yes"),
        ("capabilities", "--request", MARKER),
        ("plan", "--format", MARKER),
        ("plan", "--req", "-"),
        ("plan", "--password", MARKER),
    ],
)
def test_bad_arguments_are_safe(args):
    code, response = run(*args, data=REQUEST_BYTES)
    assert code == 2
    assert response["errors"][0]["code"] == "INVALID_INPUT"


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "token",
        "dsn",
        "certificate",
        "private_key",
        "secret",
        "secret_store_id",
        "credential_path",
        "sql",
        "command",
        "approved",
        MARKER,
    ],
)
@pytest.mark.parametrize("path", [(), ("profile",), ("profile", "authentication")])
def test_forbidden_fields_never_reflected(field, path):
    request = copy.deepcopy(REQUEST)
    parent = request
    for part in path:
        parent = parent[part]
    parent[field] = {"nested": [MARKER]}
    code, response = run("plan", "--request", "-", data=json.dumps(request).encode())
    assert code == 2
    assert response["result"] == {}
    assert response["errors"][0]["code"] == "INVALID_INPUT"


def test_even_valid_looking_values_are_not_echoed():
    request = copy.deepcopy(REQUEST)
    request["profile"]["database"] = MARKER
    code, _ = run("plan", "--request", "-", data=json.dumps(request).encode())
    assert code == 0


@pytest.mark.parametrize(
    "filename",
    [
        "../outside.json",
        "/tmp/outside.json",
        ".env",
        "credentials/request.json",
        "client.key",
        "missing.json",
    ],
)
def test_file_boundary(tmp_path, filename):
    code, response = run("inspect", "--workspace", str(tmp_path), "--request", filename)
    assert code == 4
    assert response["errors"][0]["code"] == "INPUT_ACCESS_DENIED"


@pytest.mark.parametrize("kind", ["symlink", "directory_symlink", "hardlink", "fifo", "directory"])
def test_special_files_rejected(tmp_path, kind):
    public = tmp_path / "public.json"
    public.write_bytes(REQUEST_BYTES)
    target = tmp_path / "request.json"
    if kind == "symlink":
        target.symlink_to(public)
    elif kind == "directory_symlink":
        (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
        target = tmp_path / "link/public.json"
    elif kind == "hardlink":
        os.link(public, target)
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    code, _ = run(
        "plan", "--workspace", str(tmp_path), "--request", str(target.relative_to(tmp_path))
    )
    assert code == 4


def test_size_limit_file_and_stdin(tmp_path):
    data = b" " * 65537
    (tmp_path / "large.json").write_bytes(data)
    for args in [("--request", "-"), ("--workspace", str(tmp_path), "--request", "large.json")]:
        code, response = run("plan", *args, data=data)
        assert code == 2
        assert response["errors"][0]["code"] == "INPUT_TOO_LARGE"


def test_no_network_process_or_credential_access(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline processing attempted an external operation")

    import builtins

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for command in ("capabilities", "inspect", "plan"):
        assert respond(command, None if command == "capabilities" else decode(REQUEST_BYTES))


def test_file_reader_only_opens_explicit_public_file(tmp_path, monkeypatch):
    (tmp_path / "request.json").write_bytes(REQUEST_BYTES)
    real_open = os.open
    opened = []

    def recording_open(path, *args, **kwargs):
        opened.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    assert cli.read_request("request.json", str(tmp_path)) == REQUEST_BYTES
    assert opened == [tmp_path.anchor, *tmp_path.parts[1:], "request.json"]


def test_unexpected_exception_is_redacted(monkeypatch, capfd):
    def broken(*args):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(cli, "respond", broken)
    assert cli.main(["capabilities"]) == 1
    output = capfd.readouterr()
    assert MARKER not in output.out
    assert output.err == ""
    assert json.loads(output.out)["errors"][0]["code"] == "INTERNAL_ERROR"


def test_output_limit(monkeypatch, capfd):
    monkeypatch.setattr(cli, "respond", lambda *args: {"large": "x" * 16384})
    assert cli.main(["capabilities"]) == 1
    assert json.loads(capfd.readouterr().out)["errors"][0]["code"] == "OUTPUT_TOO_LARGE"


def test_stdin_timeout():
    process = subprocess.Popen(
        [sys.executable, "-m", "query_passport", "plan", "--request", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Keep the writer open without sending EOF: the CLI itself must time out.
        assert process.wait(timeout=8) == 5
        out, err = process.communicate()
        assert err == b""
        assert json.loads(out)["errors"][0]["code"] == "TIMEOUT"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def test_timeout_handler():
    with pytest.raises(ContractError, match="time limit"):
        cli.timeout_handler(0, None)


@pytest.mark.parametrize("command", ["capabilities", "inspect", "plan"])
def test_full_cli_offline_boundary(command, monkeypatch, capfd):
    def forbidden(*args, **kwargs):
        raise AssertionError(MARKER)

    # Restore OS hooks before pytest's output-capture teardown opens its files.
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(socket, "getaddrinfo", forbidden)
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(REQUEST_BYTES)))
        args = [command] if command == "capabilities" else [command, "--request", "-"]
        assert cli.main(args) == 0
    captured = capfd.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["status"] in ("validated", "planned")


def test_malformed_input_is_not_reflected():
    code, response = run("plan", "--request", "-", data=b'{"' + MARKER.encode() + b'":')
    assert code == 2
    assert response["errors"][0]["code"] == "INVALID_INPUT"


def test_interrupt_is_json(monkeypatch, capfd):
    def interrupted(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "respond", interrupted)
    assert cli.main(["capabilities"]) == 130
    captured = capfd.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["errors"][0]["code"] == "INTERRUPTED"
