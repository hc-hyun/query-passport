"""Process regressions for the public input and JSON output boundaries."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from query_passport import cli

ROOT = Path(__file__).resolve().parents[1]
REQUEST_BYTES = (ROOT / "examples/request.json").read_bytes()


@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("suffix", ["", "/", "/.", "/nested", "/nested/.."])
def test_workspace_symlink_components_rejected(tmp_path, relative, suffix):
    public = tmp_path / "public"
    public.mkdir()
    (public / "nested").mkdir()
    (public / "request.json").write_bytes(REQUEST_BYTES)
    (public / "nested/request.json").write_bytes(REQUEST_BYTES)
    link = tmp_path / "workspace-link"
    link.symlink_to(public, target_is_directory=True)
    workspace = (link.name if relative else str(link)) + suffix

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "query_passport",
            "inspect",
            "--request",
            "request.json",
            "--workspace",
            workspace,
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert process.returncode == 4
    assert process.stderr == b""
    response = json.loads(process.stdout)
    assert response["status"] == "failed"
    assert response["result"] == {}
    assert response["errors"][0]["code"] == "INPUT_ACCESS_DENIED"
    assert str(tmp_path).encode() not in process.stdout


@pytest.mark.parametrize("workspace", ["public", "public/", "public/.", "public/nested/.."])
def test_directory_walk_accepts_real_relative_workspace(tmp_path, workspace):
    (tmp_path / "public/nested").mkdir(parents=True)
    (tmp_path / "public/request.json").write_bytes(REQUEST_BYTES)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "query_passport",
            "inspect",
            "--request",
            "request.json",
            "--workspace",
            workspace,
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert process.returncode == 0
    assert process.stderr == b""
    assert json.loads(process.stdout)["status"] == "validated"


def test_workspace_replacement_cannot_redirect_open_descriptor(tmp_path, monkeypatch):
    workspace = tmp_path / "public"
    workspace.mkdir()
    (workspace / "request.json").write_bytes(REQUEST_BYTES)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "request.json").write_bytes(b"unexpected")
    real_open = os.open

    def replacing_open(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if path == "public":
            workspace.rename(tmp_path / "original")
            workspace.symlink_to(replacement, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(os, "open", replacing_open)
    assert cli.read_request("request.json", str(workspace)) == REQUEST_BYTES


def test_closed_stdout_exits_without_stderr():
    # This must occur before Python starts: CPython sets sys.stdout to None when
    # FD 1 is missing. A patched stream inside the CLI does not reproduce it.
    process = subprocess.run(
        [sys.executable, "-m", "query_passport", "capabilities"],
        preexec_fn=lambda: os.close(1),
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert process.returncode == 1
    assert process.stdout == b""
    assert process.stderr == b""


def test_stdout_without_file_descriptor_exits_without_stderr(monkeypatch, capfd):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert cli.main(["capabilities"]) == 1
    assert capfd.readouterr().err == ""


def test_closed_stdout_stream_exits_without_stderr(monkeypatch, capfd):
    stream = io.StringIO()
    stream.close()
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(["capabilities"]) == 1
    assert capfd.readouterr().err == ""
