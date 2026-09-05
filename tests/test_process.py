import os
import sys
import time

import pytest

from query_passport.contract import ContractError
from query_passport.process import MAX_PRIVATE_INPUT, run_process


def child(source, **kwargs):
    return run_process(
        [sys.executable, "-I", "-c", source], env={"PATH": "/usr/bin:/bin"}, **kwargs
    )


def test_duplex_large_input_and_output_do_not_deadlock():
    source = (
        "import os,sys; data=b'x'*524288; "
        "sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); "
        "received=sys.stdin.buffer.read(); assert len(received)==1048576"
    )
    code, output = child(source, stdin=b"y" * MAX_PRIVATE_INPUT, limit=524288, timeout=5)
    assert code == 0 and output == b"x" * 524288


def test_stalled_input_is_bounded_and_child_reaped(tmp_path):
    marker = tmp_path / "pid"
    # This argv is a synthetic test process; production boundaries have fixed argv.
    source = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(30)"
    start = time.monotonic()
    with pytest.raises(ContractError) as error:
        child(source, stdin=b"x" * MAX_PRIVATE_INPUT, timeout=0.3)
    assert error.value.code == "TIMEOUT"
    assert time.monotonic() - start < 3
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)


def test_eof_with_process_still_running_obeys_deadline():
    with pytest.raises(ContractError) as error:
        child("import os,time; os.close(1); time.sleep(30)", timeout=0.2)
    assert error.value.code == "TIMEOUT"


def test_raw_stderr_is_discarded(capsys):
    code, output = child("import sys; sys.stderr.write('private-canary'); print('ok'); sys.exit(7)")
    assert (code, output) == (7, b"ok\n")
    assert capsys.readouterr() == ("", "")


def test_output_overflow_is_a_fixed_error():
    with pytest.raises(ContractError) as error:
        child("print('private-canary'*10000)", limit=12)
    assert error.value.code == "EXECUTOR_FAILED"
    assert "private-canary" not in str(error.value)


def test_input_limit_checked_before_spawn(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("must not spawn")

    monkeypatch.setattr("query_passport.process.subprocess.Popen", forbidden)
    with pytest.raises(ContractError) as error:
        child("", stdin=b"x" * (MAX_PRIVATE_INPUT + 1))
    assert error.value.code == "EXECUTOR_FAILED"


def test_input_closed_early_cannot_report_success():
    with pytest.raises(ContractError) as error:
        child("import os; os.close(0)", stdin=b"x" * MAX_PRIVATE_INPUT)
    assert error.value.code == "EXECUTOR_FAILED"
