"""Original harmless child programs; no Docker or vendor artifact execution."""

import sys

import pytest

from responseforge.integrations.wazuh.process_runner import BoundedProcessRunner, ProcessFailure


def test_valid_child_receives_stdin_and_returns_exact_bounded_streams():
    program = "import sys; raw=sys.stdin.buffer.read(); sys.stdout.buffer.write(raw[::-1]); sys.stderr.buffer.write(b'original diagnostic')"
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", program], input_data=b"original input", timeout=5, max_output=4096
    )
    assert result.returncode == 0
    assert result.stdout == b"tupni lanigiro"
    assert result.stderr == b"original diagnostic"


def test_nonzero_child_is_an_observation_not_automatic_success_or_exception():
    result = BoundedProcessRunner().run(
        [
            sys.executable,
            "-c",
            "import sys;print('original');sys.stderr.write('failure');sys.exit(7)",
        ],
        timeout=5,
    )
    assert result.returncode == 7
    assert result.stdout == b"original\n"
    assert result.stderr == b"failure"


def test_stdin_and_both_output_pipes_are_serviced_without_deadlock():
    program = "import sys;sys.stdout.buffer.write(b'x'*200000);sys.stdout.buffer.flush();raw=sys.stdin.buffer.read();sys.stderr.buffer.write(str(len(raw)).encode())"
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", program], input_data=b"y" * 200000, timeout=5, max_output=300000
    )
    assert result.returncode == 0
    assert result.stdout == b"x" * 200000
    assert result.stderr == b"200000"


def test_exact_two_mebibyte_input_is_allowed():
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", "import sys;print(len(sys.stdin.buffer.read()))"],
        input_data=b"x" * (2 * 1024 * 1024),
        timeout=5,
        max_output=4096,
    )
    assert result.returncode == 0 and result.stdout == b"2097152\n"


def test_ambient_docker_routing_is_removed_but_normal_environment_preserved(monkeypatch):
    import json
    import os

    names = [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_API_VERSION",
        "BUILDX_BUILDER",
        "BUILDKIT_HOST",
    ]
    for name in names:
        monkeypatch.setenv(name, "original-synthetic-routing")
    monkeypatch.setenv("RF07C4_ORIGINAL_MARKER", "preserved")
    program = "import os,sys,json;print(json.dumps({'routes':{n:os.environ.get(n) for n in json.loads(sys.argv[1])},'marker':os.environ.get('RF07C4_ORIGINAL_MARKER'),'same_home':os.environ.get('HOME')==sys.argv[2]}))"
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", program, json.dumps(names), os.environ.get("HOME", "")], timeout=5
    )
    data = json.loads(result.stdout)
    assert data == {"routes": dict.fromkeys(names), "marker": "preserved", "same_home": True}


@pytest.mark.parametrize(
    "argv",
    [[], "not-an-argv-list", [""], [sys.executable, None], [sys.executable, "bad\x00argument"]],
)
def test_invalid_argv_refuses_before_spawn(argv, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("invalid argv spawned")
    )
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run(argv)
    assert error.value.category == "invalid-arguments"


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout", 0),
        ("timeout", -1),
        ("timeout", True),
        ("timeout", float("nan")),
        ("timeout", float("inf")),
        ("timeout", 301),
        ("max_output", 0),
        ("max_output", True),
        ("max_output", 8388609),
        ("input_data", "not bytes"),
    ],
)
def test_invalid_limits_refuse_before_spawn(field, value, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("invalid limits spawned")
    )
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run([sys.executable, "-c", "pass"], **{field: value})
    assert error.value.category == "invalid-arguments"


def test_input_over_limit_refuses_before_spawn(monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("excess input spawned")
    )
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run([sys.executable, "-c", "pass"], input_data=b"x" * (2097152 + 1))
    assert error.value.category == "input-limit"


@pytest.mark.parametrize(
    "program",
    [
        "import sys;sys.stdout.buffer.write(b'x'*100000)",
        "import sys;sys.stderr.buffer.write(b'x'*100000)",
        "import sys;sys.stdout.buffer.write(b'x'*2000);sys.stdout.buffer.flush();sys.stderr.buffer.write(b'y'*2000)",
    ],
)
def test_total_output_limit_stops_and_retains_only_bounded_bytes(program):
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run([sys.executable, "-c", program], timeout=5, max_output=3072)
    assert error.value.category == "output-limit"
    assert len(error.value.stdout) + len(error.value.stderr) <= 3072


def test_timeout_reaps_own_child_and_keeps_failure_message_safe():
    import time

    start = time.monotonic()
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run(
            [
                sys.executable,
                "-c",
                "import sys,time;print('ORIGINAL_PRIVATE_ARGUMENT',flush=True);time.sleep(30)",
            ],
            input_data=b"ORIGINAL_PRIVATE_STDIN",
            timeout=0.2,
        )
    assert error.value.category == "timeout"
    assert time.monotonic() - start < 5
    assert b"ORIGINAL_PRIVATE_ARGUMENT" in error.value.stdout
    assert "ORIGINAL_PRIVATE" not in str(error.value)


def test_missing_executable_is_spawn_failure_without_exposing_argv():
    with pytest.raises(ProcessFailure) as error:
        BoundedProcessRunner().run(["/original/nonexistent/PRIVATE_EXECUTABLE"], timeout=1)
    assert error.value.category == "spawn-failed"
    assert "PRIVATE_EXECUTABLE" not in str(error.value)


def test_empty_stdin_is_closed_and_child_observes_eof():
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", "import sys;print(len(sys.stdin.buffer.read()))"], timeout=5
    )
    assert result.returncode == 0 and result.stdout == b"0\n"


def test_child_may_exit_before_consuming_input_without_unhandled_broken_pipe():
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", "print('original early exit')"], input_data=b"x" * 2097152, timeout=5
    )
    assert result.returncode == 0 and result.stdout == b"original early exit\n"


def test_exact_combined_output_limit_is_allowed():
    result = BoundedProcessRunner().run(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(b'x'*32);sys.stderr.buffer.write(b'y'*32)",
        ],
        timeout=5,
        max_output=64,
    )
    assert result.returncode == 0 and result.stdout == b"x" * 32 and result.stderr == b"y" * 32


def test_shell_metacharacters_remain_literal_argument_data(tmp_path):
    sentinel = tmp_path / "outside-child-sentinel"
    value = "$(touch " + str(sentinel) + ");`printf unreviewed`"
    result = BoundedProcessRunner().run(
        [sys.executable, "-c", "import sys;sys.stdout.write(sys.argv[1])", value], timeout=5
    )
    assert result.returncode == 0 and result.stdout == value.encode()
    assert not sentinel.exists()
