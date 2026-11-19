"""Explicit daemon/authority binding with an injected command runner only."""

import json
import subprocess
from pathlib import Path

import pytest

from responseforge.integrations.shuffle.operations import DockerRuntime
from responseforge.integrations.shuffle.runtime_deployment import render_runtime
from tests.rf04_runtime.test_deployment import images

ENGINE = "synthetic-reviewed-daemon"


def runtime_state(tmp_path: Path, **changes):
    path = tmp_path / "runtime.json"
    path.write_text(
        json.dumps(
            {
                "context": "reviewed-desktop",
                "engine_id": ENGINE,
                "architecture": "arm64",
                "authorized": True,
                "images": images(),
            }
            | changes
        )
    )
    path.chmod(0o600)
    settings = json.loads(path.read_text())
    compose = render_runtime(images(), tmp_path, engine_authorized=settings["authorized"] is True)[
        "compose"
    ]
    (tmp_path / "compose.json").write_text(json.dumps(compose))
    (tmp_path / "compose.json").chmod(0o600)
    return tmp_path


def runner(observation=None):
    calls = []
    info = {
        "ID": ENGINE,
        "OSType": "linux",
        "Architecture": "aarch64",
        "Swarm": {"LocalNodeState": "inactive"},
    } | (observation or {})

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "info" in argv:
            output = json.dumps(info)
        elif argv[3:5] == ["image", "inspect"]:
            output = argv[-1]
        elif argv[3:5] in (["ps", "-a"], ["volume", "ls"]):
            output = ""
        else:
            output = "operation-complete"
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    return run, calls


def test_mutation_binds_explicit_context_to_current_engine_first(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = runner()
    result = DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert result == "operation-complete"
    assert calls[0][0] == [
        "docker",
        "--context",
        "reviewed-desktop",
        "info",
        "--format",
        "{{json .}}",
    ]
    assert calls[-1][0] == ["docker", "--context", "reviewed-desktop", "compose", "up", "-d"]
    assert any(argv[3:5] == ["image", "inspect"] for argv, _ in calls)
    assert any(argv[3:5] == ["volume", "ls"] for argv, _ in calls)
    assert all(argv[:3] == ["docker", "--context", "reviewed-desktop"] for argv, _ in calls)
    for index, (argv, _) in enumerate(calls):
        mutating = argv[3] in {"pull", "run"} or argv[3:5] in (
            ["volume", "create"],
            ["compose", "up"],
        )
        if mutating:
            assert index > 0 and calls[index - 1][0][3] == "info"
    assert all(call[1].get("shell", False) is False for call in calls)
    assert all(call[1].get("timeout", 0) > 0 for call in calls)


def test_missing_authority_never_issues_mutation(tmp_path: Path):
    state = runtime_state(tmp_path, authorized=False)
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not any("up" in argv for argv, _ in calls)


@pytest.mark.parametrize(
    "observation",
    [
        {"ID": "another-daemon"},
        {"OSType": "windows"},
        {"Architecture": "x86_64"},
        {"Swarm": {"LocalNodeState": "active"}},
        {"Swarm": {}},
        {"ID": ""},
    ],
)
def test_wrong_or_unsafe_current_engine_fails_before_mutation(tmp_path: Path, observation):
    state = runtime_state(tmp_path)
    run, calls = runner(observation)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not any("up" in argv for argv, _ in calls)


@pytest.mark.parametrize(
    "args",
    [
        ("container", "rm", "foreign-container"),
        ("volume", "prune", "-f"),
        ("system", "prune", "-af"),
        ("swarm", "init"),
        ("context", "use", "another-context"),
    ],
)
def test_raw_command_cannot_disguise_unreviewed_mutation_as_read_only(tmp_path: Path, args):
    state = runtime_state(tmp_path)
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command(*args)
    assert not any(argv[3:] == list(args) for argv, _ in calls)


def test_inherited_docker_environment_cannot_retarget_bound_command(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://unreviewed.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "unreviewed-context")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "0")
    state = runtime_state(tmp_path)
    run, calls = runner()
    DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert calls
    for _, kwargs in calls:
        env = kwargs["env"]
        assert (
            "DOCKER_HOST" not in env
            and "DOCKER_CONTEXT" not in env
            and "DOCKER_TLS_VERIFY" not in env
        )


def test_subprocess_failure_does_not_echo_private_stderr(tmp_path: Path):
    state = runtime_state(tmp_path)
    secret = "SYNTHETIC_DAEMON_PRIVATE_OUTPUT"

    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=secret, stderr=secret)

    with pytest.raises(ValueError) as caught:
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"context": "--host"},
        {"context": "bad\ncontext"},
        {"context": ""},
        {"engine_id": ""},
        {"architecture": "unreviewed"},
        {"authorized": "true"},
    ],
)
def test_invalid_manifest_never_issues_lifecycle_command(tmp_path: Path, changes):
    state = runtime_state(tmp_path, **changes)
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not any("up" in argv for argv, _ in calls)


@pytest.mark.parametrize(
    "inventory",
    [
        images() | {"app": "registry.invalid/app:latest"},
        {name: value for name, value in images().items() if name != "app"},
        images() | {"sensor": "sha256:" + "a" * 64},
    ],
)
def test_unreviewed_image_inventory_cannot_reach_any_mutation(tmp_path: Path, inventory):
    state = runtime_state(tmp_path, images=inventory)
    run, calls = runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d", mutate=True)
    assert not any("up" in argv or "pull" in argv or "run" in argv for argv, _ in calls)


def owned_inventory_runner(*, foreign=False, malformed=False):
    calls = []
    owned_id, other_id = "a" * 64, "b" * 64

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        args = argv[3:]
        if args[0] == "info":
            output = json.dumps(
                {
                    "ID": ENGINE,
                    "OSType": "linux",
                    "Architecture": "aarch64",
                    "Swarm": {"LocalNodeState": "inactive"},
                }
            )
        elif args[:2] == ["ps", "-aq"]:
            output = "not-an-id" if malformed else owned_id + ("\n" + other_id if foreign else "")
        elif args[0] == "inspect":
            output = json.dumps(
                {
                    "responseforge.project": "unrelated"
                    if args[-1] == other_id
                    else "responseforge-rf04"
                }
            )
        elif args[:2] == ["rm", "-f"]:
            output = args[-1]
        else:
            raise AssertionError("Unexpected command " + str(args))
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    return run, calls


def test_down_removes_only_verified_owned_ids_and_preserves_volumes(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = owned_inventory_runner()
    DockerRuntime(state, run=run).down()
    removals = [argv[3:] for argv, _ in calls if argv[3:5] == ["rm", "-f"]]
    assert removals == [["rm", "-f", "a" * 64]]
    assert not any("prune" in argv or "volume" in argv or "down" in argv for argv, _ in calls)
    assert sum("info" in argv for argv, _ in calls) >= len(removals) + 1


def test_down_rechecks_labels_instead_of_trusting_enumeration(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = owned_inventory_runner(foreign=True)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).down()
    assert not any(argv[3:] == ["rm", "-f", "b" * 64] for argv, _ in calls)


def test_down_rejects_malformed_container_inventory_before_removal(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = owned_inventory_runner(malformed=True)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).down()
    assert not any(argv[3:5] == ["rm", "-f"] for argv, _ in calls)


def test_changed_local_build_proof_cannot_start_or_seed(tmp_path: Path):
    state = runtime_state(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "info" in argv:
            output = json.dumps(
                {
                    "ID": ENGINE,
                    "OSType": "linux",
                    "Architecture": "aarch64",
                    "Swarm": {"LocalNodeState": "inactive"},
                }
            )
        else:
            output = "sha256:" + "0" * 64
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).up()
    assert not any(
        "pull" in argv or "run" in argv or "up" in argv or argv[3:5] == ["volume", "create"]
        for argv, _ in calls
    )


def lifecycle_runner(*, foreign_container=False, foreign_volume=False, bad_image=False):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        args = argv[3:]
        if args[0] == "info":
            output = json.dumps(
                {
                    "ID": ENGINE,
                    "OSType": "linux",
                    "Architecture": "aarch64",
                    "Swarm": {"LocalNodeState": "inactive"},
                }
            )
        elif args[:2] == ["image", "inspect"]:
            output = "sha256:" + "0" * 64 if bad_image else args[-1]
        elif args[:2] == ["ps", "-a"]:
            output = "responseforge-rf04-core" if foreign_container else ""
        elif args[:2] == ["volume", "ls"]:
            output = "responseforge-rf04-callback" if foreign_volume else ""
        elif args[0] in {"inspect", "container", "volume"} and "inspect" in args:
            output = json.dumps({"responseforge.project": "another-project"})
        else:
            output = "operation-complete"
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    return run, calls


def mutation_calls(calls):
    return [
        argv[3:]
        for argv, _ in calls
        if argv[3] in {"pull", "run", "rm"}
        or argv[3:5] in (["compose", "up"], ["volume", "create"])
    ]


def test_public_up_command_does_not_bypass_foreign_resource_proof(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = lifecycle_runner(foreign_container=True)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d")
    assert mutation_calls(calls) == []


def test_public_up_command_does_not_bypass_source_build_proof(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = lifecycle_runner(bad_image=True)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "up", "-d")
    assert mutation_calls(calls) == []


def test_direct_seed_rejects_foreign_named_volume_before_any_writes(tmp_path: Path):
    state = runtime_state(tmp_path)
    run, calls = lifecycle_runner(foreign_volume=True)
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).seed()
    assert mutation_calls(calls) == []


def test_changed_compose_cannot_enable_unreviewed_privilege_or_host_mounts(tmp_path: Path):
    state = runtime_state(tmp_path)
    path = state / "compose.json"
    altered = json.loads(path.read_text())
    altered["services"]["core"]["privileged"] = True
    altered["services"]["core"]["volumes"].append("/:/developer-host")
    path.write_text(json.dumps(altered))
    run, calls = lifecycle_runner()
    with pytest.raises(ValueError):
        DockerRuntime(state, run=run).command("compose", "restart", "core")
    assert not any(argv[3:5] == ["compose", "restart"] for argv, _ in calls)
