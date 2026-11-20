"""Original offline control-plane vectors; never native Docker/image proof."""

import base64
import hashlib
import json
import re
from dataclasses import asdict, replace
from datetime import datetime, timedelta

import pytest

from responseforge.integrations.wazuh.image_qualification import (
    CODE_FILES,
    MATERIALS,
    ROOT,
    EngineTarget,
    execute_run,
    load_image_policy,
    prepare_run,
    recover_run,
)
from responseforge.integrations.wazuh.security import PreparationError


def digest(value):
    return hashlib.sha256(value).hexdigest()


def inputs(tmp_path):
    raw = b"// Original synthetic corrected client; not vendor bytes\n"
    source = {
        name: ("Original synthetic data for " + name + "\n").encode()
        for name in load_image_policy().source_hashes
    }
    policy = replace(
        load_image_policy(),
        client_sha256=digest(raw),
        source_hashes={name: digest(value) for name, value in source.items()},
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700)
    (bundle / "build-context").mkdir(mode=0o700)
    (bundle / "patched").mkdir(mode=0o700)
    dockerfile = (
        "FROM "
        + policy.parent_ref
        + "\nCOPY --chown=1000:1000 --chmod=0644 server-api-client.js "
        + policy.client_path
        + "\n"
    ).encode()
    for path, value in [
        (bundle / "build-context/Dockerfile", dockerfile),
        (bundle / "build-context/server-api-client.js", raw),
        (bundle / "patched/server-api-client.js", raw),
    ]:
        path.write_bytes(value)
        path.chmod(0o600)
    files = {name: (ROOT / relative).read_bytes() for name, relative in CODE_FILES.items()}
    files.update(source)
    files.update(
        {
            "materials/"
            + name: b"-----BEGIN SYNTHETIC-----\noriginal fixture data\n-----END SYNTHETIC-----\n"
            for name in MATERIALS
        }
    )
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "files": {name: base64.b64encode(value).decode() for name, value in files.items()},
                "material_generator": "original synthetic fixture",
            }
        )
    )
    fixture.chmod(0o600)
    target = EngineTarget(
        "synthetic-local", "unix:///tmp/original-synthetic.sock", "synthetic-engine"
    )
    return policy, bundle, fixture, target, dockerfile


def test_valid_private_preparation_does_not_execute_docker(tmp_path):
    policy, bundle, fixture, target, dockerfile = inputs(tmp_path)
    output = tmp_path / "prepared"
    assert prepare_run(bundle, fixture, output, target, policy) == output
    assert (output / "context/Dockerfile").read_bytes() == dockerfile
    assert output.stat().st_mode & 0o077 == 0
    assert (output / "plan.json").is_file()
    assert not (output / "execution.json").exists()


def fixture_value(path):
    return json.loads(path.read_text())


def save_fixture(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_plan_binds_target_context_source_input_and_unique_owner_identity(tmp_path):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    first, second = tmp_path / "first", tmp_path / "second"
    prepare_run(bundle, fixture, first, target, policy)
    prepare_run(bundle, fixture, second, target, policy)
    one, two = fixture_value(first / "plan.json"), fixture_value(second / "plan.json")
    assert one["schema_version"] == "1.0"
    assert re.fullmatch(r"[0-9a-f]{32}", one["run_id"])
    assert re.fullmatch(r"[0-9a-f]{64}", one["nonce"])
    assert one["run_id"] != two["run_id"] and one["nonce"] != two["nonce"]
    assert one["target"] == asdict(target)
    for name in ["source_fingerprint", "policy_fingerprint"]:
        assert re.fullmatch(r"[0-9a-f]{64}", one[name])
    assert one["labels"] == {
        "io.responseforge.work": "rf07c4",
        "io.responseforge.run": one["run_id"],
        "io.responseforge.source": one["source_fingerprint"],
    }
    assert one["image_tag"] == "responseforge/rf07-dashboard-tls:" + one["run_id"]
    assert one["container_name"] == "rf07c4-" + one["run_id"]
    assert set(one["files"]) == {
        "context/Dockerfile",
        "context/server-api-client.js",
        "fixture.json",
        "bootstrap.cjs",
    }
    assert all(
        digest((first / name).read_bytes()) == expected for name, expected in one["files"].items()
    )
    created = datetime.fromisoformat(one["created_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(one["expires_at"].replace("Z", "+00:00"))
    assert created.utcoffset() == timedelta(0) and expires - created == timedelta(hours=24)
    assert not (first / "execution.json").exists()
    assert set(p.name for p in (first / "context").iterdir()) == {
        "Dockerfile",
        "server-api-client.js",
    }
    assert all(p.stat().st_mode & 0o077 == 0 for p in first.rglob("*") if p.is_file())


@pytest.mark.parametrize(
    "change", ["recipe", "context-client", "patched-client", "linked-context", "hardlinked-context"]
)
def test_changed_or_unsafe_context_refuses_without_publishing(tmp_path, change):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    path = bundle / (
        "build-context/Dockerfile"
        if change == "recipe"
        else "patched/server-api-client.js"
        if change == "patched-client"
        else "build-context/server-api-client.js"
    )
    if change in {"linked-context", "hardlinked-context"}:
        path.unlink()
        outside = tmp_path / "original-retained"
        outside.write_bytes(b"original retained material")
        outside.chmod(0o600)
        if change == "linked-context":
            path.symlink_to(outside)
        else:
            path.hardlink_to(outside)
    else:
        path.write_bytes(path.read_bytes() + b"\nRUN unreviewed-data-command\n")
    with pytest.raises(PreparationError):
        prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "change",
    [
        "extra-file",
        "missing-code",
        "changed-code",
        "changed-source",
        "invalid-base64",
        "bad-material",
        "oversized-material",
        "bad-schema",
        "extra-field",
    ],
)
def test_fixture_is_data_of_exact_reviewed_files_not_an_arbitrary_program(tmp_path, change):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    value = fixture_value(fixture)
    code = next(iter(CODE_FILES))
    if change == "extra-file":
        value["files"]["runner/arbitrary.cjs"] = base64.b64encode(
            b"throw new Error('unreviewed');"
        ).decode()
    elif change == "missing-code":
        value["files"].pop(code)
    elif change == "changed-code":
        value["files"][code] = base64.b64encode(b"// unreviewed executable\n").decode()
    elif change == "changed-source":
        value["files"][next(iter(policy.source_hashes))] = base64.b64encode(
            b"changed source"
        ).decode()
    elif change == "invalid-base64":
        value["files"][code] = "not@valid@base64"
    elif change == "bad-material":
        value["files"]["materials/good.key"] = base64.b64encode(
            b"unreviewed executable data"
        ).decode()
    elif change == "oversized-material":
        value["files"]["materials/good.key"] = base64.b64encode(
            b"-----BEGIN SYNTHETIC-----" + b"x" * 16385
        ).decode()
    elif change == "bad-schema":
        value["schema_version"] = "other"
    else:
        value["unexpected"] = "not an execution authority"
    save_fixture(fixture, value)
    with pytest.raises(PreparationError):
        prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "kind",
    ["symlink", "hardlink", "world-write", "fifo", "malformed-json", "duplicate-json", "too-large"],
)
def test_unsafe_fixture_is_refused_before_publication(tmp_path, kind):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    if kind in {"symlink", "hardlink"}:
        retained = tmp_path / "retained-fixture.json"
        fixture.rename(retained)
        if kind == "symlink":
            fixture.symlink_to(retained)
        else:
            fixture.hardlink_to(retained)
    elif kind == "world-write":
        fixture.chmod(0o666)
    elif kind == "fifo":
        import os

        fixture.unlink()
        os.mkfifo(fixture)
    elif kind == "malformed-json":
        fixture.write_bytes(b"not JSON ORIGINAL_PRIVATE_INPUT")
    elif kind == "duplicate-json":
        fixture.write_bytes(
            b'{"schema_version":"1.0","schema_version":"1.0","files":{},"material_generator":"synthetic"}'
        )
    else:
        fixture.write_bytes(b"x" * (2097152 + 1))
    with pytest.raises(PreparationError) as error:
        prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    assert "ORIGINAL_PRIVATE_INPUT" not in str(error.value)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("context", "--host=unreviewed"),
        ("context", "two words"),
        ("endpoint", "tcp://unreviewed.invalid:2375"),
        ("endpoint", "unix:///tmp/../unreviewed.sock"),
        ("engine_id", ""),
    ],
)
def test_invalid_target_cannot_redirect_operations(tmp_path, field, value):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    with pytest.raises(PreparationError):
        prepare_run(bundle, fixture, tmp_path / "out", replace(target, **{field: value}), policy)
    assert not (tmp_path / "out").exists()


def test_existing_output_is_preserved(tmp_path):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    (output / "retained").write_bytes(b"original preserved")
    with pytest.raises(PreparationError):
        prepare_run(bundle, fixture, output, target, policy)
    assert set(p.name for p in output.iterdir()) == {"retained"}
    assert (output / "retained").read_bytes() == b"original preserved"


class NoCommands:
    def run(self, *args, **kwargs):
        pytest.fail("execution without literal permission called Docker")


@pytest.mark.parametrize(
    "build,fixture",
    [
        (False, False),
        (True, False),
        (False, True),
        ("true", True),
        (1, True),
        (True, "true"),
        (True, 1),
        (None, True),
    ],
)
def test_execution_needs_both_literal_acknowledgements_before_commands(tmp_path, build, fixture):
    policy, bundle, fixture_path, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture_path, tmp_path / "out", target, policy)
    before = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    try:
        result = execute_run(
            output,
            allow_image_build=build,
            allow_isolated_fixture=fixture,
            runner=NoCommands(),
            policy=policy,
        )
    except PreparationError:
        pass
    else:
        assert result.get("qualified") is False
    after = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    assert after == before


def test_recovery_needs_literal_cleanup_acknowledgement(tmp_path):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    try:
        result = recover_run(output, runner=NoCommands(), policy=policy)
    except PreparationError:
        pass
    else:
        assert result.get("qualified") is False
    assert not (output / "execution.json").exists()


class ReadOnlyEngine:
    """Original structured observations, with no actual daemon transport."""

    def __init__(self, target, *, endpoint=None, info_change=None, malformed=None):
        self.target = target
        self.endpoint = endpoint if endpoint is not None else target.endpoint
        self.info = {
            "ID": target.engine_id,
            "Architecture": "aarch64",
            "MemTotal": 8318844928,
            "NCPU": 15,
            "Swarm": {"LocalNodeState": "inactive"},
        }
        if info_change:
            self.info.update(info_change)
        self.malformed = malformed
        self.commands = []

    def run(self, argv, input_data=b"", timeout=120, max_output=1048576):
        from responseforge.integrations.wazuh.process_runner import ProcessResult

        command = list(argv)
        self.commands.append(command)
        assert command[command.index("--context") + 1] == self.target.context
        rest = command[command.index("--context") + 2 :]
        if rest[:2] == ["context", "inspect"]:
            if self.malformed == "context-status":
                return ProcessResult(1, b"", b"original synthetic denied query")
            data = {"Endpoints": {"docker": {"Host": self.endpoint}}}
        elif rest[:1] == ["info"]:
            if self.malformed == "info-status":
                return ProcessResult(1, b"", b"original synthetic denied query")
            data = self.info
        else:
            pytest.fail("Read-only preflight attempted Docker mutation: " + repr(rest))
        if self.malformed == "json":
            return ProcessResult(0, b"not JSON ORIGINAL_PRIVATE_DIAGNOSTIC", b"")
        return ProcessResult(0, json.dumps(data).encode(), b"")


def test_readonly_preflight_uses_bound_target_without_native_claim(tmp_path):
    from responseforge.integrations.wazuh.image_qualification import preflight_run

    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    runner = ReadOnlyEngine(target)
    result = preflight_run(output, runner, policy)
    assert isinstance(result, dict) and result.get("qualified") is not True
    assert len(runner.commands) == 2
    assert not (output / "execution.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"ID": "different-engine"},
        {"Architecture": "amd64"},
        {"MemTotal": 0},
        {"NCPU": 0},
        {"Swarm": {"LocalNodeState": "active"}},
        {"Swarm": {"LocalNodeState": "pending"}},
    ],
)
def test_readonly_preflight_refuses_engine_mismatch_without_mutating(tmp_path, change):
    from responseforge.integrations.wazuh.image_qualification import preflight_run

    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    runner = ReadOnlyEngine(target, info_change=change)
    with pytest.raises(PreparationError):
        preflight_run(output, runner, policy)
    assert len(runner.commands) <= 2 and not (output / "execution.json").exists()


def test_readonly_context_endpoint_refused_before_daemon_info(tmp_path):
    from responseforge.integrations.wazuh.image_qualification import preflight_run

    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    runner = ReadOnlyEngine(target, endpoint="tcp://unreviewed.invalid:2375")
    with pytest.raises(PreparationError):
        preflight_run(output, runner, policy)
    assert len(runner.commands) == 1
    assert not (output / "execution.json").exists()


@pytest.mark.parametrize("bad", ["context-status", "info-status", "json"])
def test_readonly_preflight_does_not_relabel_failure_as_resource_absence(tmp_path, bad):
    from responseforge.integrations.wazuh.image_qualification import preflight_run

    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    runner = ReadOnlyEngine(target, malformed=bad)
    with pytest.raises(PreparationError) as error:
        preflight_run(output, runner, policy)
    assert "ORIGINAL_PRIVATE_DIAGNOSTIC" not in str(error.value)
    assert not (output / "execution.json").exists()


class RecoveryEngine(ReadOnlyEngine):
    def __init__(self, target, container):
        super().__init__(target)
        self.container = container
        self.removed = False
        self.mutations = []

    def run(self, argv, input_data=b"", timeout=120, max_output=1048576):
        from responseforge.integrations.wazuh.process_runner import ProcessResult

        command = list(argv)
        rest = command[command.index("--context") + 2 :]
        if rest[:2] == ["container", "inspect"]:
            self.commands.append(command)
            return ProcessResult(0, json.dumps(self.container).encode(), b"")
        if rest[:1] in [["stop"], ["rm"]]:
            self.commands.append(command)
            self.mutations.append(rest)
            if rest[0] == "stop":
                self.container["State"]["Running"] = False
            else:
                self.removed = True
            return ProcessResult(0, (self.container["Id"] + "\n").encode(), b"")
        if rest[:2] == ["container", "ls"]:
            self.commands.append(command)
            return ProcessResult(0, b"" if self.removed else self.container["Id"].encode(), b"")
        return super().run(argv, input_data, timeout, max_output)


def reserved_packet(tmp_path, *, recorded_cid=True):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    plan = fixture_value(output / "plan.json")
    image, cid = "sha256:" + "a" * 64, "b" * 64
    records = {
        "execution.json": {
            "run_id": plan["run_id"],
            "source": plan["source_fingerprint"],
            "native_adapter": False,
            "phase": "RESERVED",
            "qualified": False,
        },
        "image.json": {"id": image, "native_adapter": False},
        "container-intent.json": {
            "name": plan["container_name"],
            "image_id": image,
            "labels": plan["labels"],
            "input_sha256": "c" * 64,
        },
    }
    if recorded_cid:
        records["container.json"] = {"id": cid, "image_id": image}
    for name, value in records.items():
        save_fixture(output / name, value)
    container = {
        "Id": cid,
        "Name": "/" + plan["container_name"],
        "Image": image,
        "Config": {"Labels": dict(plan["labels"])},
        "State": {"Running": False, "ExitCode": 0},
    }
    return policy, output, target, plan, container


def test_recovery_cleans_exact_persisted_resource_without_start_or_qualification(tmp_path):
    policy, output, target, _, container = reserved_packet(tmp_path)
    runner = RecoveryEngine(target, container)
    result = recover_run(output, allow_owned_cleanup=True, runner=runner, policy=policy)
    assert result["qualified"] is False and result["cleanup_verified"] is True
    assert runner.removed
    assert all(m[0] in {"stop", "rm"} for m in runner.mutations)
    assert not (output / "proof.json").exists()


def test_recovery_reconciles_reserved_name_if_create_reply_was_lost(tmp_path):
    policy, output, target, _, container = reserved_packet(tmp_path, recorded_cid=False)
    runner = RecoveryEngine(target, container)
    result = recover_run(output, allow_owned_cleanup=True, runner=runner, policy=policy)
    assert result["qualified"] is False and runner.removed


@pytest.mark.parametrize(
    "change", ["cid", "name", "image", "work-label", "run-label", "source-label"]
)
def test_recovery_never_deletes_foreign_resource_even_with_a_matching_prefix(tmp_path, change):
    policy, output, target, _, container = reserved_packet(tmp_path)
    if change == "cid":
        container["Id"] = "d" * 64
    elif change == "name":
        container["Name"] += "-foreign"
    elif change == "image":
        container["Image"] = "sha256:" + "d" * 64
    else:
        key = {
            "work-label": "io.responseforge.work",
            "run-label": "io.responseforge.run",
            "source-label": "io.responseforge.source",
        }[change]
        container["Config"]["Labels"][key] = "foreign"
    runner = RecoveryEngine(target, container)
    with pytest.raises(PreparationError):
        recover_run(output, allow_owned_cleanup=True, runner=runner, policy=policy)
    assert not runner.mutations and not runner.removed


@pytest.mark.parametrize("field", ["run_id", "source"])
def test_recovery_reservation_must_belong_to_this_plan(tmp_path, field):
    policy, output, target, _, container = reserved_packet(tmp_path)
    marker = fixture_value(output / "execution.json")
    marker[field] = "foreign-reservation"
    save_fixture(output / "execution.json", marker)
    runner = RecoveryEngine(target, container)
    with pytest.raises(PreparationError):
        recover_run(output, allow_owned_cleanup=True, runner=runner, policy=policy)
    assert not runner.mutations


EXPECTED_CASES = {
    "original_insecure_baseline",
    "trusted_CA_matching_SAN",
    "missing_CA",
    "different_CA",
    "untrusted_chain",
    "wrong_SAN",
    "environment_TLS_zero",
    "plain_HTTP",
    "URL_credentials",
    "URL_control",
    "HTTPS_redirect",
    "HTTP_redirect",
    "hostile_proxy",
}
EXPECTED_LISTENERS = {
    "good",
    "untrusted",
    "wrongname",
    "plain",
    "proxy",
    "redirectHTTPS",
    "redirectHTTP",
}


def synthetic_native_shaped_proof(plan, policy, image, stdin):
    """Expected protocol observations from the independently frozen case matrix."""
    body = json.loads(stdin)
    proof = {
        "schema_version": "1.0",
        "passed": True,
        "qualification_run_id": plan["run_id"],
        "qualification_nonce": plan["nonce"],
        "fixture_input_sha256": digest(stdin),
        "image_id": image,
        "node_executable_sha256": policy.node_sha256,
        "node_license_sha256": policy.node_license_sha256,
        "platform": "linux",
        "architecture": "arm64",
        "uid": 1000,
        "gid": 1000,
        "installed_corrected_module": policy.client_path,
        "packaged_corrected_sha256": policy.client_sha256,
        "selected_files": 297,
        "module_resolution_guard": True,
        "parent_artifact_execution": False,
        "dashboard_started": False,
        "manager_started": False,
        "node": "v18.19.0",
    }
    for key, file in [
        ("harness_sha256", "runner/wazuh-tls/qualify.cjs"),
        ("wrapper_sha256", "runner/wazuh-image/qualify.cjs"),
    ]:
        proof[key] = digest(base64.b64decode(body["files"][file]))
    cases = {
        "original_insecure_baseline": {
            "loaded": True,
            "authHTTP": 1,
            "requestHTTP": 1,
            "module_guard": True,
            "outside_module_resolutions": 0,
            "secure_assertion": "FAIL: untrusted certificate accepted",
        }
    }
    for name in EXPECTED_CASES - {"original_insecure_baseline"}:
        success = name in {"trusted_CA_matching_SAN", "hostile_proxy"}
        redirect = name in {"HTTPS_redirect", "HTTP_redirect"}
        policy_refusal = name in {"plain_HTTP", "URL_credentials", "URL_control"}
        method = {"success": success}
        if success:
            method["valid"] = True
        elif redirect:
            method["status"] = 302
        elif policy_refusal:
            method["policy"] = True
        else:
            method["code"] = (
                "ERR_TLS_CERT_ALTNAME_INVALID"
                if name == "wrong_SAN"
                else "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
            )
        listener = (
            "good"
            if success
            else "redirectHTTPS"
            if name == "HTTPS_redirect"
            else "redirectHTTP"
            if redirect
            else None
        )
        delta = {
            key: {"auth": int(key == listener), "request": int(key == listener), "badIdentity": 0}
            for key in EXPECTED_LISTENERS
        }
        cases[name] = {
            "result": {
                "loaded": True,
                "axios": "1.18.1",
                "module_guard": True,
                "outside_module_resolutions": 0,
                "authenticate": dict(method),
                "request": dict(method),
            },
            "delta": delta,
        }
    proof["scenarios"] = cases
    return proof


class SyntheticDocker(RecoveryEngine):
    """Never invokes Docker. A complete fake flow must remain unqualified."""

    def __init__(
        self,
        target,
        policy,
        plan,
        run_dir,
        *,
        mutate_parent=None,
        mutate_derived=None,
        mutate_container=None,
        mutate_proof=None,
        fault=None,
    ):
        super().__init__(target, {})
        self.policy, self.plan, self.run_dir = policy, plan, run_dir
        self.image, self.cid = "sha256:" + "a" * 64, "b" * 64
        self.mutate_parent, self.mutate_derived = mutate_parent, mutate_derived
        self.mutate_container, self.mutate_proof, self.fault = mutate_container, mutate_proof, fault
        self.created = False
        self.started = False
        self.running = False
        self.stdin = None

    def image_info(self, derived):
        import copy

        config = copy.deepcopy(self.policy.config)
        config["Env"] = ["RF07C4_SYNTHETIC=value"]
        config["Labels"] = dict(self.plan["labels"]) if derived else None
        data = {
            "Id": self.image if derived else self.policy.parent_id,
            "Os": "linux",
            "Architecture": "arm64",
            "RootFS": {
                "Layers": list(self.policy.rootfs) + (["sha256:" + "d" * 64] if derived else [])
            },
            "Config": config,
        }
        mutate = self.mutate_derived if derived else self.mutate_parent
        if mutate:
            mutate(data)
        return data

    def container_info(self):
        from responseforge.integrations.wazuh.image_qualification import TMPFS

        data = {
            "Id": self.cid,
            "Name": "/" + self.plan["container_name"],
            "Image": self.image,
            "Config": {
                "Labels": dict(self.plan["labels"]),
                "Entrypoint": [self.policy.node_path],
                "Cmd": ["-e", (self.run_dir / "bootstrap.cjs").read_text()],
                "User": "1000:1000",
                "WorkingDir": "/tmp",
                "Tty": False,
                "Healthcheck": {"Test": ["NONE"]},
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "Memory": 1073741824,
                "NanoCpus": 2000000000,
                "PidsLimit": 128,
                "SecurityOpt": ["no-new-privileges"],
                "Binds": None,
                "PortBindings": None,
                "PublishAllPorts": False,
                "Devices": None,
                "DeviceRequests": None,
                "DeviceCgroupRules": None,
                "VolumesFrom": None,
                "Links": None,
                "ExtraHosts": None,
                "PidMode": "",
                "UTSMode": "",
                "UsernsMode": "",
                "IpcMode": "private",
                "CgroupnsMode": "private",
                "AutoRemove": False,
                "Tmpfs": {"/tmp": TMPFS},
            },
            "Mounts": [],
            "NetworkSettings": {"Ports": {"443/tcp": None}},
            "State": {
                "Running": self.running,
                "ExitCode": 7 if self.fault == "exit" and self.started else 0,
                "OOMKilled": self.fault == "oom" and self.started,
                "Error": "",
            },
        }
        if self.mutate_container:
            self.mutate_container(data)
        return data

    def run(self, argv, input_data=b"", timeout=120, max_output=1048576):
        from responseforge.integrations.wazuh.process_runner import ProcessFailure, ProcessResult

        command = list(argv)
        rest = command[command.index("--context") + 2 :]
        if rest[:1] == ["pull"]:
            self.commands.append(command)
            self.mutations.append(rest)
            if self.fault == "pull":
                return ProcessResult(1, b"", b"original synthetic pull failure")
            return ProcessResult(0, self.policy.parent_ref.encode(), b"")
        if rest[:2] == ["image", "inspect"]:
            self.commands.append(command)
            return ProcessResult(
                0, json.dumps(self.image_info(rest[2] != self.policy.parent_ref)).encode(), b""
            )
        if rest[:1] == ["build"]:
            self.commands.append(command)
            self.mutations.append(rest)
            if self.fault == "build-timeout":
                raise ProcessFailure("timeout", b"original partial build observation", b"")
            from pathlib import Path

            iid = Path(rest[rest.index("--iidfile") + 1])
            iid.write_text(self.image + "\n")
            iid.chmod(0o600)
            return ProcessResult(0, b"original synthetic build observation", b"")
        if rest[:1] == ["create"]:
            self.commands.append(command)
            self.mutations.append(rest)
            self.created = True
            self.container = self.container_info()
            if self.fault == "create-timeout":
                raise ProcessFailure("timeout", b"", b"original lost create reply")
            return ProcessResult(0, (self.cid + "\n").encode(), b"")
        if rest[:2] == ["container", "inspect"]:
            self.container = self.container_info()
        if rest[:1] == ["start"]:
            self.commands.append(command)
            self.mutations.append(rest)
            self.started = True
            self.stdin = input_data
            if self.fault == "start-timeout":
                self.running = True
                self.container = self.container_info()
                raise ProcessFailure("timeout", b"original incomplete native output", b"")
            proof = synthetic_native_shaped_proof(self.plan, self.policy, self.image, input_data)
            if self.mutate_proof:
                self.mutate_proof(proof)
            return ProcessResult(0, json.dumps(proof).encode(), b"")
        if rest[:1] == ["stop"]:
            self.running = False
        if rest[:1] == ["rm"] and self.fault == "cleanup":
            self.commands.append(command)
            self.mutations.append(rest)
            return ProcessResult(1, b"", b"original cleanup failure")
        return super().run(argv, input_data, timeout, max_output)


def executable_packet(tmp_path, **options):
    policy, bundle, fixture, target, _ = inputs(tmp_path)
    env_hash = digest(
        json.dumps(["RF07C4_SYNTHETIC=value"], sort_keys=True, separators=(",", ":")).encode()
    )
    policy = replace(policy, env_sha256=env_hash)
    output = prepare_run(bundle, fixture, tmp_path / "out", target, policy)
    plan = fixture_value(output / "plan.json")
    return policy, output, plan, SyntheticDocker(target, policy, plan, output, **options)


def run_control(tmp_path, **options):
    policy, output, plan, runner = executable_packet(tmp_path, **options)
    report = execute_run(
        output, allow_image_build=True, allow_isolated_fixture=True, runner=runner, policy=policy
    )
    return policy, output, plan, runner, report


def test_complete_test_double_flow_validates_controls_but_never_qualifies_native_image(tmp_path):
    _, output, plan, runner, report = run_control(tmp_path)
    assert report["phase"] == "COMPLETE" and report["qualified"] is False
    assert (
        report["native_adapter"] is False
        and report["image_built"] is False
        and report["image_executed"] is False
    )
    assert report["cleanup_verified"] is True and runner.removed
    assert (
        report["dashboard_started"] is False
        and report["manager_started"] is False
        and report["live_endpoint_verified"] is False
    )
    assert (output / "execution.json").is_file() and (output / "proof.json").is_file()
    assert json.loads(runner.stdin)["session"] == {
        "run_id": plan["run_id"],
        "nonce": plan["nonce"],
        "image_id": runner.image,
    }
    operations = [c[c.index("--context") + 2 :] for c in runner.commands]
    create = next(c for c in operations if c[0] == "create")
    for flag, value in [
        ("--entrypoint", "/usr/share/wazuh-dashboard/node/bin/node"),
        ("--user", "1000:1000"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--memory", "1073741824"),
        ("--cpus", "2"),
        ("--pids-limit", "128"),
        ("--ipc", "private"),
        ("--cgroupns", "private"),
    ]:
        assert create[create.index(flag) + 1] == value
    assert {"--read-only", "--interactive", "--no-healthcheck"} <= set(create)
    assert not set(create) & {
        "--privileged",
        "--publish",
        "--publish-all",
        "-p",
        "-P",
        "--volume",
        "-v",
        "--mount",
        "--device",
        "--volumes-from",
    }
    build = next(c for c in operations if c[0] == "build")
    assert {"--pull=false", "--network=none", "--platform=linux/arm64"} <= set(build)
    assert not any(c[0] in {"run", "exec", "push", "prune"} for c in operations)
    create_i = next(i for i, c in enumerate(operations) if c[0] == "create")
    start_i = next(i for i, c in enumerate(operations) if c[0] == "start")
    assert any(c[:2] == ["container", "inspect"] for c in operations[create_i + 1 : start_i])


def changed_top(field, value):
    return lambda proof: proof.__setitem__(field, value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("passed", 1),
        ("qualification_run_id", "foreign"),
        ("qualification_nonce", "foreign"),
        ("fixture_input_sha256", "f" * 64),
        ("image_id", "sha256:" + "f" * 64),
        ("node_executable_sha256", "f" * 64),
        ("node_license_sha256", "f" * 64),
        ("platform", "darwin"),
        ("architecture", "amd64"),
        ("uid", 0),
        ("gid", 0),
        ("installed_corrected_module", "/tmp/substitute.js"),
        ("packaged_corrected_sha256", "f" * 64),
        ("selected_files", 296),
        ("module_resolution_guard", False),
        ("parent_artifact_execution", True),
        ("dashboard_started", True),
        ("manager_started", True),
        ("harness_sha256", "f" * 64),
        ("wrapper_sha256", "f" * 64),
        ("node", "unobserved"),
    ],
)
def test_native_shaped_proof_identity_is_not_a_passed_true_shortcut(tmp_path, field, value):
    policy, output, _, runner = executable_packet(tmp_path, mutate_proof=changed_top(field, value))
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.removed
    assert fixture_value(output / "failure.json")["qualified"] is False
    assert not (output / "result.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "missing-case",
        "extra-case",
        "baseline-no-http",
        "baseline-not-guarded",
        "generic-failure",
        "not-loaded",
        "outside-module",
        "wrong-axios",
        "bad-identity",
        "unexpected-http",
        "redirect-target",
        "wrong-redirect-status",
        "proxy-contact",
        "missing-listener",
        "boolean-counter",
    ],
)
def test_each_named_native_observation_is_required(tmp_path, change):
    def mutate(proof):
        cases = proof["scenarios"]
        if change == "missing-case":
            cases.pop("missing_CA")
        elif change == "extra-case":
            cases["unexpected-skipped"] = {"skipped": True}
        elif change == "baseline-no-http":
            cases["original_insecure_baseline"]["authHTTP"] = 0
        elif change == "baseline-not-guarded":
            cases["original_insecure_baseline"]["module_guard"] = False
        elif change == "generic-failure":
            cases["missing_CA"]["result"]["request"]["code"] = "UNRELATED_TYPE_ERROR"
        elif change == "not-loaded":
            cases["missing_CA"]["result"]["loaded"] = False
        elif change == "outside-module":
            cases["missing_CA"]["result"]["outside_module_resolutions"] = 1
        elif change == "wrong-axios":
            cases["missing_CA"]["result"]["axios"] = "host-substitute"
        elif change == "bad-identity":
            cases["trusted_CA_matching_SAN"]["delta"]["good"]["badIdentity"] = 1
        elif change == "unexpected-http":
            cases["missing_CA"]["delta"]["good"]["auth"] = 1
        elif change == "redirect-target":
            cases["HTTPS_redirect"]["delta"]["good"]["request"] = 1
        elif change == "wrong-redirect-status":
            cases["HTTPS_redirect"]["result"]["request"]["status"] = 200
        elif change == "proxy-contact":
            cases["hostile_proxy"]["delta"]["proxy"]["auth"] = 1
        elif change == "missing-listener":
            cases["missing_CA"]["delta"].pop("proxy")
        else:
            cases["trusted_CA_matching_SAN"]["delta"]["good"]["auth"] = True

    policy, output, _, runner = executable_packet(tmp_path, mutate_proof=mutate)
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.removed and not (output / "result.json").exists()


@pytest.mark.parametrize(
    "change",
    ["baseline-auth-bool", "baseline-request-bool", "baseline-outside-bool", "case-outside-bool"],
)
def test_native_counter_observations_are_numbers_not_booleans(tmp_path, change):
    def mutate(proof):
        baseline = proof["scenarios"]["original_insecure_baseline"]
        if change == "baseline-auth-bool":
            baseline["authHTTP"] = True
        elif change == "baseline-request-bool":
            baseline["requestHTTP"] = True
        elif change == "baseline-outside-bool":
            baseline["outside_module_resolutions"] = False
        else:
            proof["scenarios"]["missing_CA"]["result"]["outside_module_resolutions"] = False

    policy, output, _, runner = executable_packet(tmp_path, mutate_proof=mutate)
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.removed and not (output / "result.json").exists()


@pytest.mark.parametrize(
    "field,value", [("Architecture", "amd64"), ("Id", "sha256:" + "f" * 64), ("Os", "darwin")]
)
def test_derived_inspection_must_describe_exact_iid_not_another_valid_image(tmp_path, field, value):
    policy, output, _, runner = executable_packet(
        tmp_path, mutate_derived=lambda obj: obj.__setitem__(field, value)
    )
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert not runner.created and not runner.started


@pytest.mark.parametrize(
    "field,value",
    [
        ("OnBuild", ["RUN unreviewed"]),
        ("Volumes", {"/host-like-volume": {}}),
        ("Healthcheck", {"Test": ["CMD", "unreviewed"]}),
        ("User", "root"),
        ("Entrypoint", ["/unreviewed"]),
        ("Env", ["UNREVIEWED=value"]),
    ],
)
def test_parent_triggers_and_runtime_changes_refuse_before_build(tmp_path, field, value):
    policy, output, _, runner = executable_packet(
        tmp_path, mutate_parent=lambda obj: obj["Config"].__setitem__(field, value)
    )
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert all(command[0] == "pull" for command in runner.mutations)
    assert not runner.created and not runner.started


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("Config", "Entrypoint", ["/entrypoint.sh"]),
        ("Config", "Cmd", ["-e", "foreign code"]),
        ("Config", "User", "0:0"),
        ("Config", "WorkingDir", "/"),
        ("Config", "Tty", True),
        ("Config", "Healthcheck", {"Test": ["CMD", "foreign"]}),
        ("HostConfig", "NetworkMode", "bridge"),
        ("HostConfig", "ReadonlyRootfs", False),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
        ("HostConfig", "CapDrop", []),
        ("HostConfig", "Memory", 0),
        ("HostConfig", "NanoCpus", 0),
        ("HostConfig", "PidsLimit", -1),
        ("HostConfig", "SecurityOpt", []),
        ("HostConfig", "Binds", ["/var/run/docker.sock:/socket"]),
        ("HostConfig", "PortBindings", {"443/tcp": [{"HostPort": "9443"}]}),
        ("HostConfig", "PublishAllPorts", True),
        ("HostConfig", "Devices", [{"PathOnHost": "/dev/example"}]),
        ("HostConfig", "DeviceRequests", [{"Count": -1}]),
        ("HostConfig", "DeviceCgroupRules", ["a *:* rwm"]),
        ("HostConfig", "VolumesFrom", ["foreign"]),
        ("HostConfig", "Links", ["foreign"]),
        ("HostConfig", "ExtraHosts", ["host:127.0.0.1"]),
        ("HostConfig", "PidMode", "host"),
        ("HostConfig", "UTSMode", "host"),
        ("HostConfig", "UsernsMode", "host"),
        ("HostConfig", "IpcMode", "host"),
        ("HostConfig", "CgroupnsMode", "host"),
        ("HostConfig", "AutoRemove", True),
        ("HostConfig", "Tmpfs", {"/tmp": "rw,exec"}),
        ("NetworkSettings", "Ports", {"443/tcp": [{"HostPort": "9443"}]}),
    ],
)
def test_prestart_containment_drift_refused_before_any_start(tmp_path, section, key, value):
    def mutate(data):
        data[section][key] = value

    policy, output, _, runner = executable_packet(tmp_path, mutate_container=mutate)
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.created and not runner.started
    assert not (output / "result.json").exists()
    assert runner.removed  # Exact-owned unsafe container is still removed without starting it.


@pytest.mark.parametrize(
    "mount",
    [
        {"Type": "bind", "Destination": "/tmp", "Source": "/private"},
        {"Type": "volume", "Destination": "/tmp"},
        {"Type": "tmpfs", "Destination": "/unexpected"},
    ],
)
def test_prestart_host_or_volume_mount_refused(tmp_path, mount):
    policy, output, _, runner = executable_packet(
        tmp_path, mutate_container=lambda data: data.update(Mounts=[mount])
    )
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert not runner.started and runner.removed


@pytest.mark.parametrize(
    "fault,started,cleaned",
    [
        ("pull", False, False),
        ("build-timeout", False, False),
        ("create-timeout", False, True),
        ("start-timeout", True, True),
        ("exit", True, True),
        ("oom", True, True),
        ("cleanup", True, False),
    ],
)
def test_execution_faults_retain_uncertainty_without_false_success_or_replay(
    tmp_path, fault, started, cleaned
):
    policy, output, _, runner = executable_packet(tmp_path, fault=fault)
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    failure = fixture_value(output / "failure.json")
    assert failure["phase"] == "UNCERTAIN" and failure["qualified"] is False
    assert failure["cleanup_verified"] is cleaned and runner.removed is cleaned
    assert runner.started is started and not (output / "result.json").exists()
    if fault == "start-timeout":
        stops = [args for args in runner.mutations if args[0] == "stop"]
        assert stops == [["stop", "--time", "5", runner.cid]]
    mutations = list(runner.mutations)
    with pytest.raises((PreparationError, OSError)):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.mutations == mutations


def test_successful_reservation_is_single_use_even_with_valid_proof(tmp_path):
    policy, output, _, runner, _ = run_control(tmp_path)
    mutations = list(runner.mutations)
    with pytest.raises((PreparationError, OSError)):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.mutations == mutations


@pytest.mark.parametrize(
    "name",
    [
        "plan.json",
        "context/Dockerfile",
        "context/server-api-client.js",
        "fixture.json",
        "bootstrap.cjs",
    ],
)
def test_prepared_packet_mutation_refused_before_queries_or_mutations(tmp_path, name):
    policy, output, _, runner = executable_packet(tmp_path)
    path = output / name
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert not runner.commands and not (output / "execution.json").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "foreign-name"),
        ("image_id", "sha256:" + "f" * 64),
        ("labels", {"io.responseforge.work": "foreign"}),
    ],
)
def test_recovery_private_intent_binding_refused_before_any_query(tmp_path, field, value):
    policy, output, target, _, container = reserved_packet(tmp_path)
    intent = fixture_value(output / "container-intent.json")
    intent[field] = value
    save_fixture(output / "container-intent.json", intent)
    runner = RecoveryEngine(target, container)
    with pytest.raises(PreparationError):
        recover_run(output, allow_owned_cleanup=True, runner=runner, policy=policy)
    assert not runner.commands and not runner.mutations


def test_engine_replacement_between_preflight_and_pull_prevents_all_mutations(tmp_path):
    policy, output, _, runner = executable_packet(tmp_path)
    original = runner.run
    observations = 0

    def replacing_engine(argv, **kwargs):
        nonlocal observations
        if "info" in argv:
            observations += 1
            if observations == 2:
                runner.info["ID"] = "foreign-engine"
        return original(argv, **kwargs)

    runner.run = replacing_engine
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert not runner.mutations and not runner.started
    assert fixture_value(output / "failure.json")["qualified"] is False


def test_engine_replacement_at_cleanup_refuses_even_owned_looking_deletion(tmp_path):
    policy, output, _, runner = executable_packet(tmp_path)
    original = runner.run

    def replacing_engine(argv, **kwargs):
        if "info" in argv and runner.started:
            runner.info["ID"] = "foreign-engine"
        return original(argv, **kwargs)

    runner.run = replacing_engine
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert runner.started and not runner.removed
    assert not any(args[0] in {"stop", "rm"} for args in runner.mutations)
    failure = fixture_value(output / "failure.json")
    assert failure["qualified"] is False and failure["cleanup_verified"] is False
    assert not (output / "result.json").exists()


@pytest.mark.parametrize(
    "name", ["context/Dockerfile", "context/server-api-client.js", "bootstrap.cjs", "missing-map"]
)
def test_resealed_input_cannot_replace_reviewed_executable_material(tmp_path, name):
    policy, output, _, runner = executable_packet(tmp_path)
    plan = fixture_value(output / "plan.json")
    if name == "missing-map":
        plan["files"] = {}
    else:
        path = output / name
        path.write_bytes(path.read_bytes() + b"\n# substituted executable material\n")
        plan["files"][name] = digest(path.read_bytes())
    save_fixture(output / "plan.json", plan)
    (output / "plan.sha256").write_text(digest((output / "plan.json").read_bytes()) + "\n")
    with pytest.raises(PreparationError):
        execute_run(
            output,
            allow_image_build=True,
            allow_isolated_fixture=True,
            runner=runner,
            policy=policy,
        )
    assert not runner.commands and not (output / "execution.json").exists()


def test_build_and_runtime_use_verified_snapshots_despite_later_packet_mutation(tmp_path):
    import io
    import tarfile

    policy, output, _, runner = executable_packet(tmp_path)
    expected_client = (output / "context/server-api-client.js").read_bytes()
    expected_fixture = fixture_value(output / "fixture.json")
    original_run = runner.run
    built = []

    def mutate_after_validation(argv, input_data=b"", **kwargs):
        rest = list(argv)[list(argv).index("--context") + 2 :]
        if rest[:1] == ["pull"]:
            (output / "context/Dockerfile").write_text("FROM hostile\nRUN hostile\n")
            (output / "context/server-api-client.js").write_text("hostile code")
            (output / "fixture.json").write_text("{}")
        if rest[:1] == ["build"]:
            assert rest[-3:] == ["--file", "Dockerfile", "-"]
            with tarfile.open(fileobj=io.BytesIO(input_data)) as archive:
                assert archive.getnames() == ["Dockerfile", "server-api-client.js"]
                assert archive.extractfile("server-api-client.js").read() == expected_client
                assert b"RUN" not in archive.extractfile("Dockerfile").read()
            built.append(input_data)
        return original_run(argv, input_data=input_data, **kwargs)

    runner.run = mutate_after_validation
    report = execute_run(
        output, allow_image_build=True, allow_isolated_fixture=True, runner=runner, policy=policy
    )
    assert report["phase"] == "COMPLETE" and report["qualified"] is False
    assert json.loads(runner.stdin)["files"] == expected_fixture["files"]
    assert (output / "context-archive.tar").read_bytes() == built[0]
    assert (output / "runtime-input.json").read_bytes() == runner.stdin
