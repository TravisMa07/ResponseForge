"""Pinned source acquisition expectations; injected bytes only, no external fetch."""

import hashlib
from pathlib import Path

import pytest

from responseforge.integrations.shuffle.artifacts import prepare_sources

REVISION = "a" * 40
SOURCE = b"# Original inert SDK input for source-preparation tests.\n"
URL = f"https://raw.githubusercontent.com/Shuffle/app_sdk/{REVISION}/shuffle_sdk/shuffle_sdk.py"


def source_lock(**changes):
    entry = {
        "component": "sdk",
        "name": "shuffle_sdk.py",
        "url": URL,
        "sha256": hashlib.sha256(SOURCE).hexdigest(),
    } | changes
    return {"schema_version": "1.0", "files": [entry]}


def test_verified_inert_source_written_once_with_matching_manifest(tmp_path: Path):
    calls = []

    def fetch(url):
        calls.append(url)
        return SOURCE

    destination = tmp_path / "context"
    manifest = prepare_sources(source_lock(), destination, fetch=fetch)
    assert calls == [URL]
    assert (destination / "sdk/shuffle_sdk.py").read_bytes() == SOURCE
    assert manifest["sdk/shuffle_sdk.py"] == hashlib.sha256(SOURCE).hexdigest()
    assert (destination.stat().st_mode & 0o077) == 0
    assert ((destination / "sdk/shuffle_sdk.py").stat().st_mode & 0o077) == 0


def test_hash_mismatch_never_leaves_usable_source(tmp_path: Path):
    destination = tmp_path / "context"
    with pytest.raises(ValueError):
        prepare_sources(source_lock(sha256="0" * 64), destination, fetch=lambda url: SOURCE)
    assert not (destination / "sdk/shuffle_sdk.py").exists()


@pytest.mark.parametrize("name", ["../escaped", "/absolute", "x/../../escaped", "", "x\\escaped"])
def test_invalid_relative_source_name_rejected_before_fetch(tmp_path: Path, name):
    calls = []
    with pytest.raises(ValueError):
        prepare_sources(
            source_lock(name=name), tmp_path / "context", fetch=lambda url: calls.append(url)
        )
    assert not calls


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/Shuffle/app_sdk/" + REVISION + "/file.py",
        "https://raw.githubusercontent.com/Shuffle/app_sdk/main/file.py",
        "https://raw.githubusercontent.com.evil.invalid/Shuffle/app_sdk/" + REVISION + "/file.py",
        "https://user:secret@raw.githubusercontent.com/Shuffle/app_sdk/" + REVISION + "/file.py",
        URL + "?secret=value",
        "file:///private/source.py",
    ],
)
def test_mutable_or_untrusted_source_url_rejected_before_fetch(tmp_path: Path, url):
    calls = []
    with pytest.raises(ValueError):
        prepare_sources(
            source_lock(url=url), tmp_path / "context", fetch=lambda url: calls.append(url)
        )
    assert calls == []


@pytest.mark.parametrize("digest", ["", "A" * 64, "a" * 63, "sha256:" + "a" * 64, "g" * 64])
def test_noncanonical_source_digest_is_rejected_before_fetch(tmp_path: Path, digest):
    calls = []
    with pytest.raises(ValueError):
        prepare_sources(
            source_lock(sha256=digest), tmp_path / "context", fetch=lambda url: calls.append(url)
        )
    assert not calls


def test_preexisting_destination_and_symlink_never_overwritten(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "private.txt"
    marker.write_text("preserve existing state")
    symlink = tmp_path / "link"
    symlink.symlink_to(existing, target_is_directory=True)
    for destination in (existing, symlink):
        calls = []
        with pytest.raises((ValueError, FileExistsError)):
            prepare_sources(source_lock(), destination, fetch=lambda url: calls.append(url))
        assert not calls
        assert marker.read_text() == "preserve existing state"
        assert not (existing / "sdk").exists()


def test_duplicate_destination_entries_are_rejected_before_fetch(tmp_path: Path):
    lock = source_lock()
    lock["files"] *= 2
    calls = []
    with pytest.raises(ValueError):
        prepare_sources(lock, tmp_path / "context", fetch=lambda url: calls.append(url))
    assert not calls


@pytest.mark.parametrize("component", ["unknown", "../worker", "worker/../../escaped"])
def test_unknown_component_cannot_select_path(tmp_path: Path, component):
    calls = []
    with pytest.raises(ValueError):
        prepare_sources(
            source_lock(component=component),
            tmp_path / "context",
            fetch=lambda url: calls.append(url),
        )
    assert not calls


def test_missing_patch_anchor_is_rejected_instead_of_unpatched_fallback():
    from responseforge.integrations.shuffle.artifacts import patch_source

    with pytest.raises(ValueError):
        patch_source("orborus", "orborus.go", "package main\nfunc main() {}\n")


def test_ambiguous_patch_anchor_is_rejected():
    from responseforge.integrations.shuffle.artifacts import patch_source

    with pytest.raises(ValueError):
        patch_source("backend", "main.go", "func main() {}\nfunc main() {}\n")


def test_invalid_utf8_source_never_produces_build_context(tmp_path: Path):
    raw = b"\xff\xfe"
    lock = source_lock(sha256=hashlib.sha256(raw).hexdigest())
    destination = tmp_path / "context"
    with pytest.raises(ValueError):
        prepare_sources(lock, destination, fetch=lambda url: raw)
    assert not destination.exists()


def test_all_sources_verified_before_any_context_is_written(tmp_path: Path):
    lock = source_lock()
    second = source_lock(name="other.py", sha256="0" * 64)["files"][0]
    lock["files"].append(second)
    destination = tmp_path / "context"
    with pytest.raises(ValueError):
        prepare_sources(lock, destination, fetch=lambda url: SOURCE)
    assert not destination.exists()


def test_cleanup_patch_removes_housekeeping_but_preserves_dispatch():
    """Tiny original Go-shaped input exercises body parsing without vendoring source."""
    from responseforge.integrations.shuffle.artifacts import patch_source

    original = """package main
import (
\t"sync"
\t"os/signal"
\t"syscall"
)
var sensor = shuffle.SensorMode{
\t\tSoftwareListEnabled: os.Getenv("SHUFFLE_SOFTWARE_LIST_ENABLED") == "true",
\t\tHdEncryptedCheck: os.Getenv("SHUFFLE_HD_ENCRYPTED_CHECK") == "true",
\t\tScreenlockCheck: os.Getenv("SHUFFLE_SCREENLOCK_CHECK") == "true",
}
func init() {
    connectDocker()
}
func cleanupExistingNodes(ctx context.Context) error {
    foreignRemovalMarker("} string is not a closing brace")
    if true { foreignRemovalMarker("nested") }
    return nil
}
func zombiecheck(ctx context.Context, workerTimeout int, sensorMode shuffle.SensorMode) error {
    /* } braces in a comment must not terminate a function. */
    foreignRemovalMarker(`{ raw string }`)
    return nil
}
func stopWorker(containername string) error {
    // } braces in a line comment must not terminate a function.
    foreignRemovalMarker(containername)
    return nil
}
func getOrborusStats(ctx context.Context, sensorMode shuffle.SensorMode) shuffle.OrborusStats {
    sensorProbeMarker()
    return shuffle.OrborusStats{}
}
func StartAgentSensor(sensorMode shuffle.SensorMode) error {
    sensorProbeMarker()
    return nil
}
func disabledSensorResponse() {
    go shuffle.HandleSensorResponseAction(sensorMode, incRequest)
}
func deployWorker(image string, identifier string, env []string, executionRequest shuffle.ExecutionRequest) error {
\thostConfig := &container.HostConfig{}
\t// This is just to test the mounting locally so
\tconfig := &container.Config{
\t\tImage: image,
\t\tEnv:   env,
\t}
    actualVendorDispatchMarker(config)
    return nil
}
"""
    patched = patch_source("orborus", "orborus.go", original)
    assert "foreignRemovalMarker" not in patched
    assert "sensorProbeMarker" not in patched
    assert "Queue: executionCount" in patched
    assert "actualVendorDispatchMarker(config)" in patched
    assert patched.index('os.Getenv("SHUFFLE_SWARM_CONFIG")') < patched.index("connectDocker()")
    assert '"responseforge.project": "responseforge-rf04"' in patched
    assert '"responseforge.execution": executionRequest.ExecutionId' in patched
    assert '"RF_CALLBACK_IMAGE="+os.Getenv("RF_CALLBACK_IMAGE")' in patched


def test_unterminated_cleanup_function_is_never_partially_patched():
    from responseforge.integrations.shuffle.artifacts import patch_source

    incomplete = "func cleanupExistingNodes(ctx context.Context) error {\n removeForeign()\n"
    with pytest.raises(ValueError):
        patch_source("orborus", "orborus.go", incomplete)


def test_worker_app_guard_mount_and_owned_removal_do_not_change_native_dispatch():
    from responseforge.integrations.shuffle.artifacts import patch_source

    original = """package main
func main() {
    executeNativeWorkflowMarker()
}
func deployApp(cli *dockerclient.Client, image string, identifier string, env []string, workflowExecution shuffle.WorkflowExecution, action shuffle.Action) error {
\t\timageName := buildAppImageName("", baseimagename, parsedAppname, action.AppVersion)
\tconfig := &container.Config{
\t\tImage: image,
\t\tEnv:   env,
\t}
    createActualAppContainerMarker(config, imageName)
\t\t\tgo cli.ContainerRemove(ctx, cont.ID, container.RemoveOptions{})
    return nil
}
"""
    patched = patch_source("worker", "worker.go", original)
    assert "executeNativeWorkflowMarker()" in patched
    assert "createActualAppContainerMarker(config, imageName)" in patched
    assert patched.index('os.Getenv("SHUFFLE_SWARM_CONFIG")') < patched.index(
        "executeNativeWorkflowMarker()"
    )
    assert (
        'allowedCallback := action.AppName == "responseforge_callback" && action.Name == "callback"'
        in patched
    )
    assert 'action.AppVersion != "1.0.0" || (!allowedCallback && !allowedTask)' in patched
    assert 'action.AppName == "responseforge_tasks"' in patched
    assert (
        'action.Name == "prepare" || action.Name == "gate" || action.Name == "dispatch"' in patched
    )
    assert 'action.AppName == "responseforge_callback" && action.Name == "callback"' in patched
    assert (
        'Source: os.Getenv("RF_CALLBACK_VOLUME")' in patched
        and 'Target: "/run/responseforge"' in patched
    )
    assert "ReadOnly: true" in patched and "ReadonlyRootfs = true" in patched
    assert 'owned.Config.Labels["responseforge.project"] != "responseforge-rf04"' in patched
    assert (
        'owned.Config.Labels["responseforge.execution"] != workflowExecution.ExecutionId' in patched
    )
    assert patched.index("cli.ContainerInspect(ctx, cont.ID)") < patched.index(
        "go cli.ContainerRemove(ctx, cont.ID"
    )
