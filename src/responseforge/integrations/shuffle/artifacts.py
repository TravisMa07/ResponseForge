"""Pinned source preparation for the reviewed Shuffle pilot images."""

import hashlib
import json
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_COMPONENTS = frozenset({"backend", "worker", "orborus", "sdk"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SOURCE_BYTES = 4 * 1024 * 1024


def _once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("Pinned source patch anchor changed")
    return text.replace(before, after, 1)


def _without_function_body(
    text: str,
    signature: str,
    body: str = "\n\t// RF-04: cleanup is explicit and project-scoped.\n\treturn nil\n",
) -> str:
    """Locate braces in Go code, ignoring quoted strings and comments."""
    if text.count(signature) != 1:
        raise ValueError("Pinned cleanup function changed")
    start = text.index(signature) + len(signature) - 1
    depth = 0
    mode = "code"
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if mode == "line":
            if char == "\n":
                mode = "code"
        elif mode == "block":
            if pair == "*/":
                mode = "code"
                index += 1
        elif mode in {'"', "'", "`"}:
            if escaped:
                escaped = False
            elif char == "\\" and mode != "`":
                escaped = True
            elif char == mode:
                mode = "code"
        elif pair == "//":
            mode = "line"
            index += 1
        elif pair == "/*":
            mode = "block"
            index += 1
        elif char in {'"', "'", "`"}:
            mode = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[: start + 1] + body + text[index:]
        index += 1
    raise ValueError("Pinned cleanup function is incomplete")


_MODE_GUARD = """
\t// RF-04: reject alternative execution planes before any Docker operation.
\tlog.SetOutput(io.Discard)
\tif len(os.Args) != 1 || os.Getenv("SHUFFLE_SWARM_CONFIG") != "" ||
\t\tstrings.EqualFold(os.Getenv("IS_KUBERNETES"), "true") ||
\t\tstrings.EqualFold(os.Getenv("SHUFFLE_EC2_INSTANCE"), "true") ||
\t\tstrings.EqualFold(os.Getenv("SHUFFLE_AGENT_MODE"), "true") ||
\t\tstrings.EqualFold(os.Getenv("SHUFFLE_AGENT_SENSOR_MODE"), "true") ||
\t\tos.Getenv("SHUFFLE_VOLUME_BINDS") != "" ||
\t\tos.Getenv("SHUFFLE_CERT_PATH") != "" ||
\t\tos.Getenv("DOCKER_HOST") != "" ||
\t\tos.Getenv("REGISTRY_URL") != "" ||
\t\tos.Getenv("RF_PROJECT") != "responseforge-rf04" {
\t\tos.Exit(78)
\t}
"""

_WORKER_APP_GUARD = """
\t// RF-04: only the reviewed app receives the immutable image and secret volume.
\tif action.AppName != "responseforge_callback" || action.AppVersion != "1.0.0" || action.Name != "callback" {
\t\treturn errors.New("RF-04 app metadata is not allowlisted")
\t}
\timage = os.Getenv("RF_CALLBACK_IMAGE")
\tif !strings.HasPrefix(image, "sha256:") || len(image) != 71 || os.Getenv("RF_CALLBACK_VOLUME") != "responseforge-rf04-callback" {
\t\treturn errors.New("RF-04 immutable app configuration is invalid")
\t}
\tfor _, character := range strings.TrimPrefix(image, "sha256:") {
\t\tif !strings.ContainsRune("0123456789abcdef", character) {
\t\t\treturn errors.New("RF-04 immutable app image is invalid")
\t\t}
\t}
"""

_OWNED_LABELS = """
\t\tLabels: map[string]string{
\t\t\t"responseforge.project": "responseforge-rf04",
\t\t\t"responseforge.execution": %s,
\t\t},"""


def patch_source(component: str, name: str, text: str) -> str:
    """Apply exact reviewed source transformations or reject drift."""
    if component not in _COMPONENTS or not isinstance(text, str):
        raise ValueError("Unknown source component")
    if component == "backend" and name == "main.go":
        text = _once(text, "func main() {", "func main() {\n\tlog.SetOutput(io.Discard)")
        text = _once(
            text,
            '\tif len(parsedApikey) == 0 {\n\t\tlog.Printf("[WARNING] No apikey found for cleanup. Skipping cleanup schedule.")',
            '\tif true { // RF-04: automatic environment-wide stop/rerun is disabled.\n\t\tlog.Printf("[WARNING] No apikey found for cleanup. Skipping cleanup schedule.")',
        )
        text = _once(
            text,
            "} else if err == nil && len(workflowapps) < 10 {",
            '} else if err == nil && len(workflowapps) < 10 && os.Getenv("RF_ALLOW_DEFAULT_APPS") == "true" {',
        )
    elif component == "backend" and name == "walkoff.go":
        guard = """
\t// RF-04: default environments also require the explicit queue credential.
\tif token := os.Getenv("RF_QUEUE_TOKEN"); len(token) < 36 || request.Header.Get("Authorization") != token {
\t\tresp.WriteHeader(http.StatusUnauthorized)
\t\tresp.Write([]byte(`{"success":false,"reason":"Queue authorization required"}`))
\t\treturn
\t}
"""
        for function in ("handleGetWorkflowqueue", "handleGetWorkflowqueueConfirm"):
            signature = f"func {function}(resp http.ResponseWriter, request *http.Request) {{"
            text = _once(text, signature, signature + guard)
    elif component == "orborus" and name == "go.mod":
        text = _once(
            text,
            "replace github.com/shuffle/shuffle-shared => ../../../../shuffle-shared\n",
            "// RF-04: use the declared checksummed module, never a local checkout.\n",
        )
    elif component == "orborus" and name == "orborus.go":
        for signature in (
            "func cleanupExistingNodes(ctx context.Context) error {",
            "func zombiecheck(ctx context.Context, workerTimeout int, sensorMode shuffle.SensorMode) error {",
            "func stopWorker(containername string) error {",
        ):
            text = _without_function_body(text, signature)
        # The licensed source predates the shared module's host sensor API
        # changes. Sensor collection is excluded and blocked before init;
        # preserve genuine queue metadata without emulating host capabilities.
        text = _without_function_body(
            text,
            "func getOrborusStats(ctx context.Context, sensorMode shuffle.SensorMode) shuffle.OrborusStats {",
            """
\t// RF-04: only actual queue counters and orchestration identity are reported.
\treturn shuffle.OrborusStats{
\t\tOrgId: org,
\t\tEnvironment: environment,
\t\tOrborusLabel: orborusLabel,
\t\tTimestamp: time.Now().Unix(),
\t\tUuid: orborusUuid,
\t\tPollTime: sleepTime,
\t\tMaxQueue: maxConcurrency,
\t\tQueue: executionCount,
\t}
""",
        )
        text = _without_function_body(
            text,
            "func StartAgentSensor(sensorMode shuffle.SensorMode) error {",
            '\n\treturn errors.New("RF-04 host sensor mode is disabled")\n',
        )
        for field, environment_key in (
            ("SoftwareListEnabled", "SHUFFLE_SOFTWARE_LIST_ENABLED"),
            ("HdEncryptedCheck", "SHUFFLE_HD_ENCRYPTED_CHECK"),
            ("ScreenlockCheck", "SHUFFLE_SCREENLOCK_CHECK"),
        ):
            text = _once(
                text,
                f'\t\t{field}: os.Getenv("{environment_key}") == "true",',
                f'\t\t{field}: "", // RF-04 sensor collection is disabled.',
            )
        for sensor_only_import in ("sync", "os/signal", "syscall"):
            text = _once(text, f'\t"{sensor_only_import}"\n', "")
        text = _once(
            text,
            "go shuffle.HandleSensorResponseAction(sensorMode, incRequest)",
            "os.Exit(78) // RF-04: host sensor response is never permitted.",
        )
        text = _once(text, "func init() {", "func init() {" + _MODE_GUARD)
        signature = "func deployWorker(image string, identifier string, env []string, executionRequest shuffle.ExecutionRequest) error {"
        text = _once(
            text,
            signature,
            signature
            + """
\tenv = append(env,
\t\t"RF_PROJECT=responseforge-rf04",
\t\t"RF_CALLBACK_IMAGE="+os.Getenv("RF_CALLBACK_IMAGE"),
\t\t"RF_CALLBACK_VOLUME="+os.Getenv("RF_CALLBACK_VOLUME"),
\t\t"SHUFFLE_AUTO_IMAGE_DOWNLOAD=false",
\t)
""",
        )
        text = _once(
            text,
            "\tconfig := &container.Config{\n\t\tImage: image,\n\t\tEnv:   env,\n\t}",
            "\tconfig := &container.Config{\n\t\tImage: image,\n\t\tEnv:   env,"
            + _OWNED_LABELS % "executionRequest.ExecutionId"
            + "\n\t}",
        )
        text = _once(
            text,
            "\t// This is just to test the mounting locally so",
            """\thostConfig.ReadonlyRootfs = true
\thostConfig.CapDrop = []string{"ALL"}
\thostConfig.SecurityOpt = []string{"no-new-privileges:true"}
\thostConfig.Tmpfs = map[string]string{"/tmp": "rw,nosuid,nodev,size=64m"}
\thostConfig.Resources.Memory = 536870912
\thostConfig.Resources.NanoCPUs = 1000000000
\t// This is just to test the mounting locally so""",
        )
    elif component == "worker" and name == "worker.go":
        text = _once(text, "func main() {", "func main() {" + _MODE_GUARD)
        signature = "func deployApp(cli *dockerclient.Client, image string, identifier string, env []string, workflowExecution shuffle.WorkflowExecution, action shuffle.Action) error {"
        text = _once(text, signature, signature + _WORKER_APP_GUARD)
        text = _once(
            text,
            '\t\timageName := buildAppImageName("", baseimagename, parsedAppname, action.AppVersion)',
            '\t\timageName := os.Getenv("RF_CALLBACK_IMAGE")',
        )
        before = "\tconfig := &container.Config{\n\t\tImage: image,\n\t\tEnv:   env,\n\t}"
        after = (
            """\thostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
\t\tType: mount.TypeVolume,
\t\tSource: os.Getenv("RF_CALLBACK_VOLUME"),
\t\tTarget: "/run/responseforge",
\t\tReadOnly: true,
\t})
\thostConfig.ReadonlyRootfs = true
\thostConfig.CapDrop = []string{"ALL"}
\thostConfig.SecurityOpt = []string{"no-new-privileges:true"}
\thostConfig.Resources.Memory = 268435456
\thostConfig.Resources.NanoCPUs = 1000000000
\tconfig := &container.Config{
\t\tImage: image,
\t\tEnv:   env,
\t\tCmd: []string{"python", "-m", "responseforge.integrations.shuffle.pilot", "app"},"""
            + _OWNED_LABELS % "workflowExecution.ExecutionId"
            + "\n\t}"
        )
        text = _once(text, before, after)
        # This is the only active standalone removal: a just-created app after
        # network setup failed. Check its exact labels before removing even it.
        text = _once(
            text,
            "\t\t\tgo cli.ContainerRemove(ctx, cont.ID, container.RemoveOptions{})",
            """\t\t\towned, inspectErr := cli.ContainerInspect(ctx, cont.ID)
\t\t\tif inspectErr != nil || owned.Config == nil || owned.Config.Labels["responseforge.project"] != "responseforge-rf04" || owned.Config.Labels["responseforge.execution"] != workflowExecution.ExecutionId {
\t\t\t\treturn errors.New("RF-04 refuses foreign container removal")
\t\t\t}
\t\t\tgo cli.ContainerRemove(ctx, cont.ID, container.RemoveOptions{})""",
        )
    return text


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(_MAX_SOURCE_BYTES + 1)
    if len(data) > _MAX_SOURCE_BYTES:
        raise ValueError("Source file exceeds permitted size")
    if not isinstance(data, bytes):
        raise ValueError("Invalid source response")
    return data


def _entry(value: Any) -> tuple[str, str, str, str]:
    if not isinstance(value, dict) or set(value) != {"component", "name", "url", "sha256"}:
        raise ValueError("Invalid source lock entry")
    component, name, url, digest = (value[key] for key in ("component", "name", "url", "sha256"))
    if (
        not isinstance(component, str)
        or component not in _COMPONENTS
        or not isinstance(name, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None
        or name in {".", ".."}
        or not isinstance(url, str)
        or not isinstance(digest, str)
        or _HASH.fullmatch(digest) is None
    ):
        raise ValueError("Invalid source lock identity")
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "raw.githubusercontent.com"
        or parsed.query
        or parsed.fragment
        or len(segments) < 5
        or re.fullmatch(r"[0-9a-f]{40}", segments[3]) is None
        or any(part in {"", ".", ".."} for part in segments[1:])
        or any(ord(char) <= 32 or ord(char) >= 127 for char in url)
        or "%" in url
        or "\\" in url
    ):
        raise ValueError("Source URL must identify an immutable GitHub file")
    return component, name, url, digest


def prepare_sources(
    lock: dict[str, Any],
    destination: Path,
    *,
    fetch: Callable[[str], bytes] | None = None,
) -> dict[str, str]:
    """Verify pinned input bytes and create an exclusive private build context."""
    if (
        not isinstance(lock, dict)
        or set(lock) != {"schema_version", "files"}
        or lock["schema_version"] != "1.0"
        or not isinstance(lock["files"], list)
        or not 1 <= len(lock["files"]) <= 100
    ):
        raise ValueError("Invalid source lock")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Source destination already exists")
    if any(parent.is_symlink() for parent in destination.parents):
        raise ValueError("Source destination has a symbolic-link ancestor")
    entries = [_entry(value) for value in lock["files"]]
    paths = [component + "/" + name for component, name, _, _ in entries]
    if len(set(paths)) != len(paths):
        raise ValueError("Duplicate source output name")
    output: dict[str, bytes] = {}
    for (component, name, url, digest), path in zip(entries, paths, strict=True):
        data = (fetch or _fetch)(url)
        if not isinstance(data, bytes) or len(data) > _MAX_SOURCE_BYTES:
            raise ValueError("Source response is invalid or exceeds permitted size")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Pinned source hash does not match")
        try:
            output[path] = patch_source(component, name, data.decode("utf-8")).encode("utf-8")
        except UnicodeError:
            raise ValueError("Pinned source must be UTF-8 text") from None
    manifest = {path: hashlib.sha256(data).hexdigest() for path, data in output.items()}
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path, data in output.items():
        target = destination / path
        target.parent.mkdir(mode=0o700, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o600)
    with (destination / "patch-manifest.json").open("x") as stream:
        json.dump(
            {"schema_version": "1.0", "input_lock": lock, "patched_files": manifest},
            stream,
            indent=2,
        )
        stream.write("\n")
    (destination / "patch-manifest.json").chmod(0o600)
    return manifest
