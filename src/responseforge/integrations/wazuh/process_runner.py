"""Bounded local child process adapter; no shell or authority inference."""

import math
import os
import selectors
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass

_MAX_INPUT = 2 * 1024 * 1024
_MAX_OUTPUT = 8 * 1024 * 1024
_MAX_TIMEOUT = 300
_MAX_ARG_BYTES = 1024 * 1024
_MAX_ARG_COUNT = 256


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessFailure(ValueError):
    def __init__(self, category: str, stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__("Bounded process failed")
        self.category = category
        self.stdout = stdout
        self.stderr = stderr


class BoundedProcessRunner:
    def run(self, argv: Sequence[str], input_data: bytes = b"", timeout: float = 120,
            max_output: int = 1048576) -> ProcessResult:
        arguments = _validate(argv, input_data, timeout, max_output)
        environment = os.environ.copy()
        for name in tuple(environment):
            if name.startswith(("DOCKER_", "BUILDX_")) or name == "BUILDKIT_HOST":
                environment.pop(name)
        stdout = bytearray()
        stderr = bytearray()
        deadline = time.monotonic() + timeout
        try:
            child = subprocess.Popen(
                arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, close_fds=True, env=environment,
            )
        except (OSError, ValueError):
            raise ProcessFailure("spawn-failed") from None

        # All three pipes participate in the same deadline: a child may write
        # before consuming stdin, or leave one output stream temporarily idle.
        try:
            assert child.stdin is not None
            assert child.stdout is not None
            assert child.stderr is not None
            with selectors.DefaultSelector() as selector:
                for pipe, destination in ((child.stdout, stdout), (child.stderr, stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, destination)
                if input_data:
                    os.set_blocking(child.stdin.fileno(), False)
                    selector.register(child.stdin, selectors.EVENT_WRITE, None)
                else:
                    child.stdin.close()
                offset = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProcessFailure("timeout", bytes(stdout), bytes(stderr))
                    for key, _ in selector.select(remaining):
                        if time.monotonic() >= deadline:
                            raise ProcessFailure("timeout", bytes(stdout), bytes(stderr))
                        if key.events == selectors.EVENT_WRITE:
                            try:
                                written = os.write(key.fd, input_data[offset:offset + 65536])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                written = 0
                                offset = len(input_data)
                            offset += written
                            if offset >= len(input_data):
                                selector.unregister(key.fileobj)
                                child.stdin.close()
                        else:
                            capacity = max_output - len(stdout) - len(stderr)
                            try:
                                chunk = os.read(key.fd, min(65536, capacity + 1))
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                key.data.extend(chunk[:capacity])
                                if len(chunk) > capacity:
                                    raise ProcessFailure("output-limit", bytes(stdout), bytes(stderr))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcessFailure("timeout", bytes(stdout), bytes(stderr))
            try:
                returncode = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ProcessFailure("timeout", bytes(stdout), bytes(stderr)) from None
            return ProcessResult(returncode, bytes(stdout), bytes(stderr))
        except OSError:
            raise ProcessFailure("spawn-failed", bytes(stdout), bytes(stderr)) from None
        finally:
            # Terminating this CLI cannot establish cleanup of resources it
            # manages. Never signal process groups or infer container cleanup.
            try:
                if child.poll() is None:
                    child.kill()
            finally:
                child.wait()
                for open_pipe in (child.stdin, child.stdout, child.stderr):
                    if open_pipe is not None:
                        open_pipe.close()


def _validate(argv: Sequence[str], input_data: bytes, timeout: float, max_output: int) -> list[str]:
    if (
        not isinstance(argv, Sequence) or isinstance(argv, (str, bytes, bytearray))
        or not 0 < len(argv) <= _MAX_ARG_COUNT
        or not isinstance(input_data, bytes)
        or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
        or not 0 < timeout <= _MAX_TIMEOUT or not math.isfinite(timeout)
        or isinstance(max_output, bool) or not isinstance(max_output, int)
        or not 0 < max_output <= _MAX_OUTPUT
    ):
        raise ProcessFailure("invalid-arguments")
    if len(input_data) > _MAX_INPUT:
        raise ProcessFailure("input-limit")
    arguments = list(argv)
    total = 0
    for argument in arguments:
        if not isinstance(argument, str) or "\x00" in argument:
            raise ProcessFailure("invalid-arguments")
        try:
            total += len(argument.encode("utf-8")) + 1
        except UnicodeEncodeError:
            raise ProcessFailure("invalid-arguments") from None
        if total > _MAX_ARG_BYTES:
            raise ProcessFailure("invalid-arguments")
    if not arguments[0]:
        raise ProcessFailure("invalid-arguments")
    return arguments
