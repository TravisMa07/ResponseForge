"""Read-only prerequisite inventory. Does not start containers or change the host."""
import json
import platform
import shutil
import subprocess
import sys


def run(label, command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f'UNAVAILABLE {label}: {type(error).__name__}')
        return False
    if result.returncode:
        print(f'UNAVAILABLE {label} (exit {result.returncode})')
        return False
    print(f'OK {label}: {result.stdout.strip()}')
    return True


def main():
    print('ResponseForge foundation doctor — read-only inventory')
    print(f'Host: {platform.system()} {platform.release()} {platform.machine()}')
    python_ok = sys.version_info >= (3, 12)
    print(f'{"OK" if python_ok else "UNAVAILABLE"} Python: {platform.python_version()} (requires 3.12+)')
    disk = shutil.disk_usage('.')
    print(f'Available disk: {disk.free / 2**30:.1f} GiB')
    checks = [python_ok]
    for label, command in (
        ('Git', ['git', '--version']),
        ('Docker client/server', ['docker', 'version', '--format', '{{.Client.Version}} / {{.Server.Version}}']),
        ('Docker Compose', ['docker', 'compose', 'version']),
        ('Docker resources', ['docker', 'info', '--format', 'OS={{.OSType}} architecture={{.Architecture}} CPUs={{.NCPU}} memory_bytes={{.MemTotal}}']),
    ):
        checks.append(run(label, command))
    print('No images pulled, services started, endpoint operations or configuration changes performed.')
    print('Vendor architecture compatibility, memory sufficiency and endpoint connectivity remain unqualified.')
    print(json.dumps({'prerequisites_available': all(checks), 'runtime_qualified': False, 'verified_live': False}))
    return 0 if all(checks) else 1

if __name__ == '__main__':
    raise SystemExit(main())
