"""Check foundation Markdown paths and required artifacts, without dependencies."""
from pathlib import Path
import re
import sys
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'AGENTS.md', 'README.md', 'THIRD_PARTY.md',
    'docs/architecture.md', 'docs/dependencies.md', 'docs/environment.md',
    'docs/implementation-plan.md', 'docs/acceptance.md', 'docs/sdlc.md',
    'docs/roadmap.md', 'docs/implementation-ledger.md',
    'docs/decisions/0001-bounded-core.md', 'docs/security.md', 'docs/limitations.md',
)

def main():
    errors = []
    # Inspect the Git index, not just ignore rules: already-tracked files bypass ignores.
    tracked = subprocess.run(
        ['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split('\0')
    for name in filter(None, tracked):
        if 'handoff' in Path(name).name.lower() or name.startswith('docs/private/'):
            errors.append(f'Private engineering document must not be tracked: {name}')
    if sys.version_info < (3, 12):
        errors.append('Python 3.12+ required; select a suitable interpreter with PYTHON=...')
    for name in REQUIRED:
        path = ROOT / name
        if not path.is_file() or not path.read_text().strip():
            errors.append(f'Missing or empty required document: {name}')
    documents = [ROOT / name for name in ('README.md', 'AGENTS.md', 'THIRD_PARTY.md')]
    documents += sorted((ROOT / 'docs').rglob('*.md'))
    for path in documents:
        if not path.exists():
            continue
        content = path.read_text()
        if re.search(r'\{\{[A-Z_]+\}\}', content):
            errors.append(f'{path.relative_to(ROOT)}: unresolved template marker')
        # Check inline local file links; fenced examples are not document links.
        content = re.sub(r'```.*?```', '', content, flags=re.S)
        for match in re.finditer(r'\[[^\]]*\]\(([^)]+)\)', content):
            target = match.group(1).strip().strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith('#'):
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            if not destination.is_relative_to(ROOT) or not destination.exists():
                errors.append(f'{path.relative_to(ROOT)}: invalid local link {target}')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'PASS: {len(documents)} Markdown documents; required files and local file links checked.')
    print('Scope: documentation integrity only; no runtime or endpoint qualification.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
