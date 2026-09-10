#!/usr/bin/env bash
# Parse selected fenced documentation snippets. Never execute documented commands.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify-snippets.sh [MARKDOWN_FILE ...]

Without files, parses shell and Nix fenced examples in README.md and
CONTRIBUTING.md. Shell examples are checked with `bash -n`; Nix expressions are
parsed with `nix-instantiate --parse` when that command is available. No example
is executed, and this script does not load or attach eBPF programs.
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

if (($# == 0)); then
  set -- README.md CONTRIBUTING.md
fi
for file in "$@"; do
  [[ -f $file ]] || { printf 'error: Markdown file not found: %s\n' "$file" >&2; exit 66; }
done

python3 - "$@" <<'PY'
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

fence = re.compile(r'^```([A-Za-z0-9_+.-]*)\s*$')
shell_languages = {'sh', 'bash', 'shell', 'console'}
nix_languages = {'nix'}
failures = []
checked = 0
skipped = 0

for filename in sys.argv[1:]:
    lines = Path(filename).read_text(encoding='utf-8').splitlines()
    open_language = None
    contents = []
    start_line = 0
    for index, line in enumerate(lines + ['```'], 1):
        marker = fence.match(line)
        if open_language is None:
            if marker:
                open_language = marker.group(1).lower()
                contents = []
                start_line = index + 1
            continue
        if marker:
            language = open_language
            code = '\n'.join(contents) + '\n'
            open_language = None
            if language in shell_languages:
                if language == 'console':
                    code = '\n'.join(
                        item[2:] for item in contents if item.startswith('$ ')
                    ) + '\n'
                if not code.strip():
                    skipped += 1
                    continue
                with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as handle:
                    handle.write(code)
                    path = handle.name
                result = subprocess.run(['bash', '-n', path], text=True, capture_output=True)
                Path(path).unlink(missing_ok=True)
                checked += 1
                if result.returncode:
                    failures.append(f'{filename}:{start_line}: shell syntax error: {result.stderr.strip()}')
            elif language in nix_languages:
                if shutil.which('nix-instantiate') is None:
                    print(f'SKIPPED {filename}:{start_line}: nix-instantiate is unavailable')
                    skipped += 1
                    continue
                with tempfile.NamedTemporaryFile('w', suffix='.nix', delete=False) as handle:
                    handle.write(code)
                    path = handle.name
                result = subprocess.run(['nix-instantiate', '--parse', path], text=True, capture_output=True)
                Path(path).unlink(missing_ok=True)
                if result.returncode:
                    # Sandboxed Nix may expose nix-instantiate but deny daemon access.
                    # That environmental limitation is not a source syntax failure.
                    if 'daemon-socket/socket: Permission denied' in result.stderr:
                        print(f'SKIPPED {filename}:{start_line}: Nix parser cannot access the local daemon')
                        skipped += 1
                    else:
                        checked += 1
                        failures.append(f'{filename}:{start_line}: Nix parse error: {result.stderr.strip()}')
                else:
                    checked += 1
            else:
                skipped += 1
            continue
        contents.append(line)

for failure in failures:
    print(f'ERROR {failure}', file=sys.stderr)
if failures:
    sys.exit(1)
print(f'Parsed {checked} fenced snippet(s); skipped {skipped} unsupported or empty snippet(s).')
PY
