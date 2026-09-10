#!/usr/bin/env bash
# Verify local Markdown links by default; external HTTP checks require --online.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify-links.sh [--offline|--online] [MARKDOWN_FILE ...]

Without files, verifies README.md and CONTRIBUTING.md. --offline (the default)
checks repository-local paths and heading anchors only, and reports external
URLs as unchecked. --online additionally sends bounded HEAD/GET requests to
external HTTP(S) URLs. It never modifies repository files.
USAGE
}

mode=offline
while (($#)); do
  case "$1" in
    --offline) mode=offline; shift ;;
    --online) mode=online; shift ;;
    -h|--help) usage; exit 0 ;;
    --*) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
    *) break ;;
  esac
done

if (($# == 0)); then
  set -- README.md CONTRIBUTING.md
fi

for file in "$@"; do
  [[ -f $file ]] || { printf 'error: Markdown file not found: %s\n' "$file" >&2; exit 66; }
done

python3 - "$mode" "$@" <<'PY'
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

mode, *files = sys.argv[1:]
errors = []
external = []
link_re = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
reference_def_re = re.compile(r'^\s*\[([^\]]+)\]:\s*(\S+)(?:\s+.*)?$')
heading_re = re.compile(r'^(#{1,6})\s+(.+?)\s*#*\s*$')

def slugify(text: str) -> str:
    text = re.sub(r'[`*_~]', '', text).lower()
    text = re.sub(r'[^\w\- ]', '', text)
    return re.sub(r'[ -]+', '-', text).strip('-')

def anchors(path: Path) -> set[str]:
    result, seen = set(), {}
    for line in path.read_text(encoding='utf-8').splitlines():
        match = heading_re.match(line)
        if not match:
            continue
        base = slugify(match.group(2))
        ordinal = seen.get(base, 0)
        seen[base] = ordinal + 1
        result.add(base if ordinal == 0 else f'{base}-{ordinal}')
    return result

for name in files:
    source = Path(name).resolve()
    for line_number, line in enumerate(source.read_text(encoding='utf-8').splitlines(), 1):
        targets = link_re.findall(line)
        reference = reference_def_re.match(line)
        if reference:
            targets.append(reference.group(2))
        for raw_target in targets:
            target = unquote(raw_target.strip('<>'))
            if target.startswith(('mailto:', 'data:')):
                continue
            parsed = urlsplit(target)
            if parsed.scheme in ('http', 'https'):
                external.append((str(source), line_number, target))
                continue
            if parsed.scheme or parsed.netloc:
                errors.append(f'{source}:{line_number}: unsupported link scheme: {target}')
                continue
            path_part, fragment = parsed.path, parsed.fragment
            destination = source if not path_part else (source.parent / path_part).resolve()
            if not destination.exists():
                errors.append(f'{source}:{line_number}: missing local target: {target}')
                continue
            if fragment:
                if destination.suffix.lower() not in ('.md', '.markdown'):
                    errors.append(f'{source}:{line_number}: anchor on non-Markdown target: {target}')
                elif fragment not in anchors(destination):
                    errors.append(f'{source}:{line_number}: missing heading anchor: {target}')

if mode == 'online':
    for source, line, url in external:
        result = subprocess.run(
            ['curl', '--fail', '--location', '--silent', '--show-error', '--head',
             '--max-time', '15', '--connect-timeout', '5', url],
            text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        if result.returncode:
            errors.append(f'{source}:{line}: external URL check failed: {url} ({result.stderr.strip()})')
else:
    for _, _, url in external:
        print(f'UNCHECKED external URL (offline mode): {url}')

for error in errors:
    print(f'ERROR {error}', file=sys.stderr)

if errors:
    sys.exit(1)
print(f'Verified local links in {len(files)} Markdown file(s); external URLs: {len(external)} ({mode}).')
PY
