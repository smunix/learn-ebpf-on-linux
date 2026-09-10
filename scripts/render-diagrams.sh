#!/usr/bin/env bash
# Render the book's editable D2 sources to the SVG assets consumed by Typst.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/render-diagrams.sh [--check] [--source DIR] [--output DIR]

Renders every .d2 source with the standalone d2 CLI. The default output is
book/assets/diagrams/generated, which is committed because book/main.typ imports
those SVG files. --check renders into a temporary directory and compares bytes
without modifying committed output.
USAGE
}

check=0
source_dir=book/assets/diagrams/src
output_dir=book/assets/diagrams/generated

while (($#)); do
  case "$1" in
    --check) check=1 ;;
    --source)
      shift
      (($#)) || { printf '%s\n' 'error: --source requires a directory' >&2; exit 64; }
      source_dir=$1
      ;;
    --output)
      shift
      (($#)) || { printf '%s\n' 'error: --output requires a directory' >&2; exit 64; }
      output_dir=$1
      ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

command -v d2 >/dev/null 2>&1 || {
  printf '%s\n' 'error: d2 is required; enter `nix develop`.' >&2
  exit 127
}
[[ -d $source_dir ]] || {
  printf 'error: source directory does not exist: %s\n' "$source_dir" >&2
  exit 66
}

work_dir=$output_dir
cleanup=
if ((check)); then
  work_dir=$(mktemp -d)
  cleanup=$work_dir
fi
trap '[[ -z $cleanup ]] || rm -rf "$cleanup"' EXIT

count=0
changed=0
while IFS= read -r -d '' source; do
  rel=${source#"$source_dir"/}
  destination="$work_dir/${rel%.d2}.svg"
  mkdir -p "$(dirname "$destination")"
  d2 --layout=dagre "$source" "$destination"
  ((count += 1))
  if ((check)); then
    expected="$output_dir/${rel%.d2}.svg"
    if [[ ! -f $expected ]] || ! cmp -s "$destination" "$expected"; then
      printf 'stale or missing: %s\n' "$expected" >&2
      changed=1
    fi
  else
    printf 'rendered: %s\n' "$destination"
  fi
done < <(find "$source_dir" -type f -name '*.d2' -print0 | sort -z)

if ((count == 0)); then
  printf 'No D2 sources found under %s; nothing to render.\n' "$source_dir"
elif ((check && changed)); then
  printf 'Diagram check found stale output. Run scripts/render-diagrams.sh.\n' >&2
  exit 1
else
  printf 'Processed %d D2 diagram source(s).\n' "$count"
fi
