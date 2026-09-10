#!/usr/bin/env bash
# Safe-by-default smoke harness. Runtime attachment requires an explicit flag.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/smoke-tests.sh [--audit] [--probe --allow-privileged]
       scripts/smoke-tests.sh --runtime 01-tracepoint-hello --allow-attach

--audit (default) runs read-only prerequisite checks. --probe additionally runs
`bpftool feature probe kernel`, which may require root or BPF-related Linux
capabilities. Probing is refused unless --allow-privileged is supplied. Neither
of those modes loads or attaches an eBPF program.

--runtime is deliberately limited to the payload-free first sample, runs for
five seconds, and requires explicit --allow-attach acknowledgement. Build the
ordinary-user artifacts first. The script never invokes Cargo or sudo.
USAGE
}

audit=1
probe=0
allow_privileged=0
allow_attach=0
runtime_sample=""
while (($#)); do
  case "$1" in
    --audit) audit=1 ;;
    --probe) probe=1 ;;
    --allow-privileged) allow_privileged=1 ;;
    --allow-attach) allow_attach=1 ;;
    --runtime)
      shift
      (($#)) || { printf '%s\n' 'error: --runtime requires a sample name.' >&2; exit 64; }
      runtime_sample="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

if (( probe && ! allow_privileged )); then
  printf '%s\n' 'error: --probe requires explicit --allow-privileged acknowledgement.' >&2
  exit 64
fi
if [[ -n "$runtime_sample" && $allow_attach -ne 1 ]]; then
  printf '%s\n' 'error: --runtime requires explicit --allow-attach acknowledgement.' >&2
  exit 64
fi
if [[ -n "$runtime_sample" && "$runtime_sample" != "01-tracepoint-hello" ]]; then
  printf '%s\n' 'error: runtime smoke is limited to 01-tracepoint-hello.' >&2
  exit 64
fi

if (( audit )); then
  printf '%s\n' '== Read-only kernel prerequisite audit =='
  "$(dirname "$0")/check-kernel.sh"
fi

if (( probe )); then
  command -v bpftool >/dev/null 2>&1 || {
    printf 'error: bpftool is required for --probe.\n' >&2
    exit 127
  }
  printf '%s\n' '== Capability-gated, read-only bpftool feature probe =='
  if ! timeout 30s bpftool feature probe kernel; then
    printf '%s\n' 'Feature probe did not complete successfully. This may indicate missing privileges or unavailable kernel support; no state was changed.' >&2
    exit 1
  fi
fi

if [[ -n "$runtime_sample" ]]; then
  runner="$(dirname "$0")/../samples/target/debug/sample-runner"
  object="$(dirname "$0")/../samples/target/ebpf/tracepoint-hello"
  [[ -x "$runner" ]] || { printf '%s\n' 'error: build samples/target/debug/sample-runner as an ordinary user first.' >&2; exit 66; }
  [[ -r "$object" ]] || { printf '%s\n' 'error: build the tracepoint-hello eBPF object as an ordinary user first.' >&2; exit 66; }
  printf '%s\n' '== Explicit five-second tracepoint attachment smoke test =='
  timeout 15s "$runner" run "$runtime_sample" --object "$object" --duration 5
  printf '%s\n' 'Runtime smoke completed; runner exit detached the program.'
else
  printf '%s\n' 'Smoke harness completed. No eBPF program was loaded or attached.'
fi
