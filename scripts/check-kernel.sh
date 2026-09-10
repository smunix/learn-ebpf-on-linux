#!/usr/bin/env bash
# Audit the running kernel for this repository's eBPF learning prerequisites.
# The script is read-only: it neither loads nor attaches an eBPF program.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/check-kernel.sh [OPTIONS]

Audit the current host for the eBPF lab prerequisites without changing state.

Options:
  --require-btf       Exit nonzero unless /sys/kernel/btf/vmlinux is readable.
  --require-bpf-lsm   Exit nonzero unless BPF_LSM is enabled and `bpf` is active.
  --require-lsm       Exit nonzero unless securityfs exposes the runtime LSM list.
  --quiet             Print only failures and unknown checks.
  -h, --help          Show this help text.

A missing readable kernel configuration is reported as UNKNOWN rather than as a
failed feature. Runtime checks are authoritative for the running host.
USAGE
}

require_btf=0
require_bpf_lsm=0
require_lsm=0
quiet=0

while (($#)); do
  case "$1" in
    --require-btf) require_btf=1 ;;
    --require-bpf-lsm) require_bpf_lsm=1 ;;
    --require-lsm) require_lsm=1 ;;
    --quiet) quiet=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

status=0
pass() {
  (( quiet )) || printf 'PASS    %s\n' "$*"
}
warn() {
  printf 'UNKNOWN %s\n' "$*" >&2
}
fail() {
  printf 'FAIL    %s\n' "$*" >&2
  status=1
}

kernel_config_line() {
  local config="/boot/config-$(uname -r)"
  if [[ -r /proc/config.gz ]] && command -v zgrep >/dev/null 2>&1; then
    zgrep -m1 -E "^${1}=" /proc/config.gz 2>/dev/null || true
  elif [[ -r "$config" ]]; then
    grep -m1 -E "^${1}=" "$config" 2>/dev/null || true
  fi
}

printf 'Kernel audit (read-only)\n'
printf '  architecture: %s\n' "$(uname -m)"
printf '  release:      %s\n' "$(uname -r)"
printf '  uid:          %s\n' "$(id -u)"

if [[ $(uname -m) == x86_64 ]]; then
  pass 'x86_64 architecture'
else
  fail "expected x86_64; found $(uname -m)"
fi

if [[ -r /sys/kernel/btf/vmlinux ]]; then
  pass 'kernel BTF is available at /sys/kernel/btf/vmlinux'
else
  if (( require_btf || require_bpf_lsm )); then
    fail 'kernel BTF is unavailable at /sys/kernel/btf/vmlinux'
  else
    warn 'kernel BTF is unavailable at /sys/kernel/btf/vmlinux'
  fi
fi

for option in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_DEBUG_INFO_BTF CONFIG_BPF_LSM; do
  value=$(kernel_config_line "$option")
  case "$value" in
    "$option"=y|"$option"=m) pass "$value" ;;
    '') warn "$option cannot be read from /proc/config.gz or /boot/config-$(uname -r)" ;;
    *)
      if [[ $option == CONFIG_BPF_LSM ]] && (( require_bpf_lsm )); then
        fail "$value"
      else
        warn "$value"
      fi
      ;;
  esac
done

if [[ -r /sys/kernel/security/lsm ]]; then
  lsm_list=$(< /sys/kernel/security/lsm)
  printf '  active LSMs:  %s\n' "$lsm_list"
  if [[ ,$lsm_list, == *,bpf,* ]]; then
    pass 'BPF LSM is active in /sys/kernel/security/lsm'
  elif (( require_bpf_lsm )); then
    fail 'BPF LSM is not active; add bpf to the kernel lsm= order in an isolated lab'
  else
    warn 'BPF LSM is not active in the runtime LSM list'
  fi
else
  if (( require_lsm || require_bpf_lsm )); then
    fail 'runtime LSM list is unavailable at /sys/kernel/security/lsm'
  else
    warn 'runtime LSM list is unavailable (securityfs may not be mounted)'
  fi
fi

if (( status )); then
  printf 'Kernel audit completed with unmet required checks. No system state was changed.\n' >&2
else
  printf 'Kernel audit completed. No system state was changed.\n'
fi
exit "$status"
