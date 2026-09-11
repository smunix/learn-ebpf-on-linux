#!/usr/bin/env bash
# Generate Aya Rust bindings from the BTF of the currently booted kernel.
set -euo pipefail

AYA_REPOSITORY=https://github.com/aya-rs/aya
AYA_REVISION=0e353a7fddf80091ae2fb2dacc08ec1d861e67cc
BTF=/sys/kernel/btf/vmlinux
output=samples/ebpf-programs/src/vmlinux.rs
install_tool=0

usage() {
  cat <<'USAGE'
Usage: scripts/generate-target-bindings.sh [--install-tool] [--output PATH]

Generate file, inode, super_block, task_struct, and BPF map-iterator context
bindings from the currently booted kernel's /sys/kernel/btf/vmlinux. The output is replaced
atomically and OUTPUT.manifest records the target and BTF digest.

Run only in a disposable worktree for the exact VM that will load the object.
Review the generated diff and ELF relocations before using --target-btf-fixture.
USAGE
}

while (($#)); do
  case "$1" in
    --install-tool) install_tool=1 ;;
    --output)
      shift
      (($#)) || { printf '%s\n' 'error: --output requires a path' >&2; exit 64; }
      output=$1
      ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

[[ $EUID -ne 0 ]] || {
  printf '%s\n' 'error: generate bindings as an ordinary user, not root.' >&2
  exit 77
}
[[ -r $BTF ]] || {
  printf 'error: target BTF is not readable: %s\n' "$BTF" >&2
  exit 69
}
command -v bpftool >/dev/null 2>&1 || {
  printf '%s\n' 'error: bpftool is required; enter `nix develop`.' >&2
  exit 127
}
command -v bindgen >/dev/null 2>&1 || {
  printf '%s\n' 'error: bindgen is required; enter `nix develop`.' >&2
  exit 127
}

if ((install_tool)); then
  cargo install --locked --git "$AYA_REPOSITORY" --rev "$AYA_REVISION" aya-tool
fi
command -v aya-tool >/dev/null 2>&1 || {
  printf '%s\n' "error: aya-tool is missing. Install the pinned revision with:"
  printf 'cargo install --locked --git %s --rev %s aya-tool\n' "$AYA_REPOSITORY" "$AYA_REVISION"
  exit 127
}

mkdir -p "$(dirname "$output")"
temporary=$(mktemp "${output}.tmp.XXXXXX")
trap 'rm -f "$temporary"' EXIT
aya-tool generate file inode super_block task_struct bpf_iter_meta bpf_iter__bpf_map_elem >"$temporary"
[[ -s $temporary ]] || { printf '%s\n' 'error: aya-tool produced an empty binding file.' >&2; exit 65; }

{
  printf '%s\n' '//! GENERATED FOR ONE TARGET — REVIEW BEFORE USE.'
  printf '//! Kernel: %s\n' "$(uname -srmo)"
  printf '//! BTF SHA-256: %s\n' "$(sha256sum "$BTF" | cut -d' ' -f1)"
  printf '//! aya-tool revision: %s\n' "$AYA_REVISION"
  printf '%s\n' '//! This file is build evidence, not a universal kernel layout.'
  cat "$temporary"
} >"${temporary}.annotated"
mv "${temporary}.annotated" "$output"

{
  printf 'kernel_release=%s\n' "$(uname -r)"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'btf_path=%s\n' "$BTF"
  printf 'btf_sha256=%s\n' "$(sha256sum "$BTF" | cut -d' ' -f1)"
  printf 'aya_repository=%s\n' "$AYA_REPOSITORY"
  printf 'aya_revision=%s\n' "$AYA_REVISION"
  printf 'generated_sha256=%s\n' "$(sha256sum "$output" | cut -d' ' -f1)"
} >"${output}.manifest"

printf 'generated %s\n' "$output"
printf 'recorded  %s.manifest\n' "$output"
printf '%s\n' 'next: cargo xtask build-ebpf --target-btf; inspect .BTF/.BTF.ext and test only in the matching disposable VM.'
