# 06-core-process-inspector

## Quarantine status

This sample is **not present in the default loadable object**. It needs typed `sched_process_fork` access and kernel-structure bindings. The checked-in `vmlinux.rs` is a hand-maintained layout fixture with filler arrays; it is neither generated from this host nor evidence of working CO-RE relocation.

In a disposable worktree on the exact target VM, run `just target-bindings -- --install-tool`, then `just target-btf-object`. Inspect `.BTF`/`.BTF.ext` and symbols in `samples/target/ebpf/samples-ebpf-target-btf`, retain `vmlinux.rs.manifest` and the object hash, then pass that object explicitly with `--object ... --target-btf-fixture`. The acknowledgment is a guard, not automated proof. Without that process the runner refuses this sample. No portability or production-readiness claim is made.
