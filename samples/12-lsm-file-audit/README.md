# 12-lsm-file-audit

## Quarantine and behavior

This BPF-LSM sample is audit-only and preserves a nonzero prior LSM return. Policy hits carry a policy generation and reason; unavailable identity and prior-denial observations have explicit reasons when telemetry can be reserved. Telemetry failure never changes the decision. `(device,inode)` is an in-session teaching identity, not a complete pathname or cross-filesystem security model.

The sample is excluded from the default object because `file`/`inode` access depends on the quarantined manual `vmlinux.rs`. In a disposable worktree on the target VM, run `just target-bindings -- --install-tool` and `just target-btf-object`, inspect the generated manifest and `.BTF.ext`, then pass `samples/target/ebpf/samples-ebpf-target-btf` with `--target-btf-fixture`. The acknowledgment is not proof. Audit mode never denies; drop detaches. Hard links, rename, overlay, FUSE, network, and pseudo filesystems remain explicit unvalidated cases.
