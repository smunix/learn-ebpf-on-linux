# 14-sentinel-capstone

## Status

This is a quarantined capstone experiment, **not a production-shaped or production-ready service**. It shares sample 13's audit-first scoped decision path, preserves prior LSM returns, and emits policy generation/reason fields. It does not yet implement two independently staged policy generations, an active-generation selector, pin ownership/schema reconciliation, link-update rollback, a service privilege split, or a tested recovery window.

The LSM program is absent from the default object because the checked-in kernel layouts are manual fixtures. In a disposable target-VM worktree, run `just target-bindings -- --install-tool` and `just target-btf-object`, inspect the recorded BTF digest and object `.BTF.ext`, then use the separately named object with `--target-btf-fixture`. Active-BPF-LSM preflight and isolated load/attach/detach/rollback evidence remain prerequisites. Ring telemetry is lossy and is never used as the enforcement decision. No default pin persists state; owned-object drop detaches.
