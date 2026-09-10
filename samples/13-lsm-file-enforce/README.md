# 13-lsm-file-enforce

## Quarantine and enforcement boundary

This experiment is audit-first. Denial is possible only when `--enforce` is explicit, the protected user-space path is under `/tmp/learn-ebpf-*`, policy identity matches `(device,inode)`, and the current cgroup ID matches a nonzero configured cgroup. It preserves prior nonzero LSM returns. Records include action, reason, and policy generation; telemetry loss does not broaden or suppress policy decisions.

The program is excluded from the default object pending target-generated BTF bindings and relocation/runtime evidence. In a disposable target-VM worktree, run `just target-bindings -- --install-tool` and `just target-btf-object`, inspect the manifest and `.BTF.ext`, then use the separately named object with `--target-btf-fixture`. Test hard links, rename, filesystem classes, link loss, rollback, and reboot before drawing conclusions. This hook does not cover every later read or execution path and is not production-ready. Build as an ordinary user; elevate only the loader. Detach before removing disposable files/cgroups.
