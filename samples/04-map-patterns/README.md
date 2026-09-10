# 04-map-patterns

## Purpose and map contracts

This focused demonstration combines a bounded per-TGID `PerCpuHashMap`, a race-free `PerCpuArray` aggregate, an LRU timestamp map, and a ring record. It creates no pins. The per-CPU maps avoid shared non-atomic counter updates. Hash and LRU insertion failures are counted in `MAP_ERRORS`; LRU capacity may also evict old keys, so it is not an audit store.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 04-map-patterns --duration 10
```

The runner requires the exact local `syscalls/sys_enter_openat` event, prints TGID totals, `bucket0`, map insertion failures, and ring transport health. Per-event ring output can be lossy; aggregation remains the primary result. Object drop detaches, and no bpffs cleanup is needed.
