# 02-syscall-counter

## Purpose and data path

This sample attaches to the locally discovered `syscalls/sys_enter_openat` tracepoint and counts calls by **TGID** in a bounded `PerCpuHashMap`. Per-CPU values avoid cross-CPU counter races. A new-key insertion can fail at capacity or for another kernel error; the `MAP_ERRORS` per-CPU map records `counter_insert_failed` and the runner prints it.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 02-syscall-counter --duration 10
```

Expected output uses `tgid=<id> count=<sum>`, followed by map-error metrics. This is aggregation, not an audit log; key capacity is 16,384 and no pins are created. The runner refuses to attach if the exact local event format is not readable. Dropping the loader detaches.
