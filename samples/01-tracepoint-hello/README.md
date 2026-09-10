# 01-tracepoint-hello

## Purpose and data path

This is the baseline kernel sample: `sched/sched_switch` increments key `0` in a one-entry `PerCpuArray<u64>`. It does not read tracepoint context, emit a payload, use a ring/perf buffer, access task memory, require BTF, or pin maps. The runner sums all per-CPU slots after a bounded observation interval.

## Build and run

Build as an ordinary user, then run only the loader with the authority required by the approved disposable host:

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 01-tracepoint-hello --duration 10
```

Expected output is `sched_switch_count=<n>`. The runner first requires a readable local `sched/sched_switch/format`; no field offset is assumed. Dropping the owned Aya object detaches the link, and no pin remains. Runtime success still depends on the target kernel, tracefs visibility, BPF policy, and verifier.
