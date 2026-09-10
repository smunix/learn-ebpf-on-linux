# 11-container-attribution

## Purpose and limits

This sample records host TGID/TID, command, timestamp, and cgroup ID at `sys_enter_execve`. A cgroup ID is a kernel attribution key, **not container identity**. Correct labeling requires a time-bounded user-space join to runtime/control-plane lifecycle metadata, plus host/boot context. An in-container cgroup pathname alone is insufficient.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 11-container-attribution --duration 10
```

The ring stream is best-effort; the runner validates its versioned same-host ABI and reports loss metrics. It does not deny execution, alter namespaces, or pin state. Dropping the object detaches the tracepoint.
