# 10-cgroup-connect-audit

## Purpose and scope

This audit-only program attaches to `BPF_CGROUP_INET4_CONNECT` for one caller-supplied cgroup and returns allow (`1`). It observes IPv4 connect destinations only; it is not a firewall and does not cover IPv6. It emits best-effort, schema-validated ring records and reports producer/consumer loss metrics.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 10-cgroup-connect-audit --cgroup /sys/fs/cgroup/learn-ebpf-demo --duration 10
```

Before use, confirm cgroup v2 is mounted, the target is delegated and contains the intended workload, DNS/proxy behavior is understood, and `Single` attachment will not conflict with existing policy. Validate address and port byte order against a known endpoint. Drop detaches; remove only an empty disposable cgroup.
