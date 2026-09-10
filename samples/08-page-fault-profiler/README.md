# 08-page-fault-profiler

## Purpose and data path

The default attaches only to the locally discovered `exceptions/page_fault_user` tracepoint. Each hit increments key `0` in a true `PerCpuArray<u64>`; no record is emitted per fault and the kernel-fault tracepoint is not attached. The runner sums the slots and prints `user_page_faults=<n>` after a bounded interval.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 08-page-fault-profiler --duration 10
```

The runner refuses the sample when that architecture/configuration-specific event is absent or unreadable. The count is an observed user page-fault tracepoint count; it does not imply disk I/O, a crash, or a specific latency cost. No address is read, no transport queue exists, and object drop detaches.
