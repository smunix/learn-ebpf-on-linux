# 03-exec-ringbuf

## Purpose and transport contract

This sample emits one fixed-size same-host record for each `sched/sched_process_exec` event. Schema version 1 includes an explicit kind, total record length, flags, and reserved-zero fields. The consumer validates those fields and dispatches by kind before decoding fixed-width native-endian bytes. This is not a durable or cross-machine serialization format.

## Build and run

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 03-exec-ringbuf --duration 10
```

The producer does not retry a full ring. It increments the per-CPU `DROPPED` map, and the runner prints `producer_reserve_dropped`, `consumer_parse_rejected`, `userspace_queue_dropped`, and `intentional_sampling_skipped`. The latter two are zero because this runner has no intermediate queue and applies no sampling. A ring stream is best-effort telemetry, not a complete audit record. Timeout and object drop detach and close the ring.
