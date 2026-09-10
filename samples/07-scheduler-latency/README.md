# 07-scheduler-latency

## Quarantine status

The former implementation decoded `sched_wakeup` and `sched_switch` using hard-coded byte offsets. Tracepoint field layouts are target data, not a universal ABI, so those programs have been removed from the default object and the runner refuses this sample.

A future implementation must generate decoder constants from archived, exact target `events/sched/*/format` fixtures, test those fixtures, and report unmatched switches, failed insertions, LRU eviction ambiguity, missed wakeups, and PID reuse limitations. The intended metric is **wakeup-to-observed-run latency**, not total application latency. Sample 01 intentionally uses `sched_switch` without reading any payload and is the safe default.
