# 15-map-iterator-telemetry

This advanced sample combines a **loss-sensitive event stream** with a **best-effort state snapshot**. The `telemetry_sys_enter` tracepoint program observes `syscalls/sys_enter_openat`, emits one fixed-size `TelemetryEvent` through the shared ring buffer, and updates the `TELEMETRY` per-CPU hash map under a composite `(tgid, uid, cgroup_id)` key. Per-CPU storage avoids unsupported spin-lock helpers in a tracepoint program. The runner drains live events during a bounded interval and then walks and reduces the map through a custom Rust iterator adaptor.

## Default, portable laboratory path

Build as an ordinary user inside `nix develop`:

```console
cd samples
cargo xtask build-ebpf
cargo build -p sample-runner
```

On an approved disposable VM, attach only the already-built loader:

```console
sudo ./target/debug/sample-runner run 15-map-iterator-telemetry --duration 10
```

Generate harmless workload from another terminal, for example:

```console
for file in /etc/hostname /etc/os-release /proc/self/status; do
  cat "$file" >/dev/null
done
```

The live `telemetry ...` lines are ring-buffer records. The final `snapshot source=userspace-percpu-reduce ...` lines come from `SnapshotIter`, a custom Rust adaptor over Aya's per-CPU hash map. It obtains each key with `BPF_MAP_GET_NEXT_KEY`, looks up one value per possible CPU, sums counts and observed-byte units, and takes the maximum last-seen timestamp. This walk has arbitrary order and is not an atomic snapshot. Concurrent inserts and current-CPU updates can make values reflect nearby but different instants.

## Kernel-executed `bpf_map_elem` iterator

The optional `telemetry_map_iter` program uses `iter/bpf_map_elem` and `bpf_seq_write()` to export binary `TelemetrySnapshot` records from inside the kernel. After the bounded live interval, user space first reduces `TELEMETRY` and stages those values into the ordinary `TELEMETRY_EXPORT` hash map; the iterator attaches to that immutable export map. Its context is target BPF Type Format (BTF), and Aya 0.14 does not expose map-target parameters through `Iter::attach()`. The runner therefore demonstrates the exact Linux `BPF_LINK_CREATE` plus `BPF_ITER_CREATE` ABI in a small, audited wrapper.

Use this mode only in a disposable worktree on the exact target VM:

```console
cd /home/ubuntu/learn-ebpf-on-linux
nix develop
just target-bindings -- --install-tool
just target-btf-object
cd samples
cargo build -p sample-runner

sudo ./target/debug/sample-runner run 15-map-iterator-telemetry \
  --object target/ebpf/samples-ebpf-target-btf \
  --target-btf-fixture \
  --kernel-map-iterator \
  --duration 10
```

The target-BTF acknowledgment is a guard, not proof. Retain the generated binding manifest, object digest, `.BTF.ext` inspection, verifier output, load/attach result, and cleanup evidence. The iterator link and iterator file descriptor are owned by the process and are closed on exit; no object is pinned.

## Concurrency and loss contract

The live map is `BPF_MAP_TYPE_PERCPU_HASH`: every CPU updates only its private `TelemetryCounter` for a key, so the BPF hot path needs no atomic read-modify-write and no spin-lock helper. The custom userspace iterator merges the returned `PerCpuValues`; an individual copy can still overlap a producer update, and the whole walk spans time. The optional kernel iterator reads only `TELEMETRY_EXPORT`, which user space populates after the observation interval and never mutates during the iterator session. The ring buffer is multi-producer/single-consumer and preserves reservation order, but it never blocks a producer. A failed reservation increments `DROPPED`; the final `transport_metrics` line reports producer reservation failures and userspace parse rejections. The map remains useful when individual ring records are lost, while the ring preserves event detail that aggregation deliberately discards.
