#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, section-ref, figure-ref, table-ref, listing-ref, definition-target

#chapter-opener(part: "VII", chapter: "19")
= Custom Map Iterators and Real-Time Ring-Buffer Telemetry <ch-19>

A useful security sensor needs two views of the same activity. The first is an ordered stream of individual events: *what just happened?* The second is a bounded summary of accumulated state: *what has happened often, for whom, and how recently?* Sending every detail through one channel overloads the consumer; retaining only counters destroys temporal evidence. This chapter builds both views in one complete Rust and Aya sample.

Sample `15-map-iterator-telemetry` attaches `telemetry_sys_enter` to `syscalls/sys_enter_openat`. For every invocation, the eBPF program updates a central-processing-unit-local value in a per-CPU Berkeley Packet Filter (BPF) hash map and attempts to reserve one fixed-size `TelemetryEvent` in a BPF ring buffer. The ordinary runner drains live records and then uses a custom Rust iterator to merge the map’s CPU-local values. An optional, target-BPF-Type-Format (BTF) path stages the merged results into an immutable export map, loads a true kernel BPF map-element iterator, and exports binary snapshot records with `bpf_seq_write()`.

This is an advanced chapter because the syntax is the easy part. The engineering problem is to state the concurrency, ordering, loss, snapshot, verifier, and portability contracts precisely enough that a quiet terminal cannot be mistaken for an idle kernel.

== Prerequisites and safety boundary <ch19-sec-prerequisites>

Complete #chapter-ref(<ch-06>, title: "events and user space"), #chapter-ref(<ch-13>, title: "stateful design"), #chapter-ref(<ch-14>, title: "verifier reasoning"), and #chapter-ref(<ch-15>, title: "BTF and CO-RE") first. You should already understand map file descriptors, tracepoint attachment, `repr(C)` Application Binary Interface (ABI) records, per-CPU loss counters, BTF-derived contexts, and the difference between compilation and `BPF_PROG_LOAD` acceptance.

Run the attaching commands only on an authorized disposable NixOS virtual machine (VM). Build as an ordinary user. Elevate only the already-built loader for a bounded interval. This sample observes `openat` system calls and does not enforce policy, but it still loads kernel programs and creates temporary links. The optional kernel iterator requires target-generated BTF bindings and direct use of the stable BPF system-call ABI. A missing prerequisite is a stop condition, not an invitation to weaken lockdown, global BPF policy, or kernel hardening.

#security-note(title: "Observation still needs a data policy")[The key contains a thread-group identifier (TGID), user identifier (UID), and cgroup ID. Those fields can identify workloads and users. Keep the output local to the disposable laboratory, do not add pathnames or arguments casually, and define retention before adapting this design to production.]

== Learning objectives <ch19-sec-objectives>

After this chapter, you should be able to:

- explain why a ring buffer and a state map answer different questions;
- reason about multi-producer/single-consumer (MPSC) ring-buffer reservation, submission, ordering, wakeups, and loss;
- write a verifier-safe reserve/write/submit path in `no_std` Rust;
- choose per-CPU state when the tracepoint program type cannot use `bpf_spin_lock`;
- distinguish race-free CPU-local updates, best-effort cross-CPU reduction, and an immutable export snapshot;
- implement a custom Rust iterator using `BPF_MAP_GET_NEXT_KEY`, `PerCpuValues` reduction, and deletion-race handling;
- explain the difference between a BPF iterator *program* and an open-coded BPF iterator;
- load `iter/bpf_map_elem`, attach it to one map, create an iterator file descriptor, and decode `bpf_seq_write()` records; and
- state why the kernel iterator targets a staged ordinary hash map instead of the live per-CPU map.

== One producer, two telemetry planes <ch19-sec-dual-plane>

Figure #figure-ref(<fig-ch19-dual-plane>, title: "the dual-plane telemetry architecture") is the central model. A single tracepoint invocation performs two independent publications. The map update preserves aggregate state even if the event transport is full. The ring-buffer reservation preserves event detail when capacity is available. Neither publication is allowed to silently stand in for the other.

#figure(
  image("../../assets/diagrams/generated/19-telemetry-dual-plane.svg", width: 100%),
  caption: [Dual-plane telemetry: live detail moves through the ring buffer, aggregate state remains in a keyed map, and independent health counters make loss visible.]
) <fig-ch19-dual-plane>

#definition-target("def-ch19-event-plane", "Event plane")[A bounded stream of individual records whose ordering and loss contract are part of the interface. In this sample, `EVENTS` is a shared BPF ring buffer and every successful reservation carries one `TelemetryEvent`.]

#definition-target("def-ch19-state-plane", "State plane")[A keyed, mutable summary whose values can be inspected after—or while—events occur. In this sample, `TELEMETRY` aggregates count, observed-byte units, and last-seen time for each `(tgid, uid, cgroup_id)` key.]

The event plane answers sequence-sensitive questions, such as whether two events occurred in a particular transport order or which central processing unit (CPU) produced a record. The state plane answers cardinality and recovery questions, such as how many observations accumulated for a workload even when some individual event reservations failed. A resilient telemetry agent commonly needs both.

Table #table-ref(<tab-ch19-plane-contracts>, title: "event and state plane contracts") prevents several common category errors.

#figure(
  table(
    columns: (1.05fr, 1.4fr, 1.4fr),
    inset: 6pt,
    stroke: 0.45pt + rgb("#B8CDD2"),
    table.header([*Property*], [*Ring-buffer event plane*], [*Hash-map state plane*]),
    [Unit], [One fixed-size event record.], [One aggregate value per key.],
    [Ordering], [Reservation order across producers; later records wait behind an earlier uncommitted reservation.], [Iteration order is arbitrary and not a temporal order.],
    [Backpressure], [Reservation fails; the producer never waits for space.], [Insert can fail at capacity; existing-key updates stay CPU-local.],
    [Loss evidence], [`DROPPED` counts failed producer reservations; parser failures are separate.], [`MAP_ERRORS` counts an insert that still failed after the concurrent-insert retry.],
    [Snapshot meaning], [Each submitted record is immutable to the consumer.], [The live walk spans time; the optional kernel iterator reads a staged immutable export.],
    [Best use], [Forensics, sequences, detailed audit context.], [Dashboards, recovery, cardinality, latest-state queries.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [The event and state planes are complementary, not interchangeable.]
) <tab-ch19-plane-contracts>

== Designing the shared ABI before writing the program <ch19-sec-abi>

The canonical types live in `samples/common`, which compiles with `std` for user space and as `no_std` for the eBPF target. #listing-ref(<lst-ch19-abi>, title: "the telemetry ABI") shows four distinct records rather than one overloaded structure.

#code-listing(
  "Telemetry key, per-CPU counter, live event, and snapshot record",
  read("../../../samples/common/src/lib.rs").split("\n").slice(115, 156).join("\n"),
  language: "rust",
  source-path: "samples/common/src/lib.rs"
) <lst-ch19-abi>

`TelemetryKey` uses fixed-width fields. The cgroup ID prevents the same TGID and UID in two cgroups from collapsing into one bucket, but it remains an attachment-time kernel identity, not a durable container name. TGIDs are reused. Cgroups can be removed and recreated. Production correlation therefore needs a lifecycle-aware workload identity outside this hot-path key.

`TelemetryCounter` contains three fixed-width fields. In the live `BPF_MAP_TYPE_PERCPU_HASH`, the kernel allocates one such value per possible CPU for each key. A producer updates only the slot of the CPU on which it is currently executing. This avoids a cross-CPU read-modify-write race without requiring a lock helper that the tracepoint program type cannot call.

`TelemetryEvent` is transport data. Its header declares schema version, total length, and kind before the consumer reads later offsets. `TelemetrySnapshot` is iterator output. It contains the key, counter tuple, and an iterator position. That position is useful for diagnostics; it is not a transaction ID, timestamp, ordering proof, or promise that no key was skipped or repeated.

#portability-note(title: "repr(C) is not a durable wire protocol")[The sample is a same-host teaching ABI. It uses native-endian decoding and a compiler-defined C representation shared by one workspace. If records leave the host, define byte order, alignment, version evolution, maximum length, authentication, and retention explicitly. Reserved-zero fields make compatible extension possible; they do not create it automatically.]

== Updating hot-path state safely <ch19-sec-map-update>

A normal hash map is shared by all CPUs. The read-modify-write sequence `value.events += 1` can lose updates when two producers execute concurrently. A tempting repair is an embedded `bpf_spin_lock`, but `telemetry_sys_enter` is a tracepoint program and current kernels do not permit tracing programs to call the spin-lock helpers. Compilation would still succeed; `BPF_PROG_LOAD` would reject the program. This is precisely why helper compatibility belongs in design, not only in build verification. #cite(<bpf-helpers>)

The sample instead uses `BPF_MAP_TYPE_PERCPU_HASH`. Every logical key has one value slot per possible CPU, and a BPF producer obtains only the current CPU’s slot. The non-atomic Rust read-modify-write is consequently race-free with respect to other CPUs. Preemption and migration semantics are handled by the BPF execution model while the program runs; user space is responsible for reducing the CPU-local values later.

#listing-ref(<lst-ch19-map-update>, title: "the per-CPU aggregate update") is the complete helper used by the tracepoint. The existing-key path updates only ordinary fields and invokes no helper. The absent-key path inserts an initial current-CPU value with numeric flag `1`, the stable userspace ABI (UAPI) value for `BPF_NOEXIST`. If another CPU creates the key between lookup and insertion, the loser retries lookup and updates its own CPU-local slot. Only a failed insert followed by a failed retry increments `TELEMETRY_INSERT_FAILED`.

#code-listing(
  "Per-CPU telemetry update with concurrent-insert retry",
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(114, 144).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs"
) <lst-ch19-map-update>

#verifier-note(title: "Build success did not make the lock design loadable")[`bpf_spin_lock` has strict map-layout and control-flow rules, but the first question is program-type availability. The helper is unavailable to tracepoint programs. Per-CPU storage removes that unsupported call and the shared update race at the same time. Always check a helper’s target-kernel allowlist before relying on a source-level API.]

Per-CPU storage does not make a whole-map snapshot atomic. User space performs separate key and value syscalls while producers may continue to run. A returned per-CPU buffer can itself overlap a current-CPU update. The sample calls this result *best effort*. When the optional kernel iterator needs stable input, user space first reduces the live map after the bounded observation interval and copies those merged values into `TELEMETRY_EXPORT`. That ordinary hash map is not mutated during the iterator session.

== Producing the live ring-buffer record <ch19-sec-ring-producer>

The BPF ring buffer is represented as `BPF_MAP_TYPE_RINGBUF`. It is a shared MPSC circular transport: producers can execute on many CPUs while one logical consumer advances the consumer position. The map’s `max_entries` is the byte capacity and must be a power of two. The shared design avoids allocating an equally large buffer for every CPU and preserves reservation order across CPUs. #cite(<bpf-ringbuf>)

#listing-ref(<lst-ch19-producer>, title: "the telemetry tracepoint producer") updates the state plane first and then attempts to publish the event plane. The two operations intentionally do not form one transaction.

#code-listing(
  "Tracepoint producer for aggregate state and real-time events",
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(183, 216).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs"
) <lst-ch19-producer>

`reserve::<TelemetryEvent>(0)` requests a verifier-known constant size. On success, Aya returns a tracked reference to ring-buffer memory. `write(event)` initializes the complete record, and `submit(0)` transfers ownership to the consumer. Every successful reserve must reach exactly one submit or discard. Forgetting both is a verifier-visible reference leak; using the slot after submit is a use-after-release.

On failure, `reserve` returns `None`. The program increments a per-CPU `DROPPED` counter and returns normally. It does not spin, sleep, allocate, or change a future authorization result. A ring reservation can fail because no capacity remains. In non-maskable interrupt (NMI) context, it can also fail when the internal reservation lock cannot be acquired even if bytes appear available. A failed reservation creates no event record, so loss must be exported through a different channel. #cite(<bpf-ringbuf>)

Figure #figure-ref(<fig-ch19-ring-sequence>, title: "reserve, submit, and loss") follows both branches.

#figure(
  image("../../assets/diagrams/generated/19-ringbuf-sequence.svg", width: 92%),
  caption: [Ring-buffer producer sequence: a reservation either becomes one submitted record or one independently counted loss.]
) <fig-ch19-ring-sequence>

The kernel assigns order when producers reserve space. Commit is lockless, but a later committed record does not become visible before an earlier reservation is committed or discarded. This gives a useful cross-CPU transport order. It does not mean a userspace-generated sequence number obtained before reservation will match transport order, nor that timestamps from different clocks or hosts become globally ordered.

The default notification strategy is self-pacing: a commit notifies when the consumer has caught up to that record. `BPF_RB_NO_WAKEUP` and `BPF_RB_FORCE_WAKEUP` permit manual batching, but they should be introduced only after measurement. Busy polling lowers latency at a CPU cost; epoll-style readiness lowers idle cost. Aya’s user-space `RingBuf` exposes a file descriptor for epoll, mio, or Tokio `AsyncFd`, and `next()` yields at most one outstanding borrowed item at a time. #cite(<aya-014-ringbuf>)

#concept(title: "Backpressure is a system property")[A larger ring delays saturation but does not make the pipeline lossless. Consumer scheduling, parsing, downstream queues, disk or network export, and retention all have independent capacity. Export producer reservation failures, consumer parse rejections, downstream drops, queue depth, and lag as separate metrics.]

== Three meanings of “map iterator” <ch19-sec-three-iterators>

The phrase *BPF iterator* is overloaded. Before writing code, identify which of the following mechanisms is intended.

#figure(
  table(
    columns: (1.15fr, 1.35fr, 1.55fr),
    inset: 6pt,
    stroke: 0.45pt + rgb("#B8CDD2"),
    table.header([*Mechanism*], [*Where iteration runs*], [*Termination and output contract*]),
    [Userspace map walk], [A process repeats `BPF_MAP_GET_NEXT_KEY` and lookup syscalls.], [Ends when next-key returns `ENOENT`; output is ordinary typed user memory.],
    [BPF iterator program], [The kernel invokes a `BPF_PROG_TYPE_TRACING` callback once per selected kernel object.], [A `seq_file` read drives the walk; the program writes formatted or binary bytes with seq helpers.],
    [Open-coded BPF iterator], [Another BPF program calls iterator-specific new/next/destroy kfuncs.], [The verifier models eventual `NULL` from `next`; destroy is mandatory and iterator state lives on the BPF stack.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Three iterator mechanisms with different execution and verifier models.]
) <tab-ch19-iterator-kinds>

Open-coded iterators are important when a BPF program itself must loop over kernel-managed objects. They use a constructor, a nullable `next`, and a destructor kfunc. The verifier explores the exhausted branch and the element branch, then uses the registered iterator contract to conclude that `next` eventually returns null. Their stack-resident iterator state contributes to the BPF stack budget. This sample does not use that mechanism; it uses the first two rows. #cite(<bpf-iterators>)

== Building a custom userspace map iterator <ch19-sec-userspace-iterator>

Aya’s `PerCpuHashMap::keys()` visits keys in arbitrary order. Internally, a map walk asks the kernel for the key after a current key and then looks up that key. If the current key is deleted, `BPF_MAP_GET_NEXT_KEY` can return the *first* key rather than the conceptual successor. Repetition is therefore possible under concurrent deletion, and batch lookup is preferable when deletion is interleaved deliberately. #cite(<bpf-map-hash>) #cite(<aya-014-percpu-hash-map>)

The sample writes a custom adaptor around a reduction pipeline. For each key, Aya returns `PerCpuValues<TelemetryCounter>`. `merge_per_cpu` wraps sums for `events` and `observed_bytes` and retains the maximum `last_seen_ns`. A key that disappears between next-key and lookup is treated as a benign concurrent deletion; other syscall errors remain visible.

#code-listing(
  "Custom snapshot iterator and per-CPU reduction",
  read("../../../samples/runner/src/main.rs").split("\n").slice(539, 619).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-ch19-userspace-iterator>

`SnapshotIter` is intentionally small. It adds a monotonically increasing position to successful reduced entries and preserves map errors. The position describes emission order in this one process; hash order is arbitrary, so it must never be interpreted as event time or stable key order.

CPU-local updates avoid producer-versus-producer loss, but a userspace copy can overlap a producer write. Inserts, deletes, and updates can also occur between keys. This is why the output says `snapshot`, not `checkpoint`. For strict export semantics, detach or gate the producer, complete the reduction, and publish the resulting generation through an immutable map.

#kernel-detail(title: "Batch lookup is not automatically a snapshot")[Batch operations reduce syscall overhead and avoid the deleted-current-key restart behavior, but concurrent writers can still change state while batches are copied. Performance and atomicity are separate properties.]

== Writing a kernel `bpf_map_elem` iterator <ch19-sec-kernel-iterator>

A BPF iterator program is activated by reading an iterator file descriptor. For `bpf_map_elem`, user space must attach the program to one supported map. The kernel walks that map and invokes the program with a BTF-described `bpf_iter__bpf_map_elem` context containing metadata, a map pointer, a key pointer, and a value pointer. On the final stop callback, key and value can be null. The program must check them before dereference. #cite(<bpf-iterators>)

#listing-ref(<lst-ch19-kernel-iterator>, title: "the kernel map-element iterator") uses a manual `iter/bpf_map_elem` ELF section because Aya eBPF 0.2.1 has no iterator attribute macro. The program is feature-gated behind `target-btf`; the context binding must be regenerated from the booted target before the object is trusted.

#code-listing(
  "Kernel BPF map-element iterator with binary seq output",
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(288, 318).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs"
) <lst-ch19-kernel-iterator>

`meta->seq` is the `seq_file` destination. `bpf_seq_write()` copies the fixed-size binary snapshot into that stream. Binary output avoids formatting overhead and parsing ambiguity, but it makes ABI validation mandatory. The runner rejects a byte count that is not an exact multiple of `size_of::<TelemetrySnapshot>()` and decodes every field by explicit offset.

The iterator does not target the live per-CPU map. After the observation loop, user space obtains the same reduced snapshots used by the default report and inserts them into `TELEMETRY_EXPORT`, an ordinary hash map that no eBPF producer updates. The kernel iterator attaches to that map and copies each immutable `TelemetryCounter`. The session is stable because of the staging protocol, not because kernel execution makes an arbitrary live walk atomic.

#code-listing(
  "Stage the reduced generation into the iterator's export map",
  read("../../../samples/runner/src/main.rs").split("\n").slice(626, 643).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-ch19-export-stage>

#verifier-note(title: "Attach-time key/value size checking")[For a map-element iterator, the kernel records the program’s maximum key read and value read/write access. Attachment rejects a target whose key or value is too small for those accesses. This protects bounds, not meaning: equal-sized but semantically different key/value layouts can still be wrong. Bind the iterator only to the intended map and verify its metadata.]

== Loading and attaching the map-targeted iterator <ch19-sec-iterator-loader>

Aya 0.14 provides `Iter::load(iter_type, btf)` and a parameterless `Iter::attach()`. A map-element iterator needs extra link information containing the target map file descriptor. The high-level attach method does not expose that parameter. The runner therefore uses Aya for object parsing, BTF lookup, program verification, and loading, then issues two narrow Linux BPF syscalls itself. #cite(<aya-014-iter>)

The sequence is:

1. load `telemetry_map_iter` with iterator type `bpf_map_elem` and target BTF;
2. reduce the live per-CPU `TELEMETRY` map and stage the results in `TELEMETRY_EXPORT`;
3. call `BPF_LINK_CREATE` with `attach_type = BPF_TRACE_ITER` and `iter_info.map.map_fd` set to `TELEMETRY_EXPORT`;
4. call `BPF_ITER_CREATE` with the resulting link file descriptor;
5. read the iterator descriptor to end-of-file, which drives the kernel walk; and
6. close the iterator and link descriptors through Rust ownership.

#code-listing(
  "Stable UAPI structures and map-targeted iterator attachment",
  read("../../../samples/runner/src/main.rs").split("\n").slice(644, 713).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-ch19-iterator-attach>

The small `bpf_fd` wrapper calls `SYS_bpf`, converts a nonnegative result into `OwnedFd`, and turns a negative result into the current `io::Error`. The C-compatible structures contain only fields through the last member used by each command and are eight-byte aligned. Numeric command and attach values are stable UAPI values, not kernel-internal addresses. Still, the wrapper is a maintenance boundary: tests should compare its layout against the pinned target UAPI headers when the supported kernel matrix changes.

#code-listing(
  "Load, read, validate, and decode binary iterator records",
  read("../../../samples/runner/src/main.rs").split("\n").slice(714, 750).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-ch19-iterator-read>

Reading until end-of-file is one iteration session. To repeat the walk, create a new iterator descriptor from the retained link. Pinning the iterator link in BPF filesystem (bpffs) could expose a proc-like file, but this sample intentionally creates no pin. Process exit closes its descriptors and releases the temporary link.

== Reproducible NixOS lab: default path <ch19-sec-lab-default>

The default lab avoids target-BTF iterator context risk. It builds the shared eBPF object, attaches only the tracepoint program, consumes live events for ten seconds, and uses the custom userspace iterator to reduce the final per-CPU values.

#terminal-listing(title: "Build sample 15 without root", "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\ncd samples\ncargo fmt --all -- --check\ncargo test --workspace --exclude samples-ebpf --locked\ncargo xtask build-ebpf\ncargo build -p sample-runner\nllvm-objdump -t target/ebpf/samples-ebpf | grep telemetry_sys_enter")

In terminal A, run the already-built loader. In terminal B, generate harmless file-open activity. The observation window is capped at 60 seconds by the runner even if a larger duration is requested.

#terminal-listing(title: "Run the default telemetry and userspace-iterator path", "# Terminal A\ncd /home/ubuntu/learn-ebpf-on-linux/samples\nsudo ./target/debug/sample-runner run 15-map-iterator-telemetry --duration 10\n\n# Terminal B\nfor file in /etc/hostname /etc/os-release /proc/self/status; do\n  cat \"$file\" >/dev/null\ndone")

#expected-output(title: "Default-path evidence")[A successful target prints `telemetry` records while the ring buffer is drained, followed by `snapshot source=userspace-percpu-reduce` records, `map_errors`, and `transport_metrics`. Exact TGIDs, UIDs, cgroup IDs, CPU numbers, timestamps, ordering, and counts are target-dependent. Attach failure is a valid incompatibility result and must retain its verifier or system-call error.]

Interpret the final health lines before interpreting silence. `producer_reserve_dropped=0` means the eBPF program observed no failed reservation during this bounded run; it does not prove that a later userspace or external exporter lost nothing. `consumer_parse_rejected=0` means this process rejected no malformed or unsupported record; it does not authenticate records or prove durable storage.

== Optional lab: the target-BTF kernel iterator <ch19-sec-lab-kernel>

The optional path adds `bpf_iter__bpf_map_elem`, `bpf_iter_meta`, and their dependencies to the generated target bindings. It emits a separately named `samples-ebpf-target-btf` object. Do not overwrite the reviewed fixture in a shared worktree and then assume it remains valid on another kernel.

#terminal-listing(title: "Generate, build, and inspect the target-BTF object", "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\n./scripts/generate-target-bindings.sh --install-tool\ncd samples\ncargo xtask build-ebpf --target-btf\ncargo build -p sample-runner\nreadelf -SW target/ebpf/samples-ebpf-target-btf | grep -E '\\.BTF(\\.ext)?'\nllvm-objdump -t target/ebpf/samples-ebpf-target-btf | grep telemetry_map_iter\nsha256sum target/ebpf/samples-ebpf-target-btf")

The generator writes a manifest beside the binding with kernel release, architecture, source BTF hash, Aya tool revision, timestamp, and output hash. Preserve it with the verifier log and runtime evidence.

#terminal-listing(title: "Run the explicit kernel-iterator mode", "cd /home/ubuntu/learn-ebpf-on-linux/samples\nsudo ./target/debug/sample-runner run 15-map-iterator-telemetry \\\n  --object target/ebpf/samples-ebpf-target-btf \\\n  --target-btf-fixture \\\n  --kernel-map-iterator \\\n  --duration 10")

The `--target-btf-fixture` flag is an acknowledgment, not automated proof. The program can still be rejected because the target lacks an iterator registration, helper, configuration, privilege, or compatible map-target contract. `snapshot source=kernel-bpf-iterator` records come from the immutable export generation explained in #section-ref(<ch19-sec-kernel-iterator>, title: "the kernel iterator").

== Verifier and portability checklist <ch19-sec-verifier-portability>

Before supporting a kernel, record all of the following:

- kernel release, architecture, configuration, lockdown state, and privilege model;
- readable `/sys/kernel/btf/vmlinux` and the exact BTF digest used for generation;
- successful load and attachment of `telemetry_sys_enter`;
- successful load of `telemetry_map_iter` as `bpf_map_elem` and map-targeted `BPF_LINK_CREATE`;
- verifier logs for both objects, including instruction count, stack depth, and helper rejection if any;
- `TELEMETRY` per-CPU map type, key/value sizes, maximum entries, possible-CPU count, and reduction rule;
- `TELEMETRY_EXPORT` type, key/value sizes, staging completion, and no-writer invariant during iteration;
- ring-buffer byte capacity and power-of-two validation;
- event and snapshot ABI sizes, native byte order, and schema version;
- producer reservation failures, map insert failures, consumer parse failures, and downstream loss; and
- descriptor and link cleanup after normal exit and interruption.

#portability-note(title: "Version numbers are hints, not capability proofs")[Ring buffers and BPF iterator programs appeared in Linux 5.8, but a release number alone does not establish BTF availability, iterator target registration, helper allowlists, verifier behavior, privileges, or distribution configuration. Probe, load, attach, read, and detach on every supported kernel/configuration/architecture tuple.]

The default object contains `telemetry_sys_enter` but excludes `telemetry_map_iter`; the target-BTF object includes both. This feature boundary prevents a placeholder context layout from silently entering the ordinary build. It also makes the artifact name part of the operating procedure. A production loader should inspect build metadata instead of relying only on a filename.

== Failure analysis and troubleshooting <ch19-sec-failures>

A few failure signatures deserve explicit interpretation:

- *`EPERM` during load or attach:* authority, lockdown, or unprivileged-BPF policy may block the operation. Do not respond by granting broad permanent capability to a build tool.
- *BTF function lookup failure for `bpf_iter_bpf_map_elem`:* the target BTF or iterator registration is unavailable. Keep the default userspace iterator path.
- *`EINVAL` or `EACCES` during map-targeted link creation:* inspect iterator type, link-info length, target map type, key/value access size, and helper compatibility.
- *Verifier reports an outstanding ring reference:* a successful reserve path did not submit or discard exactly once.
- *Verifier rejects a spin-lock helper in the tracepoint:* the design used a helper unavailable to this program type. Keep the per-CPU hot path rather than forcing an unsupported lock.
- *Repeated keys in a userspace walk:* concurrent deletion may have caused next-key to restart from the first key. Use bounded deduplication or batch lookup when the workload deletes keys.
- *`producer_reserve_dropped` rises:* the producer is outpacing consumption or reservation is failing in a constrained context. Reduce event volume, improve draining, shard deliberately, or enlarge capacity after measurement.
- *Map counts rise while no event lines appear:* the state plane confirms activity while the event plane is losing or not being drained. Investigate transport health; do not rewrite history from the aggregate.

#pagebreak()
== Exercises <ch19-sec-exercises>

#exercise(title: "Prove the two planes fail independently")[Temporarily slow the consumer in a disposable branch while generating `openat` load. Record live-event count, `producer_reserve_dropped`, and final map totals. Explain why a larger map cannot repair missing event detail and why a larger ring cannot provide aggregate recovery after process restart.]

#exercise(title: "Measure live-reduction skew and staged stability")[Add a test-only invariant `observed_bytes == events` because this sample increments both by one. Repeatedly reduce the live per-CPU map under load, then compare it with a kernel-iterator walk over the staged export map. Explain why staging stabilizes an iterator session but cannot retroactively make the earlier live reduction atomic.]

#exercise(title: "Replace next-key with batch lookup")[Implement a second userspace snapshot strategy with the batch lookup command. Benchmark syscall count and elapsed time for 4,096 keys. State clearly whether the change affects point-in-time semantics, concurrent updates, and deletion behavior.]

#exercise(title: "Design sharded rings without losing per-workload order")[Place several ring buffers in a map-of-maps and choose a shard from a stable workload key. Describe which events retain order, how shard imbalance is measured, how userspace polls multiple descriptors, and how configuration changes preserve ownership.]

#exercise(title: "Audit the raw UAPI wrapper")[Compare `BpfAttrLinkCreate`, `BpfIterLinkInfoMap`, and `BpfAttrIterCreate` against the pinned target’s `include/uapi/linux/bpf.h`. Add compile-time size and alignment assertions and a unit test around syscall error conversion. Explain why this audit remains necessary even though command numbers are stable.]

== Chapter summary <ch19-sec-summary>

A production-shaped telemetry path separates event detail from aggregate state. The ring buffer is a bounded shared MPSC transport whose successful reservations have strict ownership and whose failures never block. The live state plane is a per-CPU hash map whose current-CPU updates avoid shared read-modify-write races without an unsupported tracepoint spin lock. Independent counters expose ring reservation loss, map insertion failure, and userspace parse rejection.

“Iterator” names three different mechanisms. The default sample uses a custom Rust adaptor over next-key, per-CPU lookup, and explicit reduction; it produces useful best-effort values but not an atomic map snapshot. The optional BPF iterator program runs in the kernel as `BPF_PROG_TYPE_TRACING`, receives a BTF-described `bpf_map_elem` context, writes binary records through `seq_file`, and is driven by reading an iterator descriptor. It reads an immutable `TELEMETRY_EXPORT` generation staged by user space after the observation interval.

The important achievement is not merely printing records. It is a contract that explains ordering, loss, concurrency, target BTF, verifier obligations, descriptor ownership, and fallback behavior—and a reproducible NixOS sample that makes each claim inspectable.
