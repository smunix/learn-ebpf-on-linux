#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, exercise, kernel-detail, portability-note, verifier-note
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "II", chapter: "06")
= Moving Events to User Space <ch-06>

An extended Berkeley Packet Filter (eBPF) program is close to the event that it observes, but a useful diagnosis, metric, or audit record usually has to reach user space. That crossing is not a print statement. It is a bounded producer–consumer protocol between code running in a kernel hook and a user-space loader or consumer. Its correctness includes the record contract, overload policy, ownership rules, map semantics, and a deliberate shutdown path.

This chapter develops that protocol using the repository's conditional `03-exec-ringbuf` and `04-map-patterns` samples. They are valuable source-level demonstrations, not evidence of a successful attachment on every Linux host. The repository's non-privileged checks do not load or attach an eBPF object. Treat all runtime-facing observations here as *environment-gated* until a compatible disposable virtual machine (VM) has built the locked object and recorded a load, attach, trigger, and detach result.

== Prerequisites <sec-06-prerequisites>

You should be able to distinguish a program type, hook, and attachment from the previous chapters; understand that a BPF map is a kernel-resident object shared with user space; and read simple Rust ownership and error-handling code. This chapter assumes no tracepoint-field decoding: the primary execution sample observes the existence of `sched/sched_process_exec` without reading its context. Have a disposable Linux VM, the repository's pinned Nix development environment, and authority approved for the exact BPF and tracepoint operation. Do not develop this workflow on a production host.

== Learning objectives <sec-06-objectives>

By the end of the chapter, you should be able to choose between a ring buffer and a perf event array for a stated transport contract; explain why a reservation must finish exactly once; write down separate counters for producer, transport, parser, and application loss; and recognize why a Rust structure that happens to work locally is not automatically a durable protocol. You should also be able to identify the map semantics in `04-map-patterns`, including per-central-processing-unit (per-CPU) aggregation, Least Recently Used (LRU) eviction, and an unsafe shared counter pattern. Finally, you should be able to run the samples only as audit-only, time-bounded observations and explain what a successful or empty result does—and does not—establish.

== The mental model: a bounded hand-off <sec-06-mental-model>

Think of an event transport as five adjacent responsibilities. A hook creates a small fact; the eBPF producer either puts that fact into a bounded kernel transport or records why it could not; the kernel transport signals readiness; one owner in user space drains and validates bytes; then application code may enrich, store, or aggregate the validated record. The words *bounded* and *owner* matter. A hot kernel invocation must not wait for a slow database, a network request, allocation, or a user-space thread. Conversely, a user-space consumer must not retain a borrowed view of a ring record while it performs slow work.

#concept([A ring buffer or perf buffer bounds memory and communicates records; it cannot make an unbounded event rate lossless. For observability, the normal overload contract is: drop the new record, increment an explicit counter, and return promptly. A design that requires complete durable evidence must reduce or aggregate the event rate, use an appropriately reliable downstream control path, or state a narrower guarantee.], title: "Transport is not durable audit")

The generated flow in #figure-ref(<fig-06-ring-buffer-flow>, title: "reservation, delivery, and loss reporting") depicts this hand-off. It deliberately separates the data path from the health path. An event that was never reserved cannot later be recovered by a faster consumer; a record rejected by the parser was delivered but not usable; a record accepted by the parser can still be refused by a bounded application queue. Calling all three conditions `dropped` hides the remediation.

#figure(
  image("../../assets/diagrams/generated/06-ring-buffer-flow.svg", width: 100%),
  caption: [A bounded kernel-to-user-space event path. The loss counter is a first-class output, not an afterthought. Ring-buffer producers never wait for consumer capacity. @bpf-ringbuf],
) <fig-06-ring-buffer-flow>

A record also has an order contract. A shared ring makes records visible in reservation order, which is useful when several CPUs produce related events. It is not a universal causal order, wall-clock order, or transaction history. An earlier producer that holds a reservation can delay later completed records. State what your chosen timestamp, sequence number, and order mean; do not silently promote transport order into a stronger claim. The kernel documents the ring buffer as a shared multi-producer, single-consumer (MPSC) map with byte capacity, variable-size records, memory-mapped consumption, and readiness notification. Its `max_entries` capacity is a power of two; its usual key and value sizes are zero because it is a stream rather than a key/value map. @bpf-ringbuf

== Ring buffer and perf buffer semantics <sec-06-transport-semantics>

A BPF ring buffer is one map shared by producers on all CPUs and one consumer. It was designed in part to avoid the aggregate memory cost of per-CPU perf buffers and to provide a common reservation sequence across CPUs. User space maps the ring and drains records; a mature library such as Aya manages the required producer/consumer memory ordering instead of asking application code to update the mapped positions directly. Aya documents its `RingBuf` facility as requiring Linux 5.8 or later, but that documented floor is not a substitute for a target feature probe, successful load, tracepoint existence, resources, and authorization. @aya-book @bpf-ringbuf

The alternative is `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, an array whose entries refer to perf events. In the common configuration, user space opens a buffer for each online CPU and the eBPF program emits to the current CPU's entry using `bpf_perf_event_output`. Each perf buffer has local ordering. A consumer that combines CPUs must establish its own timestamp or sequence policy. Aya documents the perf event array path from Linux 4.3, making it a compatibility option where ring buffers are unavailable, but its CPU-indexed files, mappings, and memory budget are different operational costs. @aya-book

#figure(
  table(
    columns: (1.12fr, 1.42fr, 1.46fr),
    inset: 5pt,
    stroke: 0.45pt + rgb("#B8CDD2"),
    align: left,
    table.header(
      [*Property*], [*Ring buffer*], [*Perf event array*],
    ),
    [Topology], [One shared MPSC byte stream.], [Normally one stream and perf-event resource per CPU/index.],
    [Producer path], [Copy output, or reserve then submit/discard.], [Emit a raw blob to a selected perf-event entry.],
    [Order offered], [Reservation order in the shared ring; not causal or time order.], [Order within each buffer; cross-CPU merge policy belongs to the application.],
    [Failure visibility], [Aya copy output returns a result; reservation returns an optional entry.], [Consumer receives `Lost` records; the high-level Aya eBPF output wrapper does not expose the immediate helper status.],
    [Consumer discipline], [Drain `next()` to empty and promptly release each borrowed item.], [Drain each readable buffer completely; separately sum samples and lost records.],
    [Good fit], [Current-kernel telemetry with one bounded shared capacity and explicit producer failure accounting.], [Compatibility or intentionally per-CPU pipelines with a tested resource budget.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Transport choices are semantic and operational choices, not interchangeable spellings. @bpf-ringbuf @aya-book],
) <tbl-06-transport>

The distinction in #table-ref(<tbl-06-transport>, title: "ring buffer versus perf event array") is especially important for loss accounting. A ring-buffer producer can observe an `Err` from copy output or `None` from reservation and increment an eBPF-side counter. In current Aya, the high-level eBPF `PerfEventArray::output` returns unit rather than the helper result; therefore an application cannot infer immediate output failure from that wrapper alone. The user-space `Lost` record is still meaningful, but it is later evidence of a perf-buffer overrun, not a proof that every earlier producer action succeeded. Recheck this API behavior against the locked Aya version whenever the dependency graph changes. @aya-book

== Reservations are verifier-tracked obligations <sec-06-reservations>

Ring buffers provide two producer patterns. Copy output copies a completed source record into the ring. It is often the simplest choice for a fixed record and can accept a length that is not statically known to the verifier, at the cost of a copy. Reservation instead obtains writable ring memory for a verifier-known size. The producer initializes it in place and either submits it so the consumer may observe it or discards it. Reservation avoids a temporary copy, but it creates a resource obligation on every control-flow path. @bpf-ringbuf @bpf-verifier

A failed reservation is non-blocking. It commonly means the ring lacks capacity; in a non-maskable interrupt (NMI) context it can also fail because the reservation lock cannot be acquired, even if capacity appears available. A retry loop in an eBPF hook changes overload into kernel-side work and is the wrong response. A slow operation after reservation is also harmful because commit order follows reservation order: an early unsubmitted record can hold up later ones. Construct the event first when possible; after a successful reserve, use a short straight-line fill-and-submit sequence. The default adaptive wakeup behavior is the safe starting point. `BPF_RB_NO_WAKEUP` and forced wakeups tune notification, not capacity, and require a tested polling strategy. @bpf-ringbuf

The canonical producer helper is shown in #listing-ref(<lst-06-ebpf-producer>, title: "the shared eBPF program source"). `emit` tries `EVENTS.reserve::<Event>(0)`. In the success arm it writes the entire supplied `Event` and submits it. In the failure arm it increments `DROPPED` if the per-CPU map pointer is available. `exec_ringbuf` merely calls this helper with an event of kind `EXEC`; it neither reads tracepoint fields nor implements a policy decision. Every listed tracepoint function returns zero, the neutral tracepoint return value.

#code-listing(
  [Canonical ring-buffer producer, map declarations, and selected tracepoints],
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(20, 102).join("\n"),
  language: "rust",
  source-path: "../../../samples/ebpf-programs/src/main.rs",
) <lst-06-ebpf-producer>

#verifier-note([The `Some(mut slot)` branch writes the event before `submit`, and the alternate branch has no reservation to release. There is no path that returns while holding `slot`. The verifier checks resource lifetimes as well as pointer and stack state, so a future edit that branches after a successful reservation must preserve the one-submit-or-one-discard rule. The `Event` is built through `base`, which starts from `Event::default`; this initializes the schema header, flags, and reserved bytes before submission.], title: "Why this reservation shape is acceptable")

This helper is not a proof of exact end-to-end delivery. `DROPPED` is a `PerCpuArray<u64>`, which avoids ordinary cross-CPU sharing for the selected slot, and the runner now sums and prints it as `producer_reserve_dropped`. The consumer separately reports `consumer_parse_rejected`, `userspace_queue_dropped`, and `intentional_sampling_skipped`; the last two are zero because this teaching runner has no intermediate queue and performs no sampling. Downstream storage failures remain outside this process and need their own metric in a real service.

== The record boundary is an application binary interface <sec-06-schema>

A record is an application binary interface (ABI): both sides must agree on field position, width, alignment, validity, byte order, and evolution. `#[repr(C)]` gives Rust fields C-layout ordering and alignment rules; it does not erase padding, provide a cross-architecture protocol, or make arbitrary bytes valid Rust values. Aya's `Pod` trait is an unsafe promise that a type may be converted to and from bytes for map APIs; it is not a serialization format. @aya-book

The shared `Event` type in `samples/common/src/lib.rs` has fixed-width fields, a `RecordHeader` containing schema version, record length, kind, and a reserved-zero field, plus explicit flags and reserved tail bytes. The eBPF helper initializes the whole record through `Default`. The runner reads integer fields byte-wise with native-endian conversions, rejects unsupported schema versions, kinds, lengths, flags, and nonzero reserved fields, and only then formats the record. This is a deliberate same-host teaching ABI—not a durable or cross-machine serialization format.

That header is the minimum, not the finish line. A later version can introduce a new kind or larger record without redefining old bytes, but it needs an explicit compatibility table. For a cross-machine or durable store, encode fields into bytes in a stated byte order—usually little-endian—instead of sending the native representation of a Rust structure. Never put pointers, references, `usize`, `bool`, Rust enums, or `Option<T>` into a raw event protocol. @bpf-map @aya-book

Schema validation is also a safe consumer-ownership boundary. A ring item is a borrowed view of memory-mapped data. Aya advances the consumer position when that item is dropped and permits only one outstanding item. Validate a bounded header, copy or synchronously process only what is needed, then release it. Do not pass the borrowed slice to an asynchronous task, a worker queue, or a logging system. If enrichment is slow, hand a copied, validated representation to a *bounded* user-space queue and export its rejection count separately.

== Loss accounting and backpressure <sec-06-loss-backpressure>

Backpressure is the set of consequences when producers arrive faster than the transport and consumer can retire records. In eBPF, the producer policy must be immediate and bounded: do not sleep, spin, allocate, or retry. In user space, readiness means that work may exist, not that exactly one event exists. Drain a ring with `next()` until it returns no item; drain every readable perf buffer fully. The current runner does this inner drain, then sleeps for 50 milliseconds, as #listing-ref(<lst-06-runner-drain>, title: "the canonical runner's drain loop") shows. It is a simple teaching loop, not a benchmarked latency or loss guarantee.

#code-listing(
  [Canonical attachment selection, ring drain, and per-process counter reporting],
  read("../../../samples/runner/src/main.rs").split("\n").slice(646, 704).join("\n"),
  language: "rust",
  source-path: "../../../samples/runner/src/main.rs",
) <lst-06-runner-drain>

The code attaches `03-exec-ringbuf` only to `sched/sched_process_exec` and `04-map-patterns` only to `syscalls/sys_enter_openat`. It drains every available ring item, counts parse rejection, caps the duration at 60 seconds, and reports map and transport health at the end. The map-patterns path prints per-thread-group `COUNTERS`, `bucket0`, and insertion failures. An empty event stream can still mean no matching activity or producer loss; use the health counters and attach diagnostics rather than treating silence as proof of absence.

A useful health model names each boundary separately:

- *Loader and hook status:* record kernel release, architecture, object identity, program and attach type, target event existence, privilege or policy error, and a verifier-log summary when load fails.
- *eBPF producer quality:* count helper/context-read failures, map-insertion or capacity failures where relevant, and ring output or reservation failures per CPU.
- *Perf transport loss:* sum every `Lost` record by CPU and interval when using a perf event array.
- *Consumer validity:* count malformed length, unsupported schema, unknown kind, invalid field, and conversion failure.
- *Application overload:* count intentional sampling, bounded work-queue rejection, downstream timeout, and storage refusal independently.
- *Lag and capacity:* export configured ring bytes or per-CPU perf sizes, poll delay, drain duration, handler duration, queue depth, and peak trigger rate.

Size capacity for bursts, not averages. A rough initial budget needs the maximum record size including alignment, peak event rate, maximum expected consumer pause, and safety headroom. Perf buffers add the number of covered CPUs and file-descriptor limits; rings add shared contention and the possibility that a reserved record delays the sequence. Map and buffer memory also encounters system resource accounting. Measure the actual deployment's CPU topology and workload, then intentionally delay the consumer and explain each counter rather than declaring a large buffer lossless. @bpf-ringbuf @bpf-map

== Map patterns: choose semantics before syntax <sec-06-map-patterns>

Maps are not interchangeable collections. Their type determines capacity, keying, allocation, sharing, eviction, and the consistency a reader may observe. `04-map-patterns` uses a per-CPU hash keyed by a 32-bit thread-group identifier (TGID), a race-free per-CPU aggregate array, an LRU timestamp map, a per-CPU insertion-failure map, and a ring buffer. `POLICY` and `CONFIG` are declared by the shared object but are not configured or consulted by the `map_patterns` entry point. @bpf-map

For an array, the key is a fixed `u32` index; values are preallocated and zero-initialized. A normal array value is shared, while a per-CPU array gives each CPU a separate value for an index. A user-space read of a per-CPU value yields multiple possible-CPU values to sum, not one instantaneously global scalar. For a hash, lookup may fail and an insertion can fail at capacity; both require a stated policy. An LRU hash deliberately evicts entries when full, so it is useful for approximate recent state but cannot be described as audit-complete history. @bpf-map

The repaired source makes the fast-path concurrency contract explicit. `COUNTERS` and `BUCKETS` are per-CPU maps, so each CPU updates its own value and user space performs the sum. Failed hash or LRU insertions increment `MAP_ERRORS`. LRU eviction remains an intentional, bounded approximation: an old key can disappear without being an insertion error, so the map is not an audit-complete history.

#kernel-detail([For a counter that need not be one instantaneous global value, a per-CPU map plus user-space summation avoids a shared multi-step update. When an exact shared scalar is truly necessary, choose and document a target-supported synchronization method or atomic operation, including reader semantics. For recent-state correlation, use an LRU map only when eviction is intentional, measurable approximation. A map lookup's pointer is nullable; no collection choice removes the need to check it. @bpf-map @bpf-verifier], title: "Prefer a simpler consistency contract")

The same rule applies to map ownership. The selected runner holds `Ebpf`, programs, maps, and the ring consumer in one process scope. It does not pin maps in the BPF filesystem (bpffs), and the sample documentation says timeout/drop detaches and closes the ring. That makes this a useful short-lived lab pattern. A service that pins maps or links must instead name the owner, bpffs path and access policy, schema generation, retention and removal action, startup reconciliation, upgrade procedure, and rollback. A map can outlive a process if another descriptor, an attachment, or a pin retains it; process exit is not a universal lifecycle design. @bpf-map

== Safe, reproducible procedure <sec-06-procedure>

Begin with non-privileged inspection in the pinned development environment. The following commands build as the ordinary development user. They do not attach the object. The eBPF build uses `nightly-2026-07-15` with `rust-src`; run it through the project environment rather than substituting an arbitrary system Cargo version.

#terminal-listing("cd /home/ubuntu/learn-eBPF-00\nnix develop\njust check\njust kernel-audit\ncd samples\ncargo xtask build-ebpf\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check\ntest -r /sys/kernel/tracing/events/sched/sched_process_exec/format\ntest -r /sys/kernel/tracing/events/syscalls/sys_enter_openat/format", title: "Build and preflight without kernel attachment") <lst-06-preflight>

Interpret the final two tests independently. The exec sample requires the scheduler process-exec tracepoint; map patterns requires the openat syscall tracepoint. A readable tracefs format establishes that the named event is exposed to this environment; it does not prove that the current loader identity can load and attach, nor that every target exposes the same event semantics. Tracepoints are discoverable but are not a blanket stable application binary interface. @bpf-design-q-and-a

Only after that inspection succeeds, move the built loader—not Cargo itself—into a disposable VM whose privilege and security policy have been reviewed for the operation. The current runner imposes an effective-user-ID-zero gate as a conservative implementation choice. It does not establish that root is the only kernel authorization model: BPF authority is operation- and policy-dependent. Do not respond to a failure by granting broad `CAP_SYS_ADMIN`, changing global unprivileged-BPF policy, disabling security controls, or making Cargo privileged. Diagnose the target-specific failure instead. @capabilities

In one VM terminal, run one observer for a short, fixed interval. In another terminal, create a harmless trigger. `sh -c 'true'` performs an exec for the first sample. Reading a byte from `/etc/hostname` is a harmless open-related trigger for the second. The exact event values depend on the VM's activity; do not expect a fixed transcript.

#terminal-listing("cd /home/ubuntu/learn-eBPF-00/samples\nsudo ./target/debug/sample-runner run 03-exec-ringbuf --duration 10\n# In a second terminal while it runs:\nsh -c 'true'\n\n# Run this separately, not concurrently with the prior observation:\nsudo ./target/debug/sample-runner run 04-map-patterns --duration 10\n# In a second terminal while it runs:\nhead -c 1 /etc/hostname >/dev/null", title: "Time-bounded audit-only observations in a disposable VM") <lst-06-observe>

#expected-output([On a compatible, authorized target with a matching trigger, the exec sample formats a validated line beginning `event kind=3`; the map-patterns path emits `kind=2`, later prints `tgid=` totals and `bucket0=`, and both ring paths finish with producer/consumer/queue/sampling health counters. Values and ordering are target-dependent. No event output is a diagnostic condition to investigate, not proof of zero executions or opens.], title: "What success looks like—and what it does not")

Both selected branches are audit-only in actual code: their eBPF functions return zero and neither branch configures `POLICY` or `CONFIG`. The general command-line parser accepts `--enforce`, but the `03-exec-ringbuf` and `04-map-patterns` cases do not consult it, so the flag does not create a denial path for these samples. Keep enforcement opt-in only for a later, separately reviewed program, and test any denial-capable experiment solely in a disposable cgroup or VM with explicit recovery and rollback.

== Cleanup, portability, and exercises <sec-06-cleanup-exercises>

Allow the bounded duration to expire so the runner reaches its normal drop path; do not rely on an interrupted session as your cleanup test. The sample documentation states that timeout/drop detaches and closes the ring buffer, and it deliberately creates no pins. If an experiment is interrupted or fails after attachment, inspect the lab VM with an authorized `bpftool link show` and `bpftool prog show` before beginning another run. Record the object hash, kernel release, architecture, selected tracepoint, loader identity, and result. Never reuse an unexplained attachment as background state for the next experiment.

#portability-note([Linux 5.8 is Aya's documented ring-buffer floor and Linux 4.3 its documented perf-array floor, but neither string proves map availability, tracepoint exposure, helper availability for the chosen program type, resource limits, lockdown or Linux Security Module policy, or authority. Probe the booted kernel and execute the smallest scoped trial under the intended service identity. The versioned native-endian record remains a same-host ABI, not a durable interchange format. @aya-book @bpf-ringbuf], title: "Feature probes outrank release strings")

#exercise([For a hypothetical 256-byte event stream at a measured burst rate, list the producer reserve failures, consumer schema rejections, intentional sampling, bounded application-queue rejections, and downstream storage failures you would export. For each, identify the observation point, counter cardinality, interval, and corrective action. Explain why a single `dropped` counter is insufficient.], title: "1. Write a loss contract")

#exercise([Trace the `map_patterns` path in #listing-ref(<lst-06-ebpf-producer>, title: "the canonical producer source"). Verify the per-CPU update and user-space summation contract, identify where insertion failures reach `MAP_ERRORS`, and explain why LRU eviction remains an expected approximation rather than a counted insertion failure.], title: "2. Audit the map story")

#exercise([Specify a bounded event header containing version, kind, length, flags, and reserved bits. Define which version-one records version-two consumers accept; define the byte order; and give the exact rejection metric for malformed or unknown input. Then decide when to copy a validated record out of the poll loop and where your bounded user-space queue reports overload.], title: "3. Design version two")

== Chapter summary <sec-06-summary>

Moving facts out of eBPF is a protocol design problem. A ring buffer offers one shared, bounded MPSC stream with copy or reserve/submit production; a perf event array offers CPU-indexed streams and visible `Lost` records. Neither waits for a slow consumer, and neither supplies an end-to-end lossless guarantee. The verifier turns a successful reservation into a submit-or-discard obligation, while the consumer owns prompt release of a borrowed mapped record.

A useful event system therefore defines a versioned schema, validates bytes before interpretation, and reports losses at each distinct boundary. It chooses maps for their concurrency and retention semantics, not for their shortest API call: per-CPU values reduce shared mutation but require aggregation; LRU maps trade completeness for bounded recent state. The repository's repaired samples report producer reservation failure, parse rejection, queue/sampling status, and map insertion failure while remaining narrow, same-host, audit-only demonstrations.

== Next steps <sec-06-next-steps>

The next chapter applies this transport discipline to system-call, task, and Virtual File System observation: first discover the target interface and preserve its contract, then extract only bounded, validated fields. Continue with #chapter-ref(<ch-07>, title: "System Calls, Tasks, and the Virtual File System").
