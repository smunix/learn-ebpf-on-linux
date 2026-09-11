#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, exercise, expected-output
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref
#import "../../components/terms.typ": acronym

#chapter-opener(part: [IV · Containers and Control], chapter: [13])
= Stateful Program Design <ch-13>

A useful #acronym("ebpf") program is rarely stateless for long. A counter must survive more than one hook invocation; a policy must be shared between a kernel fast path and a user-space control plane; and an upgrade must not reinterpret yesterday’s bytes as today’s policy. Maps make this possible, but a map is not merely a convenient dictionary. It is a kernel object with a data-layout contract, contention behavior, capacity rule, lifetime, and owner. This chapter develops a way to choose and operate that object deliberately.

The primary sample, `04-map-patterns`, is an *audit-only map demonstration*. When it can run, it attaches a tracepoint program to `syscalls/sys_enter_openat`, records activity in bounded map types, emits versioned generic events, and prints aggregated thread-group counters after the observation interval. It uses a race-free `PerCpuArray` aggregate, reports insertion failures through `MAP_ERRORS`, does not deny a system call, and does not pin a map. The sample is still a warning against overclaiming: an LRU entry can be evicted, ring records can be dropped, and a successful load does not turn a sampled snapshot into a complete audit store.

== Prerequisites <ch13-sec-prerequisites>

Readers should be able to build the repository’s Rust workspace as an ordinary user, distinguish an eBPF program load from its attachment, and recognize a tracepoint as a target-local kernel interface. Earlier map material should have introduced the basic key/value model and the verifier’s requirement to check lookup results. You also need a disposable Linux virtual machine (VM) or other explicitly approved non-production target. This chapter does not require a BPF filesystem (bpffs), BPF Type Format (BTF), Compile Once – Run Everywhere (CO-RE), a Linux Security Module (LSM), or an enforcement experiment.

The runtime portion is *environment-gated*. It requires the repository’s eBPF build toolchain, a readable `syscalls/sys_enter_openat` tracepoint, ring-buffer support for the sample’s `EVENTS` map, and authority sufficient for this particular load and tracepoint attachment. The current runner implements a conservative effective-user-ID-zero gate, so its behavior is not evidence that every target kernel requires user ID zero (UID 0). Kernel release, configuration, namespace, capability, perf-event, lockdown, and LSM policy can all affect the real result. Linux capabilities partition privileged operations, but the required authority is operation- and target-dependent rather than a universal recipe @capabilities.

== Learning objectives <sec-learning-objectives>

By the end of this chapter, you should be able to:

- specify the consistency, loss, capacity, and lifetime contract of a BPF map before selecting its type;
- distinguish a shared array or hash value from a per-central-processing-unit (per-CPU) value and explain why their counter semantics differ;
- explain least-recently-used (LRU) eviction as a bounded-state trade-off rather than an insertion guarantee;
- identify when an aligned atomic update is sufficient, and when a short `bpf_spin_lock` critical section is justified;
- assign ownership to file descriptors (FDs), links, map wrappers, and pins without confusing a path with schema compatibility;
- treat a tail call as a non-returning jump with a measured fallthrough path; and
- stage a schema migration and rollback so code and state generation remain compatible.

== Start with a state contract, not a map type <sec-state-contract>

A #acronym("map") is kernel-resident storage shared, subject to access rules, by eBPF programs and user-space processes. Map operations are defined through the BPF interface, but the kernel cannot infer whether two fields must change together, whether an absent key means “never seen” or “evicted,” or whether an older value layout remains meaningful after deployment @bpf-map. Therefore write a short contract before writing the declaration. A practical contract answers five questions.

First, identify the key and value. Use fixed-width integer fields and an explicit representation at the application binary interface (ABI) boundary. For a Rust value that crosses this boundary, `#[repr(C)]` and a plain-old-data marker are only starting points: they do not create a network serialization format or silently solve padding, endian, version, or semantic-meaning changes. Second, name the readers and writers. Is a value written only by the eBPF fast path, only by one controller, or by both? Third, state what concurrent readers may see: a local component, one atomic scalar update, a lock-protected multi-field state, or either a complete old generation or a complete new generation.

Fourth, state the failure rule. A failed hash insertion, an LRU eviction, a full ring buffer, and an absent lookup are distinct observations. Do not merge them into a single zero value. Finally, state lifetime and ownership. Does ordinary process exit destroy the object? Is a service-owned pin intentional? Who removes it? These answers make an implementation reviewable before benchmarking enters the discussion.

#concept(title: [The unit of correctness is the value contract])[
A map update is only atomic at the scope the map operation specifies. It does not make a sequence of updates across fields, keys, or maps transactional. For a counter, a sampled total may be sufficient. For a policy with related entries, publish a fully prepared generation through one small selector instead of asking readers to infer a transaction that does not exist.
]

#figure(
  image("../../assets/diagrams/generated/13-map-concurrency.svg", width: 100%),
  caption: [Map concurrency is a design choice: local per-CPU updates avoid one shared increment, whereas shared hash/LRU values require a defined mutation rule and user-space updates require lifecycle discipline.],
) <fig-map-concurrency>

#figure-ref(<fig-map-concurrency>, title: [map concurrency and lifecycle]) is a compact decision tree. CPU 0 and CPU 1 can each use a local per-CPU slot, avoiding a shared counter update in the hot path. Both can also look up the same hash or LRU key; at that branch, a plain read–modify–write sequence is contended shared state. The diagram’s final path matters just as much: a user-space controller may update or pin state, and reuse must be an explicit choice between compatible reopening and migration.

== Selecting arrays, hashes, and per-CPU state <sec-map-selection>

An array map has a fixed key range and preallocated slots. It is appropriate when the domain is naturally bounded: a configuration slot at index zero, a known histogram bucket, or a small mode table. A hash map accepts an application-chosen key set up to its configured capacity. It suits policies keyed by a cgroup identifier, a file identity, or a process identifier (PID), but any failed insertion must have an explicit meaning. A regular hash map retains a successful entry until a program or controller changes or removes it; that does not make it unbounded or free from capacity failure.

An LRU hash is a capacity-bounded hash with eviction behavior. It is useful for best-effort correlation such as “most recently observed timestamp for this PID,” where losing old state is preferable to rejecting new activity. It is not suitable when absence must distinguish “no matching event occurred” from “the matching state was evicted.” An LRU lookup miss must be recorded or handled as a valid degraded case. The broad map interface and availability should always be checked on the target rather than inferred solely from a map name in a header or tutorial @bpf-map.

Per-CPU arrays and per-CPU hash maps hold a separate value component for each CPU. For a monotonic counter, this converts a hot shared increment into a local update. User space reads a vector of components and sums it. The resulting total is a *snapshot aggregate*, not an instant at which all CPUs paused together: one CPU may increment immediately before its component is read while another increments immediately after. For many monitoring questions that is the right accuracy/cost trade-off, especially when a global total is needed only after a short bounded interval.

The selection matrix in #table-ref(<tab-map-contracts>, title: [state contracts and map choices]) describes the observable consequence, not merely the allocation shape.

#figure(
  table(
    columns: (1.15fr, 1.28fr, 1.52fr, 1.32fr),
    inset: 5pt,
    stroke: 0.45pt + rgb("#B8CDD2"),
    table.header(
      [*State need*], [*Preferred map pattern*], [*Reader may observe*], [*Must be made visible*],
    ),
    [Hot counter], [Per-CPU array or hash], [A local component and a non-atomic aggregate snapshot], [CPU components, missing-key rule],
    [Bounded keyed correlation], [LRU hash], [A present timestamp or an absent value after eviction/miss], [Eviction/miss and insertion failure],
    [Fixed configuration], [Array, usually a small fixed index], [One element update, not a multi-map transaction], [ABI version and writer ownership],
    [Shared scalar], [Eligible array/hash field plus atomic operation], [One indivisible scalar update], [Alignment and supported atomic semantics],
    [Related fields], [Eligible map value plus very short spin lock, or generation selector], [Lock-protected fields or complete old/new generation], [Lock eligibility, fallback, generation hits],
  ),
  caption: [Map choice follows the state contract. “Preferred” means a starting pattern, not a substitute for a target feature probe.],
) <tab-map-contracts>

A per-CPU map is not a magic general synchronization primitive. It helps when each invocation can update its own component independently. A policy map keyed by a cgroup identifier is shared because the same workload can execute on different CPUs and a user-space writer must change the intended common policy. Similarly, a shared `Array<u64>` incremented by separate CPUs is a race unless the selected operation supplies synchronization. Do not label a map “per-CPU” merely because its key appears to be a CPU number; its declared map type defines its storage model.

== Read the primary sample as an inventory, then audit it <sec-sample-inventory>

The canonical source in #listing-ref(<lst-map-patterns-kernel>, title: [map declarations and the `map_patterns` hook]) declares a ring buffer, per-CPU counters, a per-CPU hash, an LRU hash, and policy maps used only by later samples. One object carries several chapters’ experiments, so declarations not touched by `map_patterns` should not be reported as behavior of this sample. In the selected function, the upper half of `bpf_get_current_pid_tgid()` is treated correctly as a thread-group identifier (TGID); `COUNTERS` and `BUCKETS` are incremented, a timestamp is inserted into `RECENT`, and a generic syscall event is submitted.

#let map-patterns-kernel-source = read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(34, 143).join("\n")
#code-listing(
  [Canonical source: map declarations and `map_patterns`],
  map-patterns-kernel-source,
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs",
) <lst-map-patterns-kernel>

There are useful correct habits in this listing. The increment helpers branch on optional pointers, use per-CPU values, and count failed hash insertions in `MAP_ERRORS`. The LRU insertion failure has its own metric. `emit` checks ring-buffer reservation and increments `DROPPED` on failure; success submits exactly once and never retries or waits in eBPF.

`COUNTERS` and `BUCKETS` are both per-CPU, so their fast-path increments avoid a shared read–modify–write race and require user-space summation. `RECENT` is intentionally different: it is a shared bounded LRU map. An insertion failure is counted, but capacity-driven eviction remains part of the map's approximation contract and is not an audit-complete history.

The runner selects a `TracePoint`, loads it, and attaches it to `syscalls/sys_enter_openat` for the sample selector, as shown in #listing-ref(<lst-map-patterns-runner>, title: [the runner’s exact attachment branch]). The program ignores the tracepoint context, so this primary exercise does not decode target-specific fields. That keeps the data-path lesson focused on state, but the event itself still must exist and be accessible on the target. Static tracepoints are discoverable interfaces, not a blanket stable ABI promise; check the local event metadata before relying on an attachment @bpf-design-q-and-a.

#let map-patterns-runner-source = read("../../../samples/runner/src/main.rs").split("\n").slice(555, 569).join("\n")
#code-listing(
  [Canonical source: runner selection and tracepoint attachment],
  map-patterns-runner-source,
  language: "rust",
  source-path: "samples/runner/src/main.rs",
) <lst-map-patterns-runner>

After the timed ring drain, the runner sums `COUNTERS`, prints `tgid=<tgid> count=<sum>`, prints `bucket0`, reports map insertion failures, and prints transport-health counters. It does not claim to count LRU evictions or produce an exact number of ring events. Consequently, a clean-looking run demonstrates the declared counters, not an audit-complete history.

== Atomics and spin locks: use the smallest sufficient boundary <sec-atomics-spinlocks>

An atomic operation makes one appropriately aligned scalar operation indivisible according to its specified semantics. It can be a sound choice for a single counter, bit, or generation selector when the target verifier, program type, architecture, and compiler output support the operation. It does *not* create a coherent snapshot of neighboring fields. For example, atomically incrementing `allow_count` does not ensure that a reader sees `allow_count`, `last_refill_ns`, and `tokens` from the same logical update. Treat ordering and atomic support as target-tested properties; the verifier checks program safety, not whether the selected memory model expresses the policy you intended @bpf-verifier.

A BPF spin lock protects fields within one eligible map value during a short critical section. It is deliberately constrained. In the documented model, it is used with BTF-described hash or array map values; the lock is a suitably aligned top-level field; only one lock can be held; every path unlocks; and helpers or BPF-to-BPF calls are forbidden while the lock is held. User space needs the locked map-operation flag when it reads or writes a spin-locked value. These restrictions make a spin lock a precise tool for a tiny compound state transition, not a general way to serialize a slow control plane.

#verifier-note(title: [A lock is a path-wide proof obligation])[
The verifier must be able to prove an unlock on every reachable return path. A lookup still may return null before any lock exists; branch on that result. Once locked, do only the few field reads and writes required by the invariant, release the lock, and only then emit an event, call another helper, or tail-call. An early return hidden in one error branch is a correctness failure, not a performance detail @bpf-verifier.
]

For the common counter case, start with a per-CPU value. If a single global scalar is actually required, use a supported atomic and document exactly which field is atomic. For a multi-field rate limiter or policy state, prefer publishing an immutable, complete value in an inactive generation when writes are infrequent. Use a spin lock only when old-or-new generation publication cannot express the invariant and the protected work is extremely short. On the user-space side, a Rust `Mutex` or one dedicated writer can serialize an application-level sequence of map operations, but it cannot make kernel readers observe several element updates atomically.

== Ownership, pins, and restart boundaries <sec-ownership-pinning>

Stateful design has two ownership graphs. In user space, the `Ebpf` object, typed map wrappers, link handles, and FDs determine what this process keeps open. Resource Acquisition Is Initialization (RAII) means a Rust value’s destruction can close an owned handle, but moving a map out of the owner or retaining another handle changes the graph. In the kernel, an attachment, an open FD, or a bpffs pin can retain an object. Object lifetime ends only after the final retaining reference is gone; dropping one wrapper is not a proof that all state vanished.

A pin is therefore neither a backup nor a compatibility promise. It is a bpffs directory entry that retains a BPF object beyond the creating process. Pinning is appropriate only when a service has a documented need to survive loader restart or to hand a validated object to a controlled peer. Give every pin a service-owned directory, restrictive permissions, a named owner, map purpose, expected map metadata, schema version, creation time, expiry or removal action, and startup-reconciliation procedure. Never point a new binary at a familiar pin path and infer compatibility from its name. Compare map type, key size, value size, flags, maximum-entry policy, BTF layout where relevant, and semantic version first.

`04-map-patterns` deliberately does not pin. Its runner owns the loaded object and attachment for the bounded observation; the source keeps the `Ebpf` owner alive through map reading; then ordinary return and drop release the objects it owns. The sample README describes timeout/drop detachment. This is an excellent beginner lifecycle because it is reversible, but it is not a restart-resilient service pattern. Do not add a pin merely to make a short lab survive a crash; that converts cleanup into an operational migration problem.

#security-note(title: [Separate audit from policy authority])[
Keep the privileged loader or map writer narrow, and keep a telemetry consumer unable to load arbitrary programs or edit policy maps. The primary sample contains no denial path. If a later exercise uses enforcement, begin with audit, require explicit opt-in, restrict it to a disposable cgroup or recovery-capable VM, and make rollback independently operable. Telemetry loss must never silently decide whether an operation is allowed or denied.
]

== Tail calls require fallthrough semantics <sec-tail-calls>

A tail call dispatches through a program-array slot to another eBPF program. It is a one-way jump, not an ordinary function call: the callee receives the context, but it cannot use the caller’s stack or register values. If no target is installed, the target is incompatible, or the tail-call nesting budget is exhausted, execution resumes immediately after the tail-call helper. The exact documented presentation of the limit has varied between 32 and 33, so neither number should be embedded as a policy invariant. Reserve ample stack margin, keep pipelines small, and test the target rather than treating the limit as a portable capacity.

The required pattern is simple but non-negotiable: populate and load a candidate target, validate its generation and return contract, install it in a known program-array index, issue the tail call, and make the very next instructions a safe fallback. Count fallback hits by reason where possible. A fallback might record an audit outcome and return the program type’s safe default; it must not accidentally apply a stale policy or use a pointer assumed to have survived a failed dispatch. The program-array update changes one dispatch slot, not the compatibility of the caller and callee. They still need the same context interpretation, map schema, return semantics, and ownership plan.

== Schema migration and rollback are one release protocol <sec-migration-rollback>

A value layout changes whenever its size, field interpretation, endian rule, padding contract, allowed mode values, or associated map meaning changes. Adding a field to the end of a `PolicyV1` structure may look harmless, but an existing pinned map has its old value size. Reusing it with `PolicyV2` code is not a migration; it is an ABI mismatch. The safer rule is to create a new map name and pin path for every incompatible schema and retain the old map only for a declared migration or rollback window.

A controlled rollout can follow seven steps. *Discover* the booted kernel, active attachments, required map metadata, service identity, and current pins. *Stage* the new object without attaching it, collect verifier diagnostics in testing, and establish its initial inactive state. *Validate* the V2 map type, sizes, flags, limits, and semantic manifest; populate it completely; and run any available object tests. *Activate one boundary at a time*: use a supported managed link update with an expected-old-program guard when available, or state the overlap/gap behavior of a legacy detach/attach procedure. *Dispatch only when ready* by filling the future tail-call slot before selecting it. *Observe* per-generation hits, fallback hits, lookup failures, insertion failures, eviction, and event loss. *Retire* only after the explicit rollback window ends and all old references are detached, closed, and unlinked.

Rollback reverses both code and interpretation. If V2 writes values that V1 cannot understand, a rollback must reselect V1 code *and* V1 state, not merely reattach the old program to the V2 map. If link update is unavailable, make duplicate observations or a short observation gap visible in metrics; “atomic upgrade” is not an honest claim without an attachment-specific proof. BTF and CO-RE can adapt certain type accesses when usable target metadata exists, but neither creates a missing helper, map type, hook, or semantic contract @libbpf-core.

For container-aware policies, treat a control group (cgroup) identifier as an event-time kernel join key, not an immortal container name. A process can move cgroups and cgroup paths can be virtualized or renamed. Record host and boot context plus time-bounded control-plane lifecycle metadata outside the eBPF fast path; cgroup v2 hierarchy and delegation have their own operational constraints @cgroups-v2. That design separates quick map lookup from human-readable workload attribution and allows migration telemetry to say which generation made a decision.

== Safe, reproducible procedure <ch13-sec-safe-procedure>

Perform the following only in a disposable VM or approved non-production target. The procedure builds without privilege and invokes only the already built runner under the runner’s current effective-UID gate; it does *not* run Cargo as root, alter sysctls, lower perf restrictions, grant broad `CAP_SYS_ADMIN`, create pins, or enable enforcement. Treat every attachment outcome as environment-gated evidence for this one machine.

#code-listing(
  [Build, preflight, and bounded audit-only observation],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\n\n# Build the locked workspace as an ordinary user.\ncargo xtask build-ebpf\ncargo build -p sample-runner\n\n# Read-only preflight and target-local tracepoint contract.\n./target/debug/sample-runner lab-check\ntest -r /sys/kernel/tracing/events/syscalls/sys_enter_openat/id || test -r /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id\ntest -r /sys/kernel/tracing/events/syscalls/sys_enter_openat/format || test -r /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format\n\n# In the disposable VM only: run the reviewed binary, not Cargo, for 10 seconds.\nsudo -- ./target/debug/sample-runner run 04-map-patterns --duration 10",
  language: "bash",
  source-path: "expected command",
)

Keep the command transcript with `uname -r`, `uname -m`, the repository revision, `Cargo.lock`, the resulting eBPF object hash, and the tracepoint `id` and `format`. A failure to build, a missing tracepoint, denied privilege, verifier rejection, unsupported ring buffer, resource limit, or attachment error is a useful result. Stop and record it; do not widen authority or change a global system setting to force the lab through. The sample limits its actual observation end to 60 seconds even if a larger `--duration` is supplied, so use an explicit small value when reproducing an observation.

=== Expected output and interpretation <ch13-sec-expected-output>

#expected-output(title: [Output shapes, not promised values])[
On a target where load and attachment succeed, the runner prints an attachment line, zero or more validated ring events, zero or more `tgid=<tgid> count=<sum>` lines, `bucket0=<sum>`, map insertion-failure counters, and transport health. Exact values and ordering depend on activity; no particular count is promised.
]

Ring events pass schema, kind, length, flags, and reserved-field checks before formatting. The TGID and bucket lines are sums of per-CPU components. Neither those aggregates nor the reported insertion/drop counters prove that `RECENT` retained every key or that every event reached an external system.

For the README’s negative control, the relevant contract is narrow: a TGID that executes no `openat` while attached should not acquire a `COUNTERS` key from this hook. Startup, dynamic loading, logging, and shell activity can open files, so use a controlled workload. Finite-map insertion failure is reported separately; LRU eviction still has its own approximation semantics.

=== Verifier reasoning <ch13-sec-verifier-reasoning>

The selected hook does not parse tracepoint fields. `get_ptr_mut` for each per-CPU map is optional; each dereference occurs only in the successful branch. Hash and LRU insertions copy fully specified scalar keys and values, and failures update bounded metric slots. Ring reservation returns an optional writable record; success writes then submits once, while failure increments `DROPPED`. The verifier proves reachable memory and helper paths, not the measurement's completeness @bpf-verifier.

That verifier proof does not prove “every open was counted.” A new key can fail to insert, a ring reservation can fail, an LRU entry can be evicted, and user-space aggregation is not transactional. Preserve verifier logs during development, but do not parse their wording as a durable machine interface.

== Portability and operational caveats <sec-portability-caveats>

The sample requires an `openat` syscall tracepoint path that is present and readable on the target. The runner’s branch uses `syscalls/sys_enter_openat` exactly; it does not select an alternative event if it is missing. The `lab-check` command is read-only and reports coarse feature indicators, but it does not prove the tracepoint exists, establish delegated cgroup scope, or prove the production service identity has attachment authority. Its own root check is an implementation limitation: it rejects a nonzero effective user ID before demonstrating a more narrowly capable deployment.

The ring buffer is declared even though the chapter’s main state lesson is maps. Treat that as an additional feature gate and loss source. A full ring does not block the hook; this code increments `DROPPED`, but the runner does not print it. The map sample’s source is therefore suitable for a static review and an environment-gated lab, not for a claim of tested loss accounting. The current repository audit also records that companion runtime loading/attachment is not established by the reviewed continuous-integration harness; a local successful build is not a substitute for a support matrix.

Map availability, atomic instruction support, spin-lock eligibility, map memory accounting, and CPU topology vary with the booted kernel and configuration. Aya APIs also need the repository’s pinned dependency graph: this workspace declares `aya = 0.14.0`, but code should be compiled against the actual lockfile, not against a floating “latest” documentation page. Aya is a Rust eBPF ecosystem, not a kernel compatibility guarantee @aya-book. Feature probe, load, attach, and cleanup under the intended service identity on every claimed support tier.

== Cleanup <ch13-sec-cleanup>

For the primary sample, wait for the bounded command to finish. The runner drains until its deadline, reads `COUNTERS`, returns from `run`, and drops the in-memory `Ebpf` owner; the documented sample behavior is drop-based detachment and no map pin. If you interrupt the process, first verify from an authorized administrative view that the tracepoint attachment is gone and that no test-owned bpffs entry was introduced. This chapter’s procedure creates no pin, so do not use a broad recursive delete under `/sys/fs/bpf` as “cleanup.”

A production service needs a stronger reconciliation procedure: enumerate only its service-owned directory, compare every surviving map/link to a signed or otherwise controlled manifest, leave unfamiliar objects untouched for investigation, detach/unlink according to the rollback policy, and record the action. Cleanup is part of the state contract, not an afterthought after a successful attachment.

== Exercises <ch13-sec-exercises>

#exercise(title: [Make the counter contract honest])[
Without changing the primary sample’s behavior, write a review note that identifies every way an observed TGID total can be incomplete. Compare the implemented `PerCpuArray<u64>` bucket plus user-space summation with one eligible shared scalar updated atomically. State what each reader can observe and how you would expose overflow, insertion failure, and snapshot semantics.
]

#exercise(title: [Design a bounded correlation map])[
Design an LRU map keyed by PID for a wakeup-to-observed-run measurement. Specify its maximum entries, what an eviction means, what happens on insertion failure, how PID reuse is addressed, and which counters distinguish “no wakeup,” “evicted correlation,” and “unmatched switch.” Do not assume tracepoint field offsets; require a target-local format fixture before decoding any context.
]

#exercise(title: [Write an upgrade manifest])[
Define a `PolicyV1` and incompatible `PolicyV2` map manifest using fixed-width fields. Include map type, key/value sizes, maximum entries, version, owner, pin path, allowed writer, activation generation, rollback deadline, and deletion condition. Describe how a new program, an inactive V2 map, one dispatch selector, and per-generation metrics yield an observable rollback.
]

== Chapter summary <ch13-sec-summary>

Stateful eBPF design starts with what observers may see and what failure means. Per-CPU maps trade an instant global value for inexpensive local updates and sampled aggregation. Arrays fit bounded indexes; hashes fit keyed state; and LRU maps intentionally trade retention for bounded memory. A plain shared increment is not made correct by its short syntax. Choose an atomic scalar, a very small eligible spin-lock region, or—often better—an immutable generation publication according to the invariant.

The primary `04-map-patterns` sample demonstrates the declarations and nullable lookup discipline with per-CPU `COUNTERS` and `BUCKETS` maps, plus explicit `MAP_ERRORS` reporting. Its runtime behavior remains environment-gated and audit-only. LRU eviction is still semantically lossy, and per-event ring output remains best effort even when the aggregate counters are race-free.

Pins, FDs, attachments, links, and Rust owners form an explicit lifecycle graph. A pin preserves a reference; it does not validate an ABI or provide an upgrade plan. Tail calls are one-way dispatches whose failures fall through locally. Finally, every incompatible state change deserves a new schema, staged validation, guarded activation, measurable old/new generations, and a rollback that restores both code and state interpretation.

== Next steps <ch13-sec-next-steps>

Continue with #chapter-ref(<ch-14>, title: [Reading the Verifier]). There, these state contracts become explicit proof obligations: the reader will use register states, pointer provenance, initialized stack regions, bounded control flow, and verifier evidence to decide which design the target kernel can accept.
