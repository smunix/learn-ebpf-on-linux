# eBPF and Aya Programming Model: A Defensive Engineering Dossier

**Research cutoff:** 10 September 2026. **Scope:** eBPF execution and calling conventions, program and map models, helper contracts, Rust/Aya architecture, event transport, backpressure, loss accounting, and portability. This dossier deliberately addresses **observable, least-privilege, defensive instrumentation**. It does not cover stealth, evasion, persistence, or offensive deployment.

## Executive conclusion

An eBPF program is not a normal Rust process moved into the kernel. It is a verifier-checked, event-driven program expressed in a constrained ISA. Its program type and attachment decide the initial context, permitted helpers, permitted map operations, required return value, lifetime, and often its privilege requirements. The safest mental model is therefore **a small, total function over a typed kernel-provided context that records bounded, explicitly versioned facts into a kernel-owned transport**. [1] [3] [4]

Aya divides this application into a standard Rust **loader/consumer** using `aya` and a `#![no_std]` eBPF crate using `aya-ebpf`. The split is useful, but it does not erase kernel contracts. Aya's wrappers expose many contracts ergonomically; the verifier and the running kernel remain the final authority. In particular, a current Aya eBPF `RingBuf` exposes output failure as `Result<(), i32>` and reservation failure as `Option`, whereas its legacy `PerfEventArray::output` wrapper returns `()` and discards the helper's status. A loss-aware design should therefore prefer ring buffers on kernels that support them, count producer failures in an explicit map, and treat perf-buffer `Lost` records as a separate loss signal rather than assuming either transport is lossless. [6] [20] [21] [28]

The chapter-level engineering rule is:

> **Make every boundary explicit:** context and return contract at the hook; helper result and pointer validity in eBPF; schema, byte order, and validity at the ABI; queue capacity and loss counters at the transport; feature/privilege probing at load time; and detach/ownership at shutdown.

## 1. What is invariant, and what is not

The table separates useful teaching invariants from facts that must be checked on the target kernel. “Invariant” here means part of the eBPF ABI or a property enforced by a successfully loaded program; it does **not** mean that every eBPF feature exists on every Linux release.

| Topic | Stable teaching invariant | Version-, configuration-, or target-dependent fact |
|---|---|---|
| Register ABI | `R0` is the return/exit register; `R1`–`R5` are call arguments; `R6`–`R9` are callee-saved; `R10` is a read-only stack frame pointer. | Instruction conformance groups, JIT support, and generated code details vary by architecture and kernel. [1] [2] |
| Program execution | A program starts with a type-specific context in `R1`; the verifier proves allowed accesses and all reachable paths. | The context layout, hook availability, allowed helpers, return meanings, and attach API are selected by program/attach type. [3] [4] [14] |
| Helpers | A helper has a fixed signature and checked argument/return contract; a helper accepts at most five BPF register arguments. | Helper availability is per program type and can expand over time; GPL-only and configuration gates also matter. Probe the target. [4] [15] |
| Maps | Maps are kernel objects shared by eBPF and user space, with a map-type-specific key/value or stream contract. | Map types, flags, memory limits, BTF requirements, and Aya wrapper coverage vary with the kernel and Aya release. [5] [7] [13] [19] |
| Verifier | It tracks types, initialization, bounds, alignment, scalar ranges, and resource/reference lifetimes across control-flow paths. | Precise acceptance, complexity limits, supported loop forms, and diagnostics change. The only reliable answer is to load and inspect the verifier log on the target. [3] [15] [40] |
| Rust ABI | Default Rust layout has minimal guarantees. `#[repr(C)]` fixes field ordering/alignment by the Rust Reference's C-layout algorithm; it does not remove padding. | Layout still depends on the target ABI; a raw native struct is not an interchange format across architectures or versions. [29] |
| Ring buffer | A BPF ring buffer is shared across CPUs, non-blocking to producers, variable-record capable, mmap-backed, and readiness-notifiable. | It requires Linux 5.8 or later; NMI reservation can fail despite free capacity; exact feature availability must be tested. [6] [20] |
| Perf event array | eBPF can emit to a per-index perf event via `bpf_perf_event_output`; user space receives samples and `PERF_RECORD_LOST` records. | Aya documents a minimum of Linux 4.3. Buffer count/size consumes per-CPU resources, and loss behavior depends on consumer service rate and buffer capacity. [21] [33] |
| CO-RE/BTF | BTF relocations can adapt eligible type/field accesses to the target kernel. | BTF must exist and be usable; CO-RE cannot make an absent program type, attach point, helper, map feature, or kernel configuration appear. [22] [37] |

A kernel design statement is particularly useful but needs careful scope: the design Q&A calls BPF instructions, arguments, helpers, and recognized return values ABI, while explicitly excluding tracing programs that walk kernel internals and attachment points such as tracepoints/kprobes from stable interfaces. It also says accepted programs should remain accepted by later kernels. That does **not** make a tracing design portable when its named hook, kernel data dependency, helper, or configuration has changed. [15] [13]

## 2. Execution model: registers, calls, stack, and verifier proof

### 2.1 The BPF register contract

The eBPF ABI defines ten writable 64-bit general-purpose registers plus `R10`, a read-only frame pointer. A BPF function or program returns through `R0`; it must set `R0` before `EXIT`. `R1`–`R5` carry function-call arguments, so the helper ABI permits at most five arguments. `R6`–`R9` survive calls; `R0`–`R5` are scratch and must be spilled or reconstructed if their values are needed after a helper call. [1] [4]

At program entry, the verifier assigns `R1` the type `PTR_TO_CTX`, not an arbitrary integer address. The exact context is determined by program type: an XDP program receives an XDP context, a tracepoint program receives a tracepoint context, and a cgroup socket-option program receives `struct bpf_sockopt`, for example. The verifier checks each direct context access against the hook's permitted offsets, sizes, and alignments. After a kernel helper call, `R1`–`R5` become unreadable and `R0` receives the helper's declared return type; `R6`–`R9` retain their state. [3]

The BPF ISA uses 64-bit instructions and registers, plus defined 32-bit operations. The standardized ISA describes basic 64-bit instruction encodings, 128-bit wide immediates, endianness, arithmetic, jumps, loads/stores, atomics, and map/platform-variable immediate forms. An implementation is not required to support every optional conformance group, so a book should teach source-level semantics rather than promise a particular instruction sequence or JIT output. [2]

### 2.2 Stack and memory are small, typed, and proven

The normal BPF stack budget is small. The Aya book documents **512 bytes**, or **256 bytes when using tail calls**; the kernel BPF design Q&A states a 512-byte limit for program types. Treat this as a strict design budget, not spare working memory. Avoid large local structures, recursive-looking abstractions, formatting, and hidden temporary allocations. Use a map as a bounded scratch area when a large fixed buffer is genuinely needed, but document its concurrency model. [17] [15]

The verifier will reject a read of an unwritten stack byte, an out-of-range stack access, a misaligned access, use of an uninitialized register, or a dereference through a scalar. It also treats map lookup as nullable: `bpf_map_lookup_elem` produces a map-value-or-null pointer, and a program must prove the non-null branch before dereferencing it. A BPF source program should make those proofs obvious: initialize all local values; check helper errors; null-check every lookup; bounds-check packet pointers before every dependent access; and do not rely on compiler cleverness to reconstruct a missing proof. [3] [5]

The verifier performs abstract interpretation over all feasible paths. It tracks scalar signed/unsigned ranges and unknown bits, pointer base/type, fixed and variable offsets, alignment, stack initialization, and certain reference lifetimes. It prunes equivalent safe states to control complexity, but path explosion is still a practical rejection risk. A short branchy parser with monotonic bounds checks is usually more portable than a general parser with multiple data-dependent branches. [3] [15]

### 2.3 Calling convention consequences for Rust authors

Aya Rust source normally does not name registers, but generated code still obeys this ABI. The implication is practical: keep values needed after a helper call in ordinary Rust locals only when the compiler can spill/reload them safely; do not preserve raw kernel-derived pointers across helpers unless the helper contract and verifier state permit it; and reacquire packet data/data-end after a helper that can invalidate packet-pointer proofs. The helper manual explicitly documents type-specific helper subsets, while the verifier documentation shows that a helper call resets caller-saved register state. [3] [4]

A BPF program cannot call arbitrary kernel functions. It can call allowed helpers, and on suitable kernels may call kfuncs. Kfuncs are **not** stable user/kernel APIs: their pointer rules, availability, and signatures may change or disappear with kernel development. An advanced beginner book should present kfuncs as an optional, target-tested extension, not as the baseline portable programming model. [15] [16]

## 3. Program types: select the semantic contract first

A program type is more than an attachment label. It fixes the context type, helper subset, allowable maps or operations, return-value interpretation, whether sleeping is allowed, attachment mechanism, and operational blast radius. Aya's macro identifies the eBPF-side kind and its user-space typed program wrapper performs `load()` and a type-specific `attach()`. The object is parsed/relocated first; Aya does not automatically load every discovered program, allowing required maps and configuration to be initialized before execution begins. [14] [23] [39]

### 3.1 A defensive taxonomy

| Family | Representative types / Aya surface | Appropriate defensive use | Contract that must be read before coding |
|---|---|---|---|
| Packet observation and steering | Socket filter, XDP, TC classifier/action, cgroup skb, flow dissector, LWT | Count, sample, classify, or enforce an explicitly authorized network policy. | Packet context lifetime; packet bounds; allowed redirect/edit helpers; action return codes; device/driver support. [14] [27] |
| Event observation | Tracepoint, raw tracepoint, perf event, kprobe/kretprobe, uprobe/uretprobe, fentry/fexit | Audited diagnostics and performance telemetry with a narrow declared event set. | Hook ABI and stability, context decoding, process/kernel access rules, and event rate. Tracepoints/kprobes are not universally stable ABI. [14] [15] [23] |
| Cgroup and socket policy | Cgroup device/skb/sock/sock-address/sockopt/sysctl, sockops, sk_skb, sk_msg, sk_lookup, reuseport | Scoped policy or telemetry for workloads explicitly placed in the target cgroup/socket domain. | Cgroup traversal/chaining, context mutability, required return values, attach mode, and input-size restrictions. [14] [41] |
| System policy and extension | LSM, extension/freplace, struct_ops, syscall, netfilter | Only with a reviewed policy owner, narrow scope, and a rollback plan. | Program-specific safety model, attach/deploy rollback, kernel/config support, and non-portable APIs. [13] [14] [16] |
| Iteration and special subsystems | Iterators, perf-event, LIRC, networking map targets | Inventory or explicitly bounded aggregation. | Object lifetime, iterator protocol, callback rules, and kernel release support. [14] [23] |

The comprehensive current kernel table is intentionally large and changes as attach types evolve. For example, current documentation calls legacy `tc`, `classifier`, and `action` section conventions deprecated in favor of `tcx/*`. That is a useful illustration of why book examples must name their tested kernel range and why an application should never infer compatibility from an ELF section name alone. [14]

### 3.2 Return values are part of correctness

Do not write “return 0” by habit. The same integer can mean pass, deny, continue, a verdict, or an action depending on program/attach type. The cgroup sockopt documentation is a clear example: return `0` rejects the syscall with `EPERM`, while `1` allows the chain to continue; it also constrains which fields can be changed and by how much. XDP, TC, socket filtering, and tracing have different return contracts. Put the semantic return constant in the program's local API and test both success and error branches. [41] [14]

For a first observable program, prefer a stable-enough, explicitly enabled tracepoint or an authorized XDP/TC test interface, perform minimal extraction, emit a fixed-size event, and return the documented neutral/pass result. Do not begin with a kprobe on an arbitrary kernel symbol or an LSM enforcement hook merely because it is convenient to demonstrate. [15] [23]

## 4. Helper contracts: treat every call as a checked capability

A helper is a fixed kernel entry point selected by an ISA `BPF_CALL`, with no foreign-function-interface transition. The verifier checks helper argument types and, after the call, assigns the declared return type. Helper availability is not global: it is a whitelist per program type, and map/helper compatibility is independently checked. The `bpf-helpers(7)` implementation notes recommend `bpftool feature probe` to inspect supported program types, map types, and helpers on the actual host. [4] [3]

| Contract pattern | Kernel contract | Defensive source pattern |
|---|---|---|
| Lookup | `bpf_map_lookup_elem(map, key)` returns a value pointer or `NULL`. [4] | Branch on `Option` immediately. Never turn a missing entry into a dereference or assume an array/hash lookup cannot fail. |
| Update/delete | Map mutation returns zero on success and a negative error otherwise. Capacity, map flags, and map type constrain semantics. [5] [8] | Check and count errors when the mutation is required for telemetry correctness; decide deliberately whether a failed auxiliary counter is best-effort. |
| Perf output | `bpf_perf_event_output(ctx, perf_event_array, flags, data, size)` writes a raw record and returns zero or a negative error. `BPF_F_CURRENT_CPU` selects the current CPU's element. [4] | Use current-CPU output unless there is a justified, validated index; treat failed output as a producer-side loss. Be aware that Aya's current high-level eBPF wrapper does not return this status. [28] |
| Ring copy output | `bpf_ringbuf_output(ringbuf, data, size, flags)` copies and returns zero or negative error. [4] | Count `Err`, not just consumer-side gaps. Use zero flags unless there is a measured notification policy. |
| Ring reservation | `bpf_ringbuf_reserve(ringbuf, size, 0)` returns a writable record pointer or `NULL`; reservation flags must be zero. Every successful reservation must finish with submit or discard. [4] [6] | Prefer `RingBuf::output` for variable-length or simple records. For reserve/submit, branch once, initialize every byte, and submit/discard on every path. |
| Reference-returning helper | Some helper/kfunc results carry a verifier-tracked reference. [3] [16] | Null-check and release/transfer on every non-null path. A “leaked reference” is a verifier rejection, not a harmless resource leak. |

The important generalization is that helper return values are a **data-quality interface**. Negative return codes, `NULL`, missing CPU/perf slots, full rings, and invalid context data should become bounded counters and health metrics where loss matters. They must not turn into retries or blocking in the BPF invocation path.

## 5. Map taxonomy: choose data semantics before an API wrapper

Maps are kernel objects accessed through BPF helpers in eBPF and through the `bpf()` syscall from user space. A conventional map is configured with type, key size, value size, and `max_entries`; different programs can share one map, and map references are retained by loaded programs. User-space map values are opaque bytes at the syscall layer, so both sides must own the ABI. [5] [7]

### 5.1 Decision-oriented map table

| Need | Suitable map family | Essential behavior | Defensive cautions |
|---|---|---|---|
| Fixed small configuration or lookup table | `ARRAY`; `PERCPU_ARRAY` for per-CPU slots | Fixed index (`u32`), preallocated, zero-initialized. Array values are shared; per-CPU values are separate per CPU. [9] | Arrays cannot delete entries. In-place shared updates need synchronization. Per-CPU user-space reads represent an array of possible-CPU values, not one scalar. |
| Dynamic keyed state | `HASH`, `PERCPU_HASH`; optionally LRU variants | General key/value lookup. LRU evicts at capacity; per-CPU variants isolate values. [8] | A normal hash can be concurrent. LRU eviction makes retention deliberately approximate; never use it as an audit-complete store. |
| Longest-prefix policy/lookup | `LPM_TRIE` | Matches longest prefix; key's data is network byte order; requires `BPF_F_NO_PREALLOC`. [11] | Specify prefix byte order and fixed key construction. Iterate only for administration, not a latency path. |
| Bounded producer/consumer work item | `QUEUE`, `STACK` | FIFO/LIFO, push/peek/pop; `BPF_EXIST` push may evict the oldest item when full. [10] | This is an explicit overwrite/drop policy. Record it if data completeness matters. Not a substitute for an event stream without a consumer plan. |
| Event stream from eBPF to user space | `RINGBUF` or `PERF_EVENT_ARRAY` | Variable-sized stream records and readiness notification. Ringbuf is shared MPSC; perf buffers are normally per CPU. [6] [20] [21] | Neither blocks producers. Size capacity from measured bursts and export loss telemetry. |
| Dispatch/control transfer | `PROG_ARRAY`, `DEVMAP`, `CPUMAP`, `XSKMAP`, socket maps | Map content directs tail calls, packet/CPU redirection, AF_XDP, or sockets. [7] [13] | These are behavioral control planes, not ordinary data structures. Validate target object lifecycle and return paths. |
| One map per tenant/shard | `ARRAY_OF_MAPS`, `HASH_OF_MAPS` | One nesting level; eBPF can look up the outer map, user space updates outer entries. [12] | Inner-map shape compatibility and outer-map lifecycle matter; no multi-level nesting and no eBPF outer updates/deletes. |
| Object-local state | cgroup/task/inode/socket storage maps | State attached to a kernel object rather than a global key. [7] [13] | Object lifetime, program type, BTF support, and cleanup semantics require feature-specific tests. |
| Probabilistic membership | Bloom filter | Membership-oriented storage. [7] [19] | A positive is not proof. Never treat it as a complete security/audit record. |

The current UAPI enumeration also includes newer forms such as `BPF_MAP_TYPE_USER_RINGBUF`, `BPF_MAP_TYPE_ARENA`, `BPF_MAP_TYPE_INSN_ARRAY`, and `BPF_MAP_TYPE_RHASH`. Their presence in current headers does not mean an installed kernel supports them, nor that the current Aya map module has a mature typed wrapper. State that distinction explicitly in a book; it avoids a common mistake of treating UAPI enumeration as deployment availability. [13] [19] [26]

### 5.2 Concurrency is a map property plus an algorithm property

A map lookup returning a pointer does not make a multi-field read-modify-write atomic. Hash and array values can be accessed concurrently. The kernel documents `bpf_spin_lock` support beginning with Linux 5.1, but a beginner-friendly design should first ask whether per-CPU aggregation, immutable replacement, or a single scalar atomic operation avoids shared mutable state altogether. [8] [9]

For counters, prefer a `PERCPU_ARRAY`/`PERCPU_HASH` and sum in user space when exact cross-CPU instant consistency is not needed. For a normal shared map, define the synchronization method and what a reader may observe. For LRU maps, define eviction as expected data loss, not a rare error. For map-of-maps, define user-space update/rollback and inner-map compatibility before introducing sharding. [8] [12]

## 6. Aya programming model and the `no_std` split

### 6.1 Two crates, two environments

Aya is a Rust-native eBPF ecosystem that does not depend on libbpf or BCC at runtime. The user-space `aya` crate loads object code, creates maps, applies relocations, exposes typed program/map conversions, and attaches programs. The eBPF `aya-ebpf` crate provides context types, map definitions, helper bindings, and macros for code compiled to the BPF target. As checked at the research cutoff, Aya source at commit `0e353a7fddf80091ae2fb2dacc08ec1d861e67cc` declares `aya` 0.14.0 and `aya-ebpf` 0.2.1. APIs should be documented with that version or a locked Cargo dependency, not merely “latest.” [18] [22] [28]

The eBPF crate is `#![no_std]`. Rust's `no_std` attribute prevents automatic linking of `std` and switches the standard prelude to `core`; it does not by itself promise an allocator-free binary if a dependency explicitly links `std`. Aya's book adds the BPF runtime constraints: use `core`, not `std`; do not depend on `alloc`/collections as a heap substitute; avoid formatting traits that need unavailable support; do not panic; and do not expect a normal `main`. The Aya integration examples use `#![no_std]`, `#![no_main]`, and an `ebpf_panic` runtime dependency outside tests. A no-std binary requires one panic handler in its dependency graph, but a BPF program should be engineered so the handler is unreachable. [17] [30] [31] [28]

Aya macros make the object discoverable by putting program functions and map statics in appropriate ELF sections. For example, the current `#[tracepoint(name = "…", category = "…")]` macro produces a `tracepoint/<category>/<name>` section and wraps a `TracePointContext`. The `#[map]` macro exports a static in the maps section. This is an object-format convention, not a replacement for the kernel's program-type checks. [27] [28]

### 6.2 Loading and typed conversion

`Ebpf::load_file` or `Ebpf::load` parses object code and initializes maps. When usable kernel BTF is present, Aya automatically loads `/sys/kernel/btf/vmlinux`; `Ebpf::load` requires a 4-byte-aligned object buffer, for which its documentation recommends `include_bytes_aligned` when embedding bytecode. Maps and programs are initially opaque (`Map`, `Program`) and become typed with `TryFrom`/`TryInto`; a program then receives explicit `load()` and type-specific `attach()` calls. [36] [19] [23]

This staged lifecycle is a defensive feature. Load and initialize configuration maps before attaching the program, check every conversion and attach error, record the selected hook/target and link information, then start consumers before enabling high-rate production. On shutdown, detach links first and only then close maps/objects. Do not assume closing a user-space file descriptor stops execution: an attachment, another descriptor, or a BPF filesystem pin can retain an object. [5] [36]

### 6.3 Shared ABI types: share the definition, not blind trust

A `common` crate can make eBPF and user-space source agree on an event definition. It must itself be `no_std`-compatible and contain only the schema types, constants, byte conversion routines, and compile-time checks required by both sides. It should not drag `aya`, `std`, allocation, parsing, or asynchronous runtime dependencies into the eBPF crate.

Use this hierarchy of safety:

1. **For an in-host, fixed record:** use `#[repr(C)]`, fixed-width integers, explicit reserved bytes/words, a schema version, a kind, and a documented native-endian policy. Initialize every field and every explicit reserve field before output.
2. **For a durable or cross-machine format:** define the wire record as bytes and encode/decode each field in a stated byte order, usually little-endian. Do not transmit a Rust struct representation as a protocol.
3. **For all formats:** prohibit pointers/references, `usize`/`isize`, `bool`, `char`, Rust enums, `Option<T>`, `NonZero*`, and unvalidated bitfield-like interpretations in raw records. Their validity or layout is not a general byte protocol.
4. **At the consumer:** validate version, kind, exact/minimum length, reserved fields if policy requires, and every length/count before slicing. Malformed input is a metric and a bounded error path, never an unchecked cast.

`#[repr(C)]` gives field order and C-layout padding rules, while the default Rust representation allows field reordering and supplies no general layout guarantee. `#[repr(C)]` **does not eliminate padding**. A `Pod` assertion is therefore a safety claim, not a serialization derive: Aya's `Pod` is an `unsafe trait` (`Copy + 'static`) precisely because it permits conversions to/from byte slices. Rust also treats producing invalid values, uninitialized scalar values, misaligned loads/stores, and data races as undefined behavior. [29] [32] [28]

A conservative 32-byte example record is:

```rust
// common/src/lib.rs
#![no_std]

pub const EVENT_SCHEMA_V1: u16 = 1;
pub const EVENT_EXEC: u16 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EventV1 {
    pub schema: u16,
    pub kind: u16,
    pub tgid: u32,
    pub tid: u32,
    pub reserved0: u32,      // explicit; always initialized to 0 in v1
    pub producer_drops: u64, // per-CPU producer failures observed before this record
    pub sequence: u64,       // source-defined, not a global time order
}

// Verify size/alignment in CI for each BPF and host target. Do not assume it.
```

This layout has deliberately explicit filler so there is no implicit gap before the first `u64` on ordinary C-layout targets. The exact size/alignment should nevertheless be asserted in CI for both compilation targets. In the user-space crate only, after a review that proves all bit patterns are valid and no padding can be uninitialized, the application may write `unsafe impl aya::Pod for EventV1 {}` for map APIs that require it. A ring-buffer consumer can instead decode bytes explicitly and avoid treating an incoming byte slice as `&EventV1` at all. [19] [28] [29] [32]

### 6.4 A deliberately small Aya event example

The following is a **design sketch**, not an attach-anywhere recipe. It assumes a compatible target kernel, an enabled/authorized `sched/sched_process_exec` tracepoint, a current Aya version, and a reviewed user-space loader. The event is intentionally fixed-size. `RingBuf::output` copies the initialized record and reports output failure; a per-CPU map keeps a best-effort producer-failure count. [20] [24] [28]

```rust
// ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use common::{EventV1, EVENT_EXEC, EVENT_SCHEMA_V1};

#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static PRODUCER_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn observe_exec(ctx: TracePointContext) -> u32 {
    let previous = PRODUCER_DROPS.get(0).copied().unwrap_or(0);
    let event = EventV1 {
        schema: EVENT_SCHEMA_V1,
        kind: EVENT_EXEC,
        tgid: ctx.tgid(),
        tid: ctx.pid(),
        reserved0: 0,
        producer_drops: previous,
        sequence: 0, // define/update only if the chosen sequence semantics are safe
    };

    if EVENTS.output(&event, 0).is_err() {
        // The policy is “drop this telemetry record; account for it; never block.”
        // Treat this counter as best-effort unless its concurrent update semantics
        // have been separately established for this program context.
        let next = previous.saturating_add(1);
        let _ = PRODUCER_DROPS.set(0, &next, 0);
    }
    0
}
```

Two cautions matter more than the syntax. First, use the current Aya context methods only after importing `EbpfContext`; its default `pid()`/`tgid()` methods wrap `bpf_get_current_pid_tgid`. Second, a per-CPU counter reduces cross-CPU sharing but is not an automatic proof that a multi-step read/modify/write is exact under every execution context. If exact loss accounting is a requirement, specify the synchronization/aggregation algorithm and test it under concurrent load. [28] [8] [9]

On the user side, convert the map to `aya::maps::RingBuf`, poll its file descriptor, and drain `next()` until it returns `None`. A `RingBufItem` borrows the mmap data; current Aya permits only one outstanding item and advances the consumer position when that item is dropped. Decode/copy only the bounded bytes needed, then release it promptly. Do not retain the borrowed slice across async work. [20] [28]

## 7. Ring buffers, perf buffers, backpressure, and loss

### 7.1 Ring buffer semantics

`BPF_MAP_TYPE_RINGBUF` was created to address two perf-buffer limitations: aggregate memory use from per-CPU buffers and loss of a shared ordering across CPUs. It is a single shared multi-producer/single-consumer ring map. `key_size` and `value_size` are zero; `max_entries` is the byte capacity and must be a power of two. It supports variable records, mmap consumption, readiness notification, and optional busy polling. [6]

The kernel offers two producer patterns:

* **Copy output:** `bpf_ringbuf_output` copies from a source buffer. It can handle sizes not statically known to the verifier, but pays a copy. Aya exposes this as `RingBuf::output`, returning `Result<(), i32>`.
* **Reserve/commit:** `bpf_ringbuf_reserve` returns writable ring memory, then every path must `submit` or `discard`. It avoids a temporary copy but the verifier must know the reservation size. Aya exposes `reserve`/`reserve_bytes` returning `Option<RingBufEntry<_>>`/`Option<RingBufBytes>`, whose `#[must_use]` annotation calls out the submit-or-discard requirement. [6] [24] [28]

Reservation is non-blocking. A failure means capacity is unavailable; in NMI context, reservation may also fail because it cannot obtain the reservation spinlock even when the ring is not full. Commit order follows reservation order, and an earlier slow producer can hold back later completed records. Therefore, keep reserved-record work minimal, fill a fully formed record immediately, and submit or discard before any complicated branching. [6]

The default notification policy is adaptive: notify when the consumer had caught up; do not generate redundant wakeups while it is already behind. `BPF_RB_NO_WAKEUP` and `BPF_RB_FORCE_WAKEUP` provide manual control, but are a performance tuning choice that requires a tested consumer wakeup strategy. A book should not present `NO_WAKEUP` as a default optimization: it can turn a correct stream into a latency or liveness problem when paired with an incorrect poll loop. [6] [4]

Aya documents Linux **5.8** as the minimum kernel version for `RingBuf`. Its user-space `RingBuf::next()` yields bytes directly from the mmap. Current Aya source pairs acquire/release ordering with the kernel's producer/consumer positions; application code should rely on Aya's API rather than attempting its own mmap consumer. [20] [28]

### 7.2 Perf-event-array semantics

`BPF_MAP_TYPE_PERF_EVENT_ARRAY` is an array of perf-event file descriptors. `bpf_perf_event_output` writes a raw blob to an element selected by flags or `BPF_F_CURRENT_CPU`. Aya user space turns each opened element into a `PerfEventArrayBuffer`; a common setup opens one buffer for each online CPU and drains each buffer on readiness. Aya documents a Linux **4.3** minimum for this feature. [4] [21]

Perf's mmap ring exposes a monotonically increasing `data_head` written by the kernel and a `data_tail` written by user space. The consumer must obey the documented read/write ordering and advance the tail after consuming records; Aya's implementation manages that detail. When the perf ring is full, the kernel can generate `PERF_RECORD_LOST`; Aya reports it as `PerfEvent::Lost { count }`, separately from `PerfEvent::Sample`. This is an advantage for loss visibility, not a guarantee that no preceding observation was dropped. [33] [28]

A critical Aya API detail deserves a callout. The current eBPF-side `PerfEventArray<T>::output` and `output_at_index` methods return `()`; their implementation calls `bpf_perf_event_output` but does not expose its return value. Thus, the high-level wrapper cannot directly count immediate producer output errors. The user-space `Lost` record remains necessary, but it arrives later and reflects perf-ring loss. If a design requires producer-side error telemetry on this path, use a reviewed lower-level helper binding or choose a `RingBuf` on supported kernels. Pin the Aya version and test this behavior after upgrades. [25] [28]

### 7.3 Ring buffer versus perf buffer

| Dimension | `BPF_MAP_TYPE_RINGBUF` / Aya `RingBuf` | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` / Aya `PerfEventArray` |
|---|---|---|
| Minimum documented by Aya | Linux 5.8. [20] | Linux 4.3. [21] |
| Topology | One shared MPSC buffer. | Typically one buffer per CPU/index. |
| Ordering | Strict reservation order in one shared ring; do not call it universal causal/time order. [6] | Per-buffer order; merging CPUs needs sequence/timestamp policy. |
| Producer API | Copy output or reserve/submit/discard. | `bpf_perf_event_output` to indexed perf event. |
| Copy avoidance | Reserve/submit can fill ring memory directly for verifier-known size. | Output is a raw-data write through perf path. |
| Producer failure visibility in current Aya wrapper | `output -> Result`; `reserve -> Option`. [24] | High-level eBPF `output -> ()`; user-space receives later `Lost` records. [25] [28] |
| Consumer | `RingBuf::next()` bytes; release item promptly. | Open per-index buffers; drain `Sample` and `Lost`. |
| Capacity cost | One shared capacity; contention and one slow reserved record can matter. | Capacity scales with configured CPU buffers; more FDs/mmap memory and per-CPU consumer scheduling. [21] [33] |
| Good default | Current-kernel event telemetry requiring compact, shared transport and explicit producer-drop accounting. | Compatibility fallback or intentionally per-CPU pipeline with visible lost records. |

### 7.4 A complete loss model

“Dropped events” is too vague to debug. Export separate counters and status for at least these conditions:

| Loss/quality dimension | Where observed | Recommended accounting |
|---|---|---|
| Hook unavailable or attach failed | Loader | Configuration/status metric with kernel release, hook, program type, verifier log summary, and capability failure. |
| Program not invoked as expected | Test/health path | Compare a low-rate known trigger or entry counter against expected test activity; do not infer this from an empty transport. |
| Helper/context read failure | eBPF | Per-CPU error counter by helper/error class; emit no partial record unless the schema says fields are absent. |
| Ring producer capacity/reservation failure | eBPF | Per-CPU `ring_output_errors`/`ring_reserve_failures`; include a prior-drop count in the next successful event if useful. |
| Perf buffer overrun | User space | Sum every `PerfEvent::Lost { count }` per CPU and report the interval/rate. |
| Consumer parse/version rejection | User space | Count malformed length, unknown schema, invalid field, and application queue rejection separately. |
| Intentional sampling/filtering | eBPF configuration | Export the sampling denominator/policy and configuration revision, so lower volume is not mistaken for loss. |
| Consumer lag | User space | Track drain time, queue depth, poll latency, handler time, and ring/perf capacity configuration. Ringbuf query values are snapshots for heuristic reporting, not exact accounting. [6] |

The event path must have a defined overload policy. For observation telemetry, a defensible policy is commonly **drop new event, increment a bounded per-CPU counter, return promptly**. For a security or audit requirement that forbids loss, do not silently upgrade the ring size and claim success: eBPF transport alone cannot promise durable, loss-free delivery under unbounded producer rate. Reduce the event rate, aggregate in-kernel, move required decisions to a reliable control path, or change the stated guarantee.

### 7.5 Backpressure design rules

1. **Never wait in eBPF.** Ring and perf output failure is a result, not a request to spin, sleep, allocate, or retry in the hot invocation.
2. **Bound work before transport.** Filter early, aggregate counters/histograms instead of emitting every event, cap payload size, and use fixed schemas where feasible.
3. **Drain to empty after readiness.** A readiness event means “work may exist,” not “exactly one record exists.” For ring buffers, call `next()` until `None`; for perf arrays, fully drain each readable buffer. [20] [21]
4. **Keep consumer handlers short.** Copy/decode only the minimal record in the poll thread and move expensive enrichment/storage to a bounded user-space queue with its own explicit drop policy.
5. **Size from bursts, not averages.** Measure peak event rate, record size including headers/alignment, maximum scheduling delay, CPU count for perf, and expected consumer pauses. Re-test under the actual CPU topology and resource limits.
6. **Separate notification tuning from capacity.** `NO_WAKEUP` affects wakeups; it does not create capacity. First make the default adaptive policy correct, then benchmark a deliberate batching policy. [6]
7. **Exercise failure paths.** Test full rings, delayed consumer, malformed record, unavailable CPU buffer, map capacity exhaustion, and an attach/load rejection. Preserve verifier logs for rejected artifacts. [5] [40]

## 8. Verifier traps and their source-level remedies

| Trap | Why the verifier or Rust rejects it | Defensive remedy |
|---|---|---|
| Read before initialize | Registers and stack slots have initialization state. [3] | Build records from a full literal or zero initialized buffer, then overwrite fields. Never output an uninitialized local struct. |
| Dereference after map lookup without null check | Lookup result is `PTR_TO_MAP_VALUE_OR_NULL`. [3] | Match `Option` and dereference only inside `Some`. |
| Misaligned packed record field | eBPF access alignment is checked; Rust references to packed fields can be invalid. [3] [32] | Prefer an explicitly padded `repr(C)` record. If parsing packed wire bytes, use byte copies/read-unaligned only where justified and isolate unsafe code. |
| Pointer arithmetic destroys provenance/type | The verifier tracks pointer class and bounded offsets. [3] | Keep base pointer and checked offset close together; use helpers/context accessors; bounds-check before every variable-length access. |
| Reusing packet pointers after a mutating helper | A helper can change underlying packet storage and invalidate earlier range proof. [4] | Reload data/data-end and repeat bounds checks after any documented invalidating helper. |
| Dynamic ring reservation size | Verifier must prove reserved memory bounds. [6] [24] | Use `output` for dynamic length or reserve a compile-time sized type/array. |
| Reserve without submit/discard on all paths | Ring records are verifier-tracked resources. [6] [24] | Structure `match reserve` so every `Some(entry)` path immediately ends in `submit` or `discard`; keep post-reserve code linear. |
| A hidden panic path | BPF has no ordinary stack unwinding/abort support; current Aya RingBuf checks may compile a panic on invalid alignment. [17] [24] | Avoid `unwrap`, indexing with unchecked values, asserts in data paths, and types with ring alignment above 8. Treat panic-free control flow as a requirement. |
| Large or branch-explosive code | Verifier tracks all feasible paths and may hit internal complexity limits. [3] [15] | Split into small phases, cap iteration, minimize data-dependent branching, and test the optimized release object on oldest supported kernels. |
| Incorrect program return code | The value's meaning is program/attach-specific. [14] [41] | Define named return constants and unit/integration test allow/deny/pass behavior. |
| Borrowing ring/perf mmap bytes too long | Aya items are borrowed views; dropping advances consumer progress. [20] [28] | Validate and copy or process synchronously; do not hand a borrowed slice to an async task. |

When `BPF_PROG_LOAD` returns `EACCES` for an otherwise syntactically valid program, request a verifier log and read the first rejected state transition. The `bpf(2)` manual calls out uninitialized stack/registers, disallowed memory, bad helper argument types, and alignment as common causes. `EAGAIN` during program load is retryable when verification was interrupted by pending signals; `EINVAL` can indicate unrecognized instructions, reserved fields, an invalid jump, an infinite loop, or an unknown function. [5]

## 9. Portability and deployment-risk checklist

### 9.1 Kernel and architecture matrix

Record and test the following per supported target rather than advertising a single “Linux support” claim:

| Check | Why it matters | Evidence/response |
|---|---|---|
| `uname -r`, architecture, distribution kernel package | Map/helper/attach behavior is kernel-version and configuration dependent. | Maintain a tested kernel matrix; pin the oldest production target. |
| `/sys/kernel/btf/vmlinux` readability and BTF load | Aya/CO-RE can use target BTF only when present and usable. [36] [37] | Use CO-RE where applicable; retain a non-CO-RE/fallback plan or fail with a clear diagnostic. |
| `bpftool feature probe` (and, where relevant, `unprivileged`) | Enumerates supported map/program/helper features on the host. [4] | Gate optional artifacts such as ringbuf rather than guessing from a release string. |
| Kernel configuration | Some program families/features require config options; cgroup BPF and perf policy are examples. [36] [41] | Verify the actual booted config where available; report capability/config mismatch distinctly from verifier rejection. |
| Capability and security policy | Linux 5.8 introduced `CAP_BPF` and `CAP_PERFMON`; perf documentation recommends `CAP_PERFMON` rather than broad `CAP_SYS_ADMIN` for monitoring. [34] [35] | Grant the narrowest documented capabilities to the loader, not the eBPF object; treat failure as a configuration error. |
| Resource limits | Maps, perf buffers, file descriptors, and locked memory
 bound available capacity and can reject otherwise-valid designs. | Budget `RLIMIT_MEMLOCK`/related kernel accounting, `perf_event_mlock_kb`, and `RLIMIT_NOFILE`; size per deployment rather than laptop defaults. [33] [35] |
| CPU topology and hotplug | Perf arrays use CPU indexes; per-CPU map values include possible CPUs; CPU count changes affect collection and aggregation. | Open only online CPUs, handle startup failures, export covered CPU set, and test on a multi-CPU host. [9] [21] |
| Aya/Rust toolchain and object target | The eBPF crate uses a nightly/rust-src/bpf-linker setup that changes over time. [44] | Pin toolchain and Aya versions; rebuild exact objects in CI; retain build metadata and verifier logs. |

A local observation is not a portability fact. In this research sandbox the running kernel reported `6.18.38+`, `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `kernel.unprivileged_bpf_disabled=2`, and no readable `/sys/kernel/btf/vmlinux`. That demonstrates why a loader must probe; it says nothing about another host.

### 9.2 NixOS-specific operational guidance

NixOS provides reproducible kernel selection through `boot.kernelPackages`, which defaults to `pkgs.linuxPackages` and changes the corresponding kernel-specific package set. The stable manual says it replaces the kernel and packages tied to it; current Nixpkgs source describes it as a function producing at least `kernel`. Record the realized `config.boot.kernelPackages.kernel.version`, Nixpkgs revision, relevant BPF configuration, and the booted kernel. If configuration is unavoidable, use a reviewed `boot.kernelPatches`/`structuredExtraConfig` change. NixOS documents config names without the `CONFIG_` prefix. Do not label a variant “eBPF-capable” without normal runtime feature preflight. [38] [43]

### 9.3 Feature-probe instead of release-gating

A minimum release is documentation, not a correctness decision. Probe required program/attach types, target hook, helpers for that type, map types/flags, BTF, ringbuf, cgroup/perf configuration, privileges, and resources. The helper manual specifically identifies `bpftool feature probe` and `bpftool feature probe unprivileged` as host-inspection tools. Linux 5.8 is Aya's documented RingBuf minimum, but it does not guarantee the rest of an application works. [4] [20] [21] [36]

## 10. Exact facts that require cautious wording

| Avoid saying | Prefer saying | Why |
|---|---|---|
| “eBPF runs safely in the kernel.” | “The kernel verifies a particular program under a particular program type, privilege policy, and feature set before load.” | Verification does not automatically prove application logic, privacy, availability, or data quality. [3] [5] |
| “BPF is a portable VM.” | “The ISA and helper ABI have stable elements, but hooks, tracing internals, kfuncs, configuration, and features impose portability boundaries.” | The kernel Q&A says BPF is not a generic VM and distinguishes tracing/kfunc instability. [15] [16] |
| “CO-RE means compile once, run everywhere.” | “CO-RE relocates eligible BTF-described accesses; it cannot provide absent hooks, helpers, map types, permissions, or configurations.” | CO-RE is bounded by the target kernel and BTF. [37] [36] |
| “`repr(C)` makes byte casting safe.” | “`repr(C)` specifies layout; conversion still requires initialized valid values, correct alignment, and an explicit padding policy.” | Rust validity and alignment requirements remain. [29] [32] |
| “`Pod` means serializable.” | “Aya `Pod` is an unsafe byte-conversion promise for map APIs, not a protocol compatibility guarantee.” | Endianness, version, padding, and validity remain application responsibilities. [28] [29] |
| “Ring buffers preserve event order.” | “A single ring makes records available in reservation order; it does not prove universal causal/time order, and an early uncommitted record can delay later records.” | Reservation and commit differ. [6] |
| “Perf buffers report all drops.” | “Aya surfaces `PERF_RECORD_LOST`; count it separately from producer helper failures and application parse/queue drops.” | Loss occurs at several stages. [21] [28] |
| “Use the latest Aya API.” | “Pin a release/commit and re-check API return types, kernel minima, and generated-object behavior after upgrades.” | This research checked Aya 0.14.0 / `aya-ebpf` 0.2.1 source at the cutoff. [18] [22] |
| “CAP_SYS_ADMIN is required.” | “Privileges are operation- and policy-dependent; modern Linux provides `CAP_BPF` and `CAP_PERFMON`, while older texts may cite `CAP_SYS_ADMIN`.” | Capabilities evolved. [5] [34] [35] |

## 11. Chapter claims and teaching sequence

The book can safely make these claims: **program type defines the execution contract; maps are data-semantic choices; the verifier rewards simple total control flow; the eBPF/user-space boundary is an ABI owned by the application; loss must be measured at each stage; and portability is a preflight/CI result rather than a slogan.** [3] [7] [15] [28]

Teach a fixed-record, low-rate observer first. Its event should have a version, kind, exact bounded length, explicit initialized padding, producer-drop metric, and consumer validation. Next explain entry context, return code, helper clobbers, stack, map lookup nullability, and verifier logs. Introduce arrays/hashes/per-CPU maps before stream maps, then contrast ring/perf transport, then finish with loader lifecycle, BTF/CO-RE boundaries, capability/resource preflight, NixOS kernel selection, CI, and overload tests. The final exercise should intentionally fill the transport and require the reader to explain every counter, rather than celebrate a happy-path event. [6] [9] [20] [21] [23] [38]

## 12. Pre-merge review checklist

| Review question | Evidence required |
|---|---|
| What are program type, hook, context ABI, and return semantics? | Exact kernel documentation and success/error-path test. |
| Can data be aggregated instead of emitted per event? | Rate, record-size, sampling, privacy, and payload budget. |
| What maps are used? | Capacity, flags, synchronization, ownership, and eviction/loss policy. |
| Are helpers available and checked? | Target feature probe or preflight; all meaningful results handled. |
| Does every pointer/reservation have a verifier proof? | Release-object verifier log and miss/short-input/reserve-fail tests. |
| Is the record a documented ABI? | Version/kind/length/endian/padding policy plus host+BPF layout CI checks. |
| Can the stream overload? | Producer failures, `PerfEvent::Lost`, parse/queue drops, lag, and capacity metrics. |
| Is deployment least privilege and reversible? | Narrow capabilities, explicit link tracking, pinning policy, detach, rollback. |
| Does the claimed fleet work? | Kernel/architecture/Nixpkgs matrix and BTF-present/absent test outcomes. |

## Sources read and methodology

This dossier followed broad discovery with full-page reading of Linux kernel documentation and UAPI source, Linux man-pages, Aya documentation and a current Aya source checkout, Rust Reference pages, NixOS manual/options source, and current Nixpkgs source. The references below list every distinct external source actually read. Aya implementation details were also checked in local source cloned at commit `0e353a7fddf80091ae2fb2dacc08ec1d861e67cc` on 10 September 2026. Index pages orient taxonomy; normative claims rely on cited kernel, UAPI, man-page, Rust, NixOS, or implementation references.

## References

[1]: https://docs.kernel.org/bpf/standardization/abi.html "BPF ABI Recommended Conventions and Guidelines"
[2]: https://docs.kernel.org/bpf/standardization/instruction-set.html "BPF Instruction Set Architecture"
[3]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier"
[4]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) — Linux manual page"
[5]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — Linux manual page"
[6]: https://docs.kernel.org/bpf/ringbuf.html "BPF ring buffer"
[7]: https://docs.kernel.org/bpf/maps.html "BPF maps"
[8]: https://docs.kernel.org/bpf/map_hash.html "BPF_MAP_TYPE_HASH, with PERCPU and LRU Variants"
[9]: https://docs.kernel.org/bpf/map_array.html "BPF_MAP_TYPE_ARRAY and BPF_MAP_TYPE_PERCPU_ARRAY"
[10]: https://docs.kernel.org/bpf/map_queue_stack.html "BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK"
[11]: https://docs.kernel.org/bpf/map_lpm_trie.html "BPF_MAP_TYPE_LPM_TRIE"
[12]: https://docs.kernel.org/bpf/map_of_maps.html "BPF_MAP_TYPE_ARRAY_OF_MAPS and BPF_MAP_TYPE_HASH_OF_MAPS"
[13]: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h "Linux UAPI bpf.h (current mainline source)"
[14]: https://docs.kernel.org/bpf/libbpf/program_types.html "Program Types and ELF Sections"
[15]: https://docs.kernel.org/bpf/bpf_design_QA.html "BPF Design Q&A"
[16]: https://docs.kernel.org/bpf/kfuncs.html "BPF Kernel Functions (kfuncs)"
[17]: https://aya-rs.dev/book/ "Building eBPF Programs with Aya — Getting Started"
[18]: https://github.com/aya-rs/aya "Aya source repository README"
[19]: https://docs.rs/aya/latest/aya/maps/index.html "aya::maps — Rust"
[20]: https://docs.rs/aya/latest/aya/maps/ring_buf/struct.RingBuf.html "aya::maps::ring_buf::RingBuf — Rust"
[21]: https://docs.rs/aya/latest/aya/maps/perf/struct.PerfEventArray.html "aya::maps::perf::PerfEventArray — Rust"
[22]: https://github.com/aya-rs/aya/tree/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc "Aya source snapshot inspected at the research cutoff"
[23]: https://docs.rs/aya/latest/aya/programs/index.html "aya::programs — Rust"
[24]: https://docs.rs/aya-ebpf/latest/aya_ebpf/maps/ring_buf/struct.RingBuf.html "aya_ebpf::maps::ring_buf::RingBuf — Rust"
[25]: https://docs.rs/aya-ebpf/latest/aya_ebpf/maps/perf/struct.PerfEventArray.html "aya_ebpf::maps::perf::PerfEventArray — Rust"
[26]: https://docs.rs/aya-ebpf/latest/aya_ebpf/maps/index.html "aya_ebpf::maps — Rust"
[27]: https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/ "aya_ebpf_macros — Rust"
[28]: https://github.com/aya-rs/aya/tree/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc "Aya 0.14.0 / aya-ebpf 0.2.1 implementation source inspected locally"
[29]: https://doc.rust-lang.org/reference/type-layout.html "Rust Reference: Type layout"
[30]: https://doc.rust-lang.org/reference/names/preludes.html#the-no_std-attribute "Rust Reference: The no_std attribute"
[31]: https://doc.rust-lang.org/reference/panic.html "Rust Reference: Panic"
[32]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html "Rust Reference: Behavior considered undefined"
[33]: https://man7.org/linux/man-pages/man2/perf_event_open.2.html "perf_event_open(2) — Linux manual page"
[34]: https://man7.org/linux/man-pages/man7/capabilities.7.html "capabilities(7) — Linux manual page"
[35]: https://docs.kernel.org/admin-guide/perf-security.html "Perf events and tool security"
[36]: https://docs.rs/aya/latest/aya/struct.Ebpf.html "aya::Ebpf — Rust"
[37]: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html "libbpf Overview"
[38]: https://nixos.org/manual/nixos/stable/#sec-kernel-config "NixOS Manual: Linux Kernel"
[39]: https://aya-rs.dev/book/programs/ "Building eBPF Programs with Aya: Program Types"
[40]: https://docs.kernel.org/bpf/bpf_devel_QA.html "BPF Development Q&A"
[41]: https://docs.kernel.org/bpf/prog_cgroup_sockopt.html "BPF_PROG_TYPE_CGROUP_SOCKOPT"
[42]: https://docs.kernel.org/userspace-api/ebpf/syscall.html "eBPF Syscall"
[43]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/system/boot/kernel.nix "Nixpkgs boot.kernelPackages option definition"
[44]: https://aya-rs.dev/book/start/development/ "Building eBPF Programs with Aya: Development Environment"
[45]: https://docs.aya-rs.dev/ "Aya generated API documentation landing page"
[46]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/ebpf/aya-ebpf/src/lib.rs "Aya eBPF crate root at inspected revision"
[47]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/ebpf/aya-ebpf/src/maps/ring_buf.rs "Aya eBPF RingBuf implementation at inspected revision"
[48]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/ebpf/aya-ebpf/src/maps/perf/perf_event_array.rs "Aya eBPF PerfEventArray implementation at inspected revision"
[49]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya/src/maps/ring_buf.rs "Aya user-space RingBuf implementation at inspected revision"
[50]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya/src/maps/perf/perf_buffer.rs "Aya user-space perf buffer implementation at inspected revision"
[51]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya/src/bpf.rs "Aya Pod trait and loader implementation at inspected revision"
[52]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya-ebpf-macros/src/tracepoint.rs "Aya tracepoint macro implementation at inspected revision"
[53]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/ebpf/aya-ebpf/src/programs/tracepoint.rs "Aya TracePointContext implementation at inspected revision"
