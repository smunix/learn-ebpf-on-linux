#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "II", chapter: "04")
= Instructions, Program Types, Helpers, and Maps <ch-04>

An extended Berkeley Packet Filter (eBPF) program is a deliberately small program that the Linux kernel checks before it may run at a selected hook. It is not a normal user-space process relocated into the kernel, and it is not a general-purpose kernel module. Its instruction-set architecture (ISA), program type, helper calls, maps, and return value together form a contract. This chapter establishes that contract before asking the reader to observe a system call (syscall): the controlled transfer from user space into the kernel.

== Prerequisites and learning objectives <ch04-sec-prerequisites>

This chapter assumes that you can use a shell in a disposable Linux virtual machine (VM), can distinguish a process from a thread, and have completed the lab preflight in the preceding material. You should also have the repository checkout available, with the pinned Rust/Aya workspace under `samples/`. The exercise loads a kernel program only when its runtime gates are satisfied; reading and building the source are safe, but attachment is not a promise that the booted kernel accepts it.

By the end of the chapter, you should be able to:

- explain why the program type must be chosen before writing eBPF logic;
- read the eBPF register calling convention and identify which values survive a helper call;
- distinguish a kernel-provided context, a helper contract, a map contract, and a program return contract;
- select an array, hash, per-central-processing-unit (per-CPU) map, or event transport based on data semantics rather than API convenience;
- explain precisely what the `02-syscall-counter` sample counts, what it does not count, and why its result is an observation rather than an audit-complete record; and
- run and remove the sample in an audit-only, reproducible way in a disposable VM.

#concept(title: [The right mental model], [Treat an eBPF program as a *small, total function over a typed kernel context*. The kernel chooses when the function runs and what `R1` initially means. The program may perform only verifier-approved operations, record bounded state through maps, and produce the return value that this program type expects. “The bytecode loaded” is therefore only one stage: target hook, configuration, authority, map capacity, and detach lifecycle remain part of correctness.])

== From ISA to a verifier-visible function <sec-isa>

The Berkeley Packet Filter (BPF) ISA supplies a register machine with arithmetic, branching, loads and stores, calls, and an exit instruction. eBPF operations are principally 64-bit, with defined 32-bit forms; source code should express the intended calculation rather than depend on a particular just-in-time (JIT) compiler sequence. The BPF design documentation describes instructions, helper arguments, and recognized returns as ABI-level interfaces, while warning that tracing attachment points and kernel-internal walks do not thereby become stable interfaces #cite(<bpf-design-q-and-a>).

The application binary interface (ABI) is compact: ten writable 64-bit registers, `R0` through `R9`, plus a read-only `R10` frame pointer. At entry, `R1` is not merely a number. The verifier assigns it a pointer-to-context type appropriate to the selected program type. A tracepoint handler receives tracepoint context; an eXpress Data Path (XDP) handler receives a packet context. The verifier permits only the accesses that its type and range analysis can prove for that context #cite(<bpf-verifier>).

#figure(
  image("../../assets/diagrams/generated/04-ebpf-abi.svg", width: 100%),
  caption: [The eBPF call boundary. Registers encode both values and verifier-tracked categories: a context pointer in `R1` cannot be used as a freely invented integer address.],
) <fig-ebpf-registers>

The generated register diagram in #figure-ref(<fig-ebpf-registers>, title: [eBPF call boundary]) is worth memorising as a data-lifetime diagram, not just as a list of names. `R0` holds the value returned by a program or helper. `R1` through `R5` are argument registers at a call boundary. `R6` through `R9` are callee-saved: a helper call preserves their verifier state. `R10` points at the top of a small stack, conventionally addressed at negative offsets. The standard design budget is a 512-byte total eBPF stack; keep a generous margin, particularly when calls or tail-call designs are introduced #cite(<bpf-design-q-and-a>).

#figure(
  table(
    columns: (1.1fr, 2.15fr, 2.6fr),
    inset: 5pt,
    align: (left, left, left),
    table.header(
      [*Register group*], [*Boundary meaning*], [*Practical source rule*],
    ),
    [*`R0`*], [Program exit value or helper result.], [Assign a result on every reachable exit path; interpret it by program type.],
    [*`R1`*], [Program context at entry; first helper argument at a call.], [Use only through the context API or a locally proved access. Do not invent offsets or retain a stale proof.],
    [*`R2`–`R5`*], [Remaining helper arguments.], [They are caller-saved. Reconstruct values needed after a helper rather than reading them as though they survived.],
    [*`R6`–`R9`*], [Callee-saved registers.], [These are the ABI place to preserve a verifier-recognised value across a call; let the compiler manage them in Rust.],
    [*`R10`*], [Read-only stack frame pointer.], [Use bounded, initialized stack storage below it; never treat it as general writable memory.],
  ),
  caption: [Register roles in the eBPF calling convention.],
) <tbl-register-contract>

#kernel-detail(title: [Registers have types, not only bits], [The verifier follows the origin of a value. It distinguishes, for example, a scalar, a context pointer, a map-value pointer, a nullable map-value pointer, and a stack pointer. A successful bounds check may refine a pointer’s permitted range on one branch but not another. Consequently, converting a pointer to an integer, adding an unproved variable offset, or using a map lookup without first taking its non-null branch destroys the proof the program needs.])

The consequence for Rust is concrete. Aya source normally names ordinary variables, not `R6` or `R10`, but the compiled object still obeys #table-ref(<tbl-register-contract>, title: [register roles]). A helper call can invalidate the usable state of caller-saved registers; a packet-modifying helper can also invalidate earlier packet-range proofs. Avoid code that depends on a raw kernel-derived pointer remaining usable across a call. Keep a check and the access it justifies adjacent in the source. The verifier performs abstract interpretation over reachable control flow, tracking ranges, pointer bases and offsets, alignment, stack initialization, and selected resource lifetimes #cite(<bpf-verifier>). Simplicity is consequently a portability technique, not merely a style preference.

== Program type, context, and return value <sec-program-contract>

A program type is the kernel execution contract. It determines the initial context, the helper allowlist, which maps or operations may be used, attachment mechanics, and the meaning of the exit value. An attachment name alone does not supply these facts. The same eBPF arithmetic is not automatically valid in a tracepoint, XDP, control group (cgroup), or Linux Security Module (LSM) program.

| Family | Typical context and purpose | Return value is a… |
| --- | --- | --- |
| Tracepoint observation | A record for a named static trace event; appropriate for narrow telemetry. | Completion value; the counter returns `0` after bookkeeping, not an allow/deny policy decision. |
| XDP packet processing | Packet data and end pointers near network receive processing. | Packet action, such as pass, redirect, or drop; malformed or unknown input should have a deliberately safe action. |
| Cgroup socket policy | A socket-operation context scoped by cgroup attachment. | Program-specific continuation, permission, or verdict value. |
| LSM policy | A security-hook context, available only with additional kernel and policy prerequisites. | Security decision, commonly a permit/errno-style outcome for the specific hook; this is not interchangeable with an XDP or tracepoint return. |

The `02-syscall-counter` sample uses a tracepoint program. The runner requests the `syscalls/sys_enter_openat` hook, and the eBPF function accepts a `TracePointContext` but deliberately does not read it. That is a useful first design: because no tracepoint fields are decoded, no locally guessed field offset or record layout becomes part of the program. It counts entries into `openat`; it does *not* establish that the file open later succeeded, nor does it observe `openat2` or every other file-opening interface. A later chapter can introduce entry/exit correlation and target-local event-format validation. Static tracepoints are discoverable in tracefs, but they are not a blanket stable ABI promise #cite(<bpf-design-q-and-a>).

This distinction prevents a dangerous habit: writing `return 0` because it compiled elsewhere. In this counter, returning zero is simply the handler’s normal completion after recording an observation. In a policy type, an identical integer can make a security decision. Read the program type and attach contract before choosing an exit constant, and place that constant beside the source that uses it.

== Helpers: checked capabilities at the call boundary <sec-helper-contracts>

A BPF helper is a verifier-described kernel entry point. An eBPF program cannot call arbitrary kernel functions merely because it is running in kernel context. The verifier checks the helper’s argument categories and, on return, assigns `R0` the helper’s declared result category. Helper availability is program-type-specific, can depend on kernel configuration or licensing, and must be tested on the intended target rather than inferred from a header or a different program #cite(<bpf-verifier>).

Think of each helper call as a narrow capability with a signature and a failure model. A current-task identity helper yields the current thread-group identifier (TGID) and thread identifier in one packed result. A map lookup yields either a pointer to a value or null. A map update normally reports success or a negative error. A ring-buffer reservation yields either storage that must be submitted or discarded, or no storage. Each form requires a different local proof and a different data-quality decision.

The counter relies on `bpf_get_current_pid_tgid` and a mutable map lookup. In the selected function, the high 32 bits are used as the key. Linux calls this high-half value a TGID: it groups threads in one process. The source calls the local variable `pid` and the runner prints `pid=...`; read that output as a *process-level TGID label*, not as the individual thread identifier (TID). This terminology correction matters when a multithreaded application enters `openat` from several threads.

A returned map pointer is nullable even when a design expects an entry. The source first attempts to obtain a mutable slot, increments it only inside the successful branch, and otherwise attempts insertion. This is the shape the verifier needs: lookup, branch, then dereference. However, the insertion result is assigned to `_` and is therefore not reported. A full or otherwise failed `PerCpuHashMap` insertion can silently leave a new TGID uncounted. The sample is a bounded observer, not a complete accounting system.

#verifier-note(title: [The proof behind a small increment], [At a successful lookup, the verifier knows the returned pointer refers to the value type of `COUNTERS`; in the other branch, it knows there is no dereference. The value update is local to the current CPU slot. The function sets `R0` to zero on its only exit. The remaining unresolved operational case is insertion failure, which is safe for kernel memory but visible as missing telemetry unless a future version exports a failure counter.])

== Maps are contracts for shared state <sec-map-taxonomy>

A BPF map is a kernel-resident object with a type-specific data contract. eBPF accesses it via permitted helpers; user space accesses it through the BPF system call and a library wrapper. Its key size, value size, maximum entry count, flags, concurrency behavior, ownership, and lifecycle are as important as its Rust type. Map references can outlive a particular file descriptor while programs, attachments, or pins retain them; do not call an object temporary merely because a loader process exits #cite(<bpf-map>).

Choose the data semantics first. The following compact taxonomy names the usual starting choices; support and flags remain target-dependent.

| Need | Map family | Contract to state explicitly |
| --- | --- | --- |
| Fixed configuration or indexed counters | `ARRAY`; `PERCPU_ARRAY` for per-CPU values | Index range, fixed capacity, and whether concurrent shared updates require synchronization. Arrays do not delete entries. |
| Dynamic keyed state | `HASH`; `PERCPU_HASH`; optionally least-recently-used (LRU) variants | Key identity, maximum entries, failure behavior, and whether eviction deliberately loses history. |
| Aggregate counters | Per-CPU array or hash | Each CPU updates its own value; user space sums possible-CPU values. Define the resulting read as a collection-time snapshot, not a globally atomic instant. |
| Prefix-based lookup | Longest-prefix-match (LPM) trie | Prefix width, byte order, allocation flag, and update authority. |
| Bounded work queue | `QUEUE` or `STACK` | First-in-first-out (FIFO) or last-in-first-out (LIFO) behavior and the explicit full/overwrite policy. |
| eBPF-to-user-space events | `RINGBUF` or `PERF_EVENT_ARRAY` | Record schema, capacity, producer failure, consumer loss, wakeup/drain policy, and overload behavior. |
| Dispatch or redirection | Program, device, CPU, socket, or map-of-maps families | Referenced object lifecycle, compatible inner-map shape, fall-through behavior, and rollback. |

Arrays are often the clearest configuration choice because their range is known, whereas hashes express keyed presence and absence. A normal hash update can race with another update; a per-CPU map trades one shared value for one value per possible CPU. That is why a per-CPU counter is attractive for frequent increments: it avoids a cross-CPU atomic update in the hot path, while moving aggregation to user space. It does not make multi-step algorithms transactional, and the sum can change while it is read. The kernel map documentation describes arrays, hashes, per-CPU variants, and map lifetime as distinct contracts rather than interchangeable containers #cite(<bpf-map>).

A ring buffer deserves separate caution. It is a bounded event transport, not an unbounded log. Producers do not wait for space; a failed output or reservation is loss that the design should count. A successful reservation must reach exactly one submit or discard operation on every reachable path. Its shared ordering is reservation order, not a universal proof of causal or wall-clock order #cite(<bpf-ringbuf>). The `02-syscall-counter` object contains an `EVENTS` ring-buffer map because this repository compiles several examples in one eBPF crate, but the selected `syscall_counter` function neither reserves nor emits ring-buffer records. Its result comes from `COUNTERS`, not from event streaming.

== Case study: `02-syscall-counter` <sec-counter>

The selected sample has a deliberately narrow path: attach one tracepoint, determine the current TGID, increment a bounded per-CPU hash value, wait for a fixed interval, sum per-CPU values in user space, and print one line per observed key. Its sample metadata maps `02-syscall-counter` to the `syscall_counter` program. It has no pathname extraction, no tracepoint-context decoding, no map pinning, and no policy decision. The generic command-line flag `--enforce` exists in the shared runner but this selected tracepoint branch does not consult it or configure policy; this counter has no denial path.

#code-listing(
  [Map declarations in the canonical eBPF object],
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(20, 27).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs (lines 21–27)",
) <lst-counter-map>

The selected map in #listing-ref(<lst-counter-map>, title: [counter map declaration]) has `u32` keys, `u64` values, a per-CPU value layout, `16,384` maximum keys, and zero flags. The other declared maps serve other sample programs in the same object; their existence does not mean this tracepoint uses them. A new TGID consumes a key. Once the map cannot create a key, this source ignores the failed `insert`, so absence from output can mean no observed entry *or* an unreported capacity/update failure.

#code-listing(
  [Canonical increment and tracepoint handler],
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(63, 84).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs (lines 64–84)",
) <lst-counter-handler>

The handler in #listing-ref(<lst-counter-handler>, title: [increment and handler]) accepts `_ctx`, making its intentional non-use explicit. It derives the key from the upper half of `bpf_get_current_pid_tgid`, calls `increment`, then returns zero. The `get_ptr_mut` result is checked before dereference. Conversely, `let _ = map.insert(...)` makes failed first insertion a known limitation of the current source, not an outcome readers should infer away.

#code-listing(
  [Canonical runner dispatch for the counter],
  read("../../../samples/runner/src/main.rs").split("\n").slice(240, 265).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs (lines 241–265)",
) <lst-counter-runner>

The runner path in #listing-ref(<lst-counter-runner>, title: [attachment dispatch]) performs its own effective-user-identifier (EUID) gate before loading the object, loads the `syscall_counter` program as a tracepoint, and attaches it to `syscalls/sys_enter_openat`. Its later result collection converts `COUNTERS` to Aya’s user-space `PerCpuHashMap`, iterates keys, sums the returned CPU values, and prints them. The runner caps its observation interval at 60 seconds and does not create BPF filesystem (`bpffs`) pins.

== Expected output and interpretation <ch04-sec-expected-output>

#expected-output(title: [What a successful conditional run looks like], [After the interval, a compatible attached run prints zero or more lines in the form `pid=<TGID> count=<positive integer>`. A process that executes `openat` while the handler is attached should normally yield a line; a quiet interval can yield no relevant new key. The number is not necessarily the number of application-level files a person intended to open. Dynamic linking, configuration reads, and other activity by the same process can also enter `openat`; failed `openat` attempts are still entry events; and a new key can be absent when insertion fails. Output order is map-iteration order, not time order.])

Do not use a quiet display as evidence that eBPF “ran but saw nothing.” It can also mean that tracefs did not expose the event, the loader lacked authority, the object failed verification or attachment, the triggering process made a different syscall, or the interval did not include a trigger. Treat an expected line only as the final observation in a chain of evidence: preflight, feature presence, successful load/attach, deliberate trigger, and bounded collection.

== A safe, reproducible audit procedure <ch04-sec-procedure>

Use a disposable VM that you can revert. This sample is audit-only, but it observes host-wide `openat` activity during its brief attachment, so do not run it casually on a production host. Build as an ordinary user; do not make Cargo or build scripts privileged. The repository pins Aya 0.14.0, `aya-ebpf` 0.2.1, and a dedicated toolchain workflow, while `build-ebpf` requires `bpf-linker`. These are environment gates, not facts established by the source alone #cite(<aya-book>).

#terminal-listing(
  title: [Build, preflight, and tracepoint check as an ordinary user],
  "cd /path/to/learn-ebpf-on-linux/samples\ncargo xtask check\ncargo xtask build-ebpf\ncargo build -p sample-runner\ncargo run -p sample-runner -- lab-check\ntest -r /sys/kernel/tracing/events/syscalls/sys_enter_openat/id \\n  || test -r /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id",
)

The `lab-check` command is read-only and reports the runner’s observed Linux, BPF Type Format (BTF), cgroup version 2, bpffs, tracefs, and EUID indicators. For this counter, BTF is not a required data-access mechanism: the program is an ordinary tracepoint handler and does not decode BTF-described kernel structures. Nevertheless, tracefs visibility, the named event, BPF authority, resource accounting, the built object, and verifier acceptance are all required for a runtime result. Feature-probe the target instead of release-gating it. A BPF Type Format/Compile Once – Run Everywhere (BTF/CO-RE) strategy can relocate eligible structure accesses, but it cannot create an absent hook, map type, permission, or configuration #cite(<libbpf-core>).

In one terminal, run only the already-built loader, with a short duration. The checked runner implementation currently rejects a nonzero EUID even where narrower Linux capabilities could theoretically be sufficient. This is a runner limitation, not a universal claim that every tracepoint loader needs UID 0. Modern Linux separates BPF and performance-monitoring authority into `CAP_BPF` and `CAP_PERFMON`, but actual authority remains operation- and policy-dependent #cite(<capabilities>).

#terminal-listing(
  title: [Attach the already-built audit-only loader in the disposable VM],
  "cd /path/to/learn-ebpf-on-linux/samples\nsudo ./target/debug/sample-runner run 02-syscall-counter --duration 10",
)

While that fixed interval is active, use a second terminal to create a small, benign trigger:

#terminal-listing(
  title: [Generate a bounded `openat` trigger],
  "python3 -c 'for _ in range(5): open(\"/etc/hosts\").close()'",
)

Do not expect the reported count to equal five. Python startup and library activity can enter `openat` under the same TGID, and the counter observes entries rather than successful opens. On return, let the runner exit normally. It holds the attachment and map handles in process scope; dropping them releases this sample’s unpinned resources. No bpffs path is created by this code, so this procedure has no pin to remove. If attachment did not complete, do not compensate by weakening global kernel settings or granting broad `CAP_SYS_ADMIN`; record the error, inspect the target’s event and policy state, and revert the disposable VM if the experiment is uncertain.

#security-note(title: [Audit is the only mode of this chapter], [The counter records a bounded statistic and always returns after bookkeeping. It has no enforcement branch, even if the shared CLI accepts `--enforce`. Do not adapt it into a denial mechanism. In later enforcement-capable material, denial must be an explicit opt-in, restricted to a dedicated disposable cgroup in a recovery-capable VM, and preceded by an audit-only validation period.])

== Verifier reasoning and portability boundaries <sec-verifier-portability>

The verifier does not prove the application question “did this user successfully open that file?” It proves that the loaded instruction graph is safe under its selected program contract: every reachable register and stack read has a valid state; context and map pointers have acceptable provenance, bounds, and alignment; helper arguments match their contracts; and tracked resources are balanced #cite(<bpf-verifier>). In this example, the short control flow makes the proof legible: compute scalar key, branch on nullable map pointer, mutate only in the non-null branch, otherwise attempt insertion, and return.

Verification is necessary but insufficient for useful telemetry. The current source’s ignored insertion result leaves an intentional quality gap. Per-CPU aggregation removes cross-CPU atomic contention from this increment, but it does not provide a globally instantaneous count. Map capacity is finite. The tracepoint is target-specific. The runner’s EUID check is stricter than the kernel capability model it describes. Finally, an accepted program does not guarantee the expected hook was exercised. Preserve verifier logs and attach results as diagnostics for a named kernel, architecture, policy context, object hash, and loader identity; do not treat a successful run on one workstation as a fleet compatibility statement.

#portability-note(title: [Probe, then claim], [Before relying on a variation, verify the booted kernel and architecture, readable tracefs event, helper/program/map support, attached program result, authority under the real service identity, CPU topology, and map/resource limits. `bpftool feature probe` can assist host inspection, but a feature list is not a successful load/attach test. Keep a BTF-free or no-feature fallback for a feature that is optional; this counter’s no-context-decode design is deliberately such a low-dependency tier.])

== Exercises <ch04-sec-exercises>

#exercise(title: [Read the counter as a contract], [First, identify the key and value types, maximum entry count, update path, and output aggregation path in the canonical listings. Then explain why the line prefix is better read as TGID than as per-thread PID. Finally, trigger the counter from two different processes and compare the number of keys with the number of processes you deliberately started. Do not infer a fixed count per trigger.])

#exercise(title: [Design before changing code], [Propose a revised map contract that reports failed first insertion without blocking the eBPF program. State its map type, key, value, maximum entries, synchronization/aggregation rule, and how user space would display the health metric. Separately, specify what extra event and state would be required to count only successful `openat` calls; this requires entry/exit correlation and target-local tracepoint validation, not merely a different return value.])

== Chapter summary <ch04-sec-summary>

The eBPF ISA is a small, typed register machine whose calling convention matters even when Rust hides register names. `R1` begins as a program-type-specific context, `R0` carries the result, `R1`–`R5` are caller-saved helper-call registers, `R6`–`R9` survive calls, and `R10` anchors the bounded stack. Program type selects context, helpers, attachment behavior, and return semantics, so it must precede syntax in the design.

Helpers and maps are contracts, not generic library calls and collections. A helper’s return category directs the verifier proof; a map’s type directs capacity, sharing, eviction, and consistency semantics. `02-syscall-counter` demonstrates a narrow tracepoint observer: it counts `sys_enter_openat` entries per TGID in a bounded per-CPU hash map and sums CPU values in user space. It does not decode a pathname, prove success, count all opening APIs, report insertion failure, pin state, or enforce a policy. That clarity is a feature.

== Next steps <ch04-sec-next-steps>

Proceed to #chapter-ref(<ch-05>, title: [The verifier as a proof obligation]). There, the register-and-map reasoning introduced here becomes explicit path analysis: initialized stack bytes, nullable pointers, bounds, alignment, helper clobbers, and the verifier log as target-specific diagnostic evidence.
