#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, kernel-detail, portability-note, security-note, verifier-note, exercise
#import "../../components/code.typ": code-listing, terminal-listing

#let sample-listing(path, title, lines, language: "text") = {
  let source = read(path)
  let all = source.split("\n")
  let selected = all.slice(lines.first() - 1, lines.last()).join("\n")
  code-listing(title, selected, language: language, source-path: path)
}
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "I", chapter: "3")

= The First Event <ch-03>

An extended Berkeley Packet Filter (eBPF) program is useful only when a kernel event can invoke it under a precise contract. This chapter builds that mental model before adding payload decoding, object persistence, or policy decisions. The first checked-in design is deliberately small: attach to `sched/sched_switch`, ignore the event record, increment one per-central-processing-unit (per-CPU) `u64` counter, read its CPU-local values in user space, and exit. Its result is an observation over a short interval—not a global scheduler truth, not a log, and not a policy mechanism.

The primary sample, `01-tracepoint-hello`, implements exactly that boundary. It has its own small eBPF binary, so later ring-buffer and layout-dependent programs cannot leak into the beginner object. Keeping the source object, selected program type, hook, loader, and target kernel visibly aligned is a core eBPF discipline.

== Prerequisites <sec-ch03-prerequisites>

You should have completed the laboratory preflight from the preceding chapter and be working in a disposable virtual machine (VM) or another explicitly approved non-production environment. You need a Linux kernel with a readable tracefs event interface, the repository's pinned Rust and Aya build prerequisites, and authority that the *running* kernel accepts for loading and attaching the selected tracepoint program. The primary sample's runner also has its own conservative effective-user-ID (EUID) zero gate; that implementation gate is stricter than a general statement that only root can use eBPF.

Before the counter can be attempted, confirm that `/sys/kernel/tracing/events/sched/sched_switch/format` is readable. A BPF Type Format (BTF) file can be useful for later type-aware work, but it is not part of this data path because the program reads neither kernel structures nor tracepoint payload bytes. Do not mount filesystems, relax global security sysctls, grant broad capabilities, or add persistent pins merely to satisfy this chapter.

== Learning objectives <sec-ch03-objectives>

After working through this chapter, you should be able to:

- distinguish a program type, an attachment type, and a named hook, and explain why syntax alone does not determine an eBPF program's privileges or return contract;
- trace the path from a compiled Executable and Linkable Format (ELF) object through Aya loading, kernel verification, attachment, invocation, map access, and teardown;
- state why a one-entry per-CPU array is appropriate for a short scheduler-switch count and why its userspace sum is only a snapshot;
- inspect the actual `01-tracepoint-hello` object and show that it contains the `sched_switch` counter but no event transport;
- run the existing audit-only sample in a bounded, reproducible way, interpret its conditional output, and leave no intentionally pinned eBPF object behind; and
- treat verifier acceptance and successful attachment as target-specific evidence, not as a claim that an observation is complete, portable, or semantically correct.

== Begin with the execution contract <sec-ch03-contract>

A *program type* is the kernel-defined execution contract for an eBPF program. It determines the initial context, which helper functions are eligible, how a program is attached, and—where the hook uses a decision—what its return value means. An *attachment type* refines that contract for some families. A *hook* is the particular place at which the program may execute, such as a static scheduler tracepoint, a packet ingress point, or a Linux Security Module (LSM) operation. Treating all three as merely “an eBPF hook” hides exactly the constraints that make an object safe to load. The kernel verifier analyzes an object under this contract, not under the programmer's intention. #cite(<bpf-design-q-and-a>)

#concept(title: [An event is an invocation, not automatically a record], [
  At a tracepoint, an event means that the kernel invokes the attached program with a tracepoint context. Nothing crosses into user space unless the program deliberately updates a map or submits a bounded record through a transport. The counter design chooses a map update. It is therefore payload-free: it does not mean that the tracepoint lacks a payload; it means the program does not read one.
])

#figure(
  table(
    columns: (1.12fr, 1.32fr, 1.85fr, 1.82fr),
    inset: 5pt,
    align: left,
    table.header(
      [*Program family*], [*Typical context*], [*Return contract*], [*First-use implication*],
    ),
    [Tracepoint], [Tracepoint event context], [Return zero in this lesson; tracing observes rather than makes an access decision.], [A named static event is discoverable in tracefs. Do not decode bytes until the target format is inspected.],
    [eXpress Data Path (XDP)], [Packet data and packet end], [An XDP action such as pass or drop.], [A return value can change network treatment; a packet parser needs separate bounds and alignment reasoning.],
    [Control group (cgroup) socket-address], [Socket-address context], [A hook-specific allow/deny-style result.], [Scope is a cgroup-v2 attachment, not a human-readable container identity.],
    [BPF LSM], [An LSM hook context], [For ordinary integer hooks, zero permits and a negative errno denies.], [This is late-stage, privileged policy work: audit is the default; denial is explicit opt-in only in a disposable cgroup and VM.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Program type comes before source syntax: contexts and return values are not interchangeable.],
) <tab-program-contracts>

The tracepoint row of #table-ref(<tab-program-contracts>, title: [program contracts]) is the least invasive fit for the first observation. A static tracepoint is intentionally placed in kernel code and exported through tracefs, usually under `/sys/kernel/tracing/events/<category>/<event>/`. Its `id` identifies the event for attachment; its `format` describes the active record layout. This discoverability is valuable, but it is not a blanket stable application binary interface (ABI) promise. Event presence, fields, offsets, sizes, and meaning must be checked on each target when a program reads the context. #cite(<bpf-design-q-and-a>)

For `sched/sched_switch`, the counter uses the hook only as a clock tick for a map update. There is no reason to know the previous or next task name, process identifier, priority, or state. Ignoring those bytes removes an entire class of layout and alignment assertions from the first program. It also prevents an attractive but false conclusion: a count of tracepoint invocations is not, by itself, a latency metric, a utilization measurement, or a task attribution record.

== From Rust object to a running program <sec-ch03-lifecycle>

The lifecycle in #figure-ref(<fig-loader-lifecycle>, title: [loader lifecycle]) has two boundaries. Compilation produces a BPF-target ELF object; user space then asks the running kernel to create the object graph and attach the accepted program. The loader is ordinary Rust and can report errors, choose a bounded duration, and own file descriptors. The eBPF crate is constrained code that executes only when the hook fires. Neither side substitutes for the other.

#figure(
  image("../../assets/diagrams/generated/03-loader-lifecycle.svg", width: 100%),
  caption: [Loader lifecycle: compilation creates an ELF object; Aya coordinates load and attachment; the kernel verifier decides whether the selected program may run. The “BPF link” box expresses a general lifetime model—an individual Aya tracepoint attachment can use a program-type-specific perf-event attachment path rather than this generic object.],
) <fig-loader-lifecycle>

The sequence is worth naming precisely.

1. *Compile.* The eBPF crate, normally built with `#![no_std]`, becomes an ELF object containing program sections, map definitions, instructions, and possibly BTF or relocation metadata. The loader is compiled separately for the host.
2. *Open and create.* Aya's `Ebpf::load_file` reads the object. The kernel creates the declared maps and begins program loading. A map is a kernel object accessed by both eBPF and user space through controlled interfaces, rather than shared arbitrary memory. #cite(<bpf-map>)
3. *Verify and load.* The kernel's program-load operation explores reachable instructions and rejects paths with unsafe state. An accepted program has a kernel-managed file descriptor (FD); rejection is a design diagnosis, not a condition to bypass. #cite(<bpf-verifier>)
4. *Attach.* Aya obtains a typed program handle, loads it, and binds it to a permitted category and event. Only then can the event invoke the program. A loaded-but-unattached program does not count future scheduler switches.
5. *Observe.* Each invocation performs the permitted map update or transport operation. User space reads a map or drains a transport during the bounded observation window.
6. *Detach and release.* Detachment removes the invocation path. Closing the final relevant FDs and other references allows the kernel objects to be released. A bpffs pin, an attachment, or another reference changes this conclusion; the first counter intentionally creates no pin.

#kernel-detail(title: [Tracefs is part of the operational contract], [
  A loader cannot attach to a tracepoint solely because a source file names it. Inspect the event directory and retain the target's `format` output before introducing a context read. Aya may locate tracefs and resolve the event on the reader's behalf, but a missing or inaccessible event is still a real deployment failure. The first counter's refusal to decode context is a reduction in assumptions, not an excuse to skip preflight.
])

Notice the loop in the figure: telemetry returns to the loader, while cleanup closes the resources that made execution possible. That loop is also a boundary of responsibility. A loader that attaches successfully but then loses track of its attachment is not a finished laboratory program. Likewise, a program that emits records without a consumer has not automatically created an audit trail.

== The payload-free per-CPU counter <sec-ch03-counter-design>

The counter has one map entry, key `0`, with a separate unsigned 64-bit integer (`u64`) value for every online CPU. On each `sched/sched_switch` invocation, the eBPF program looks up the current CPU's value and increments it with wrapping arithmetic. It returns zero. After a short interval, user space retrieves the per-CPU values for key `0`, sums them, prints the aggregate, and exits.

A per-CPU map is not a magic global counter. It is a layout choice that allows the CPU executing the tracepoint program to update its own value rather than contend on one shared scalar. User space combines the values later. Events may occur while it reads the values, CPUs may come online or offline, and a `u64` eventually wraps. Thus the printed number is a non-transactional snapshot of invocations observed while attached. The map documentation should be consulted for the exact map and userspace API behavior supported by the chosen kernel and library version. #cite(<bpf-map>)

This small design has unusually good teaching properties:

- *No payload contract.* The tracepoint context is named but unused. There is no `read_at`, no copied offset, and no assumption about task fields.
- *No per-event transport.* A busy scheduler can generate many switches. Incrementing a scalar map value has a bounded data path; submitting an event for every switch would immediately require a capacity, loss, consumer-lag, and schema contract.
- *No shared counter race in the fast path.* Each CPU increments its own slot. The readers' sum is explicitly approximate rather than pretending to be an atomic global transaction.
- *No deliberate persistence.* There is no BPF filesystem (bpffs) path, pin operation, background service, or automatic restart. The experiment's owner is the foreground loader.

The scope is intentionally narrow: it counts invocations of one selected scheduler event, not “all scheduler activity.” It must not be used to make admission, denial, or enforcement decisions. Any future enforcement chapter should remain audit-first, and a denial mode must be explicit, scoped to a disposable cgroup and VM, and independently tested for rollback.

=== Repository truth: a dedicated minimal object <sec-ch03-current-sample>

`01-tracepoint-hello` is intentionally compiled from a separate binary. #listing-ref(<lst-current-hello-producer>, title: [the canonical producer]) declares only a one-entry `PerCpuArray<u64>` and the tracepoint program. The context argument is unused. There is no `EVENTS` map, `DROPPED` map, ring buffer, task-memory read, or target-BTF dependency in this object.

#sample-listing(
  "../../../samples/ebpf-programs/src/bin/tracepoint-hello.rs",
  [Canonical payload-free `sched_switch` counter],
  (1, 20),
  language: "rust",
) <lst-current-hello-producer>

The unsafe block is narrow but still deserves an invariant: the pointer comes from a successful per-CPU array lookup for in-range key `0`, points to the current CPU's aligned `u64` value, and is used only for the immediate read-modify-write. Rust syntax does not replace the verifier's proof of that access.

The runner's typed tracepoint helper is the canonical lifecycle fragment. It obtains a mutable program by name, converts it to Aya's `TracePoint` type, loads it, and attaches it to a supplied category and event. These names and methods belong to the pinned Aya dependency set in this repository; do not replace them with a floating tutorial API. #cite(<aya-book>)

#sample-listing(
  "../../../samples/runner/src/main.rs",
  [Current Aya tracepoint load and attach helper],
  (297, 311),
  language: "rust",
) <lst-aya-tracepoint-attach>

The primary branch passes `"tracepoint_hello"`, `"sched"`, and `"sched_switch"` to that helper. It is worth inspecting because it demonstrates a general rule: the Rust program name, program type, category, and event are independent values that must be coherent at runtime. The runner also selects `target/ebpf/tracepoint-hello` for this sample rather than the larger shared object.

#sample-listing(
  "../../../samples/runner/src/main.rs",
  [Current primary-sample selection in the runner],
  (556, 559),
  language: "rust",
) <lst-current-sample-selection>

== Why the verifier can accept the small design <sec-ch03-verifier>

The verifier does not understand that a program is “just a counter.” It follows reachable paths and tracks register types, pointer provenance, ranges, alignment, initialized stack bytes, helper arguments, nullable results, and resource lifetimes. A successful load establishes that the target verifier accepted this bytecode under this program type; it does not prove that a number answers the intended operational question. #cite(<bpf-verifier>)

For the checked-in counter, the proof obligations are unusually local.

1. The map has exactly one entry, and the literal key is `0`, so the lookup key is in range.
2. A map lookup may be nullable from the verifier's point of view. The program branches on `Some(counter)` before dereferencing the pointer; the absent case returns success without writing.
3. The successful pointer designates the current CPU's `u64` map value. The program uses it only for the immediate aligned scalar read and write, retains no pointer after return, and does not turn it into a Rust reference with a longer claimed lifetime.
4. The arithmetic is explicit wrapping addition, so an overflow does not introduce a panic path. The program has a simple return on every branch.
5. No tracepoint bytes are read, no large stack buffer is built, no user pointer is followed, and no ring reservation needs a submit-or-discard proof.

#verifier-note(title: [A short source program still has a proof], [
  “Per-CPU” addresses contention, not nullability. The lookup can fail in the verifier model, so a correct first counter still branches before dereference. Conversely, a verifier-approved context read could still be semantically wrong if its offset came from another kernel. Avoiding that read is stronger than merely hoping a familiar offset remains valid.
])

Object inspection provides a useful negative test: the dedicated object should expose `tracepoint_hello` and `SCHED_SWITCHES`, but no `EVENTS`, `DROPPED`, or ring-buffer map. That test does not prove runtime acceptance, yet it prevents a packaging mistake from silently expanding the first program's data path.

== Safe, reproducible procedure <sec-ch03-procedure>

Run this procedure only in the disposable environment named in your lab record. Build as an ordinary user; execute only the reviewed loader binary with the authority your target requires.

#terminal-listing([
```bash
cd /home/ubuntu/learn-ebpf-on-linux/samples

# Record target facts; do not infer them from the build host.
uname -r
findmnt -T /sys/kernel/tracing

test -r /sys/kernel/tracing/events/sched/sched_switch/id
sed -n '1,160p' /sys/kernel/tracing/events/sched/sched_switch/format

# Build before elevation. This workspace requires its pinned toolchain and bpf-linker.
cargo xtask check
cargo xtask build-ebpf
cargo build -p sample-runner

# In the disposable VM only: the checked-in runner requires EUID 0.
sudo ./target/debug/sample-runner run 01-tracepoint-hello --duration 10
```
], title: [Preflight, ordinary-user build, and bounded primary-sample run]) <lst-current-sample-procedure>

Normal VM activity produces scheduler switches during the bounded interval; no workload generator is required. The runner limits the requested duration to 60 seconds. Inspecting the format does not license copying offsets from it: this counter uses only event presence. A later program that reads `prev_pid` or `next_pid` must preserve target-local format evidence and prove width, offset, and alignment.

#security-note(title: [Privilege is an environment gate, not a setup puzzle], [
  Modern Linux capability checks can distinguish BPF and performance-monitoring authority, while kernels, user namespaces, Linux security policy, and perf policy can add constraints. The repository runner nevertheless rejects a nonzero EUID before it reaches Aya. Treat that as a documented runner limitation. If the run fails, retain the error, kernel release, architecture, event path, and service identity; do not disable `unprivileged_bpf_disabled`, lower `perf_event_paranoid`, grant blanket `CAP_SYS_ADMIN`, or attach capabilities to Cargo or a shell just to force a lab through. Linux capabilities are deliberately finer-grained than the historical all-powerful root model. #cite(<capabilities>)
])

== Expected output and its limits <sec-ch03-expected-output>

#expected-output(title: [What the checked-in sample can show], [
  On a target where verification and attachment succeed, the runner prints the selected local tracepoint format, an attachment-status line, and finally `sched_switch_count=<n>`. The value is environment-specific and normally nonzero on an active VM, so this chapter does not manufacture an exact count.
])

The status line alone proves neither that every switch was counted nor that the later sum is transactional. A failure before the count may be a missing event, inaccessible tracefs, an unavailable BPF facility, rejected bytecode, insufficient authority, a resource limit, or an Aya/object-path error. Preserve the complete diagnostic rather than reducing it to “eBPF unsupported.”

== Portability and measurement caveats <sec-ch03-portability>

The initial counter removes several dependencies but not all of them. `sched/sched_switch` must exist and be reachable through tracefs on the booted kernel. A kernel configuration, container boundary, mount namespace, security module, or policy may prevent access even when the source compiles. The runtime result is therefore environment-gated: it is evidence for one kernel, architecture, configuration, privilege context, and object build—not a fleet-wide compatibility claim.

The counter does not need to decode the tracepoint record, which avoids a BTF or Compile Once—Run Everywhere (CO-RE) dependency for its fast path. That does not make tracepoints a stable ABI. If the next revision reads fields, BTF can help describe eligible kernel types and CO-RE can relocate eligible accesses, but neither can create a missing event, helper, authority, or unchanged semantic meaning. #cite(<libbpf-core>)

Aya is also a versioned interface. This workspace pins `aya` 0.14.0, `aya-ebpf` 0.2.1, and `nightly-2026-07-15` with `rust-src`; user-space APIs are separately checked against stable Rust 1.98.1. Build the actual lockfile and object selected by the repository rather than translating examples from an unpinned release. The required `bpf-linker` and selected target toolchain are build gates; they cannot establish that the booted kernel will accept or attach an object.

Finally, interpret the count conservatively. A scheduler switch generated while the program is attached may update one CPU-local counter; the later aggregate can race with ongoing updates. It says nothing about why the switch happened, whether an application waited, or whether every CPU was equally busy. That modest statement is a virtue: a measurement whose boundaries are explicit is more useful than a larger telemetry stream with undefined loss and semantics.

== Detach, release, and cleanup <sec-ch03-cleanup>

Let the bounded run finish, or interrupt only the foreground experiment. The primary sample retains the `Ebpf` owner in the runner's scope and does not call a pin API. Its README documents that timeout or `Ctrl-C` ends the run and that dropping `Ebpf` detaches the link; even when a process is terminated, its file descriptors are closed by process exit and the attachment must not be treated as an intentional persistent service. Do not kill unrelated BPF programs, delete shared bpffs entries, or use a global cleanup command on a multi-user host.

The relevant cleanup check is negative and local: this sample has no configured bpffs path, and the procedure never creates one. Record that fact with the lab result. If an administrator supplied an existing bpffs mount, inspect only the project-owned location if one was explicitly created—which it was not for this chapter. A persistent object found elsewhere is evidence that another workload owns it, not an invitation to remove it.

The counter follows the same rule: own the `Ebpf` object for the fixed observation window, do not transfer attachment ownership, do not pin maps/programs/links, and return. If a later service genuinely needs persistence, it needs a named owner, schema, expiry/removal action, restart reconciliation, and rollback plan; it is not an extension of this first exercise.

== Exercises <sec-ch03-exercises>

#exercise(title: [Inspect before interpreting], [
  Capture the `id` and `format` for `sched/sched_switch`. Identify which file is necessary before decoding bytes and explain why the counter still does not need to read any field. Do not write an offset-based program yet.
])

#exercise(title: [Separate lifecycle from telemetry], [
  Trace the two canonical listings in #listing-ref(<lst-current-hello-producer>, title: [the producer]) and #listing-ref(<lst-aya-tracepoint-attach>, title: [the attach helper]). Mark where the map is declared, where the verifier is invoked by `load`, where attachment happens, and which scope owns teardown. Then explain why a successful `load` is insufficient to increment the counter.
])

#exercise(title: [Audit the counter without expanding its scope], [
  Write a one-paragraph contract for the checked-in `sched_switch` counter: map name, key, value type, failure branch, return value, fixed duration, aggregation semantics, and cleanup. Verify that tracepoint payload reads, ring-buffer output, pins, and enforcement are absent. Compare your contract with #listing-ref(<lst-current-sample-selection>, title: [the runner]).
])

#exercise(title: [Make a portability record], [
  In a disposable VM, record the kernel release, architecture, tracefs mount result, event existence, Aya/Rust lockfile revision, selected program name, loader identity, load/attach result, and cleanup result. Repeat on a second approved kernel only after rebuilding the same object. Treat differences as test results, not as reasons to weaken the host.
])

== Chapter summary <sec-ch03-summary>

A first eBPF event is an agreement among a program type, a hook, an object, a loader, a verifier, and a target environment. The payload-free `sched/sched_switch` per-CPU counter is the right conceptual first program because it limits that agreement to a static event, a one-entry map, a null-checked update, a snapshot sum, and explicit release. It teaches lifecycle while avoiding event-layout decoding, unbounded transport, and persistence.

The checked-in `01-tracepoint-hello` sample implements that design in a dedicated object, loads and attaches it with Aya, sleeps for a bounded interval, sums every CPU-local slot, prints `sched_switch_count`, and relies on owned-object lifetime for cleanup. The simplicity is deliberate: transport schemas, loss counters, task attribution, and policy decisions arrive only after the lifecycle is understood.

== Next steps <sec-ch03-next-steps>

The next chapter expands this compact model into the instruction set, program types, helper contracts, and map semantics needed for larger programs. Continue with #chapter-ref(<ch-04>, title: [Instructions, Program Types, Helpers, and Maps]) only after you can explain why the counter's map update is safe, why its aggregate is approximate, and why normal exit leaves no deliberately pinned object.
