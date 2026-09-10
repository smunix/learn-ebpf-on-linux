#import "../../components/callouts.typ": concept, exercise, expected-output, kernel-detail, portability-note, security-note, verifier-note
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, definition-target, figure-ref, listing-ref, section-ref, table-ref
#import "../../components/terms.typ": acronym
#import "../../report-theme.typ": chapter-opener

#let sample-listing(path, title, lines, source-path) = {
  let source = read(path).split("\n")
  let selected = source.slice(lines.first() - 1, lines.last()).fold(
    "",
    (acc, line) => acc + line + "\n",
  )
  code-listing(title, selected, language: "rust", source-path: source-path)
}

#chapter-opener(part: "III", chapter: "08")
= Scheduling and CPU Time <ch-08>

A program can be awake, eligible to execute, and still not be executing. That apparently simple gap is where Linux scheduling becomes visible to an observer. This chapter develops a disciplined way to look at that gap with tracepoints and #acronym("ebpf"). The result is a small latency measurement, but not a private view into the scheduler and not a claim about an application's total responsiveness.

== Prerequisites <sec-08-prerequisites>

This chapter assumes that you can distinguish an eBPF program from its user-space loader, can build the repository's Rust workspace in the pinned NixOS development environment, and have read the preceding material on tracepoints, maps, event transport, and loss. You should also be comfortable with a *central processing unit (CPU)*, a process identifier (*PID*), a thread identifier (*TID*), and the idea that a Linux task commonly represents one schedulable thread. The companion sample is `07-scheduler-latency`; it is an audit-only observer, and its attachment path belongs only in a disposable, authorized virtual machine (*VM*), never on a production host.

== Learning objectives <sec-08-objectives>

After completing this chapter, you should be able to:

- distinguish a task that is sleeping, runnable, and actually executing on a CPU;
- explain why run queues and selection policy are per-CPU implementation details rather than an eBPF data interface;
- define a *wakeup-to-observed-run latency* measurement using `sched_waking` and `sched_switch` without calling it end-to-end application latency;
- reason about an eBPF PID correlation map, including missed events, least-recently-used (*LRU*) eviction, PID reuse, and non-atomic snapshots;
- inspect a target's TraceFS (tracing filesystem) event formats before decoding fields; and
- recognize why the repository's current `07-scheduler-latency` source is an environment-gated teaching artifact rather than a validated portable metric.

== A useful mental model: eligible is not running <sec-08-mental-model>

A CPU executes one task at a time in the ordinary task context. A task that calls a blocking operation, waits for an event, or has no work to do becomes non-runnable. When the relevant event arrives, a wakeup path makes the task eligible to run. It may then be selected immediately, or it may wait while another eligible task continues. The scheduler eventually chooses a next task for a CPU and performs a context switch: it saves sufficient execution state for the old task and makes the selected task the current execution context.

It is tempting to collapse that story into “the wakeup put the task on the CPU.” Do not. Between the two observations are CPU placement, per-CPU runnable state, task class and priority, cache and affinity considerations, interrupts, and possible preemption. A task can be runnable without consuming CPU time. Conversely, the CPU that observes the wakeup need not be the CPU that later switches to the task. On a symmetric multiprocessing (*SMP*) machine, this distinction is essential rather than academic.

#definition-target("def-08-wakeup-observed-run", "Wakeup-to-observed-run latency")[The elapsed monotonic-kernel-clock time from an observed task wakeup event to a later `sched_switch` event that names the same task as the selected next task. It is a correlation metric with explicit loss and ambiguity limits; it is not total application latency.]

This definition deliberately chooses observations rather than undocumented scheduler internals. The kernel's run queues, locks, scheduling-class implementation, and the details of the Completely Fair Scheduler (*CFS*) or newer policy work are not a stable tracing contract. Kernel documentation specifically declines to treat tracepoints or their formats as a stable application binary interface (*ABI*). A static tracepoint is commonly a better starting point than a kprobe, but it remains locally discoverable target data that must be inspected before decoding. #cite(<bpf-design-q-and-a>)

The distinction gives us a practical question: “after the kernel reported that task *P* was being woken, how long until the observer saw *P* selected by a context-switch record?” That question is modest, reproducible, and useful for identifying a change in scheduling delay under a known workload. It cannot tell us why the scheduler made its decision, whether the task immediately performed user-space work, or how long a request waited before it caused the wakeup.

#concept(title: "Read events, not private queues")[A run queue is scheduler-owned, per-CPU state. Tracepoints supply observations at defined instrumentation sites; they do not grant a portable or lock-safe eBPF interface to the queue. Measure an event-to-event interval, retain the target's event-format evidence, and resist turning an implementation detail into an ABI.]

== Tasks, states, queues, and preemption <sec-08-task-states>

A task's state is a compact statement of what it may do next, not a complete timeline. The scheduler's familiar `TASK_RUNNING` state covers both a task currently executing and a task that is runnable but waiting for a CPU. Sleep states distinguish tasks waiting interruptibly or uninterruptibly for a condition; stopped, traced, and exiting states have further special meanings. Exact bit values, combinations, and what a particular trace record reports are target-kernel details. In particular, `sched_switch` exposes a previous-state value about the outgoing task; it should not be treated as a universal state machine for the incoming task.

A *run queue* is the scheduler's local accounting and candidate-selection structure for a CPU. “Per-CPU” means that there is logically distinct state for each CPU, even when the scheduler performs load balancing or migration between CPUs. This organization reduces a single global lock bottleneck, but it means an observer must not infer a global order from two CPUs' local activity. A wakeup can choose a CPU, enqueue a task, trigger a reschedule request, or be followed by migration. Which of these paths occurs depends on the booted kernel, configuration, topology, and workload.

*Preemption* is another reason runnable time is not execution time. A newly runnable task may outrank the current task and induce a reschedule; it may be deferred; the current task may block; an interrupt or a kernel preemption boundary may intervene. A task can also be selected only after several unrelated switches. Therefore, a large interval does not prove “the run queue was long,” and a small interval does not prove the application was responsive. It is an observed interval that requires workload-level correlation before diagnosis.

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (1.15fr, 1.45fr, 2.25fr),
    inset: 6pt,
    stroke: 0.4pt + rgb("#B8CDD2"),
    table.header(
      [*Concept*], [*What it means*], [*Safe eBPF interpretation*],
    ),
    [Sleeping / blocked], [The task is waiting for an event or condition and is not eligible for ordinary CPU selection.], [A wakeup tracepoint is evidence that the observer saw a wakeup-related transition, not evidence that the task already ran.],
    [Runnable], [The task is eligible to execute but may be queued or otherwise waiting for selection.], [Do not attempt to walk a private run queue. Retain a timestamp keyed by the observed task identity.],
    [Running], [The task is the execution context selected for a CPU.], [At `sched_switch`, correlate only when the event's locally validated *next* task field names the key.],
    [Preempted or rescheduled], [A runnable task may wait while another context executes or while a CPU processes other work.], [Treat the interval as a symptom to correlate with CPU placement, workload, and other telemetry—not as a causal explanation.],
  ),
  caption: [Scheduler concepts and the observation boundary.],
) <tab-08-scheduler-states>

#table-ref(<tab-08-scheduler-states>, title: "Scheduler concepts and the observation boundary") is intentionally phrased in terms of observations. An eBPF program that follows a `task_struct` pointer or guesses a run-queue layout would couple itself to private structures, locking rules, configuration-dependent fields, and kernel version details. The verifier can reject an unsafe memory access, but it does not turn an internal structure into a stable semantic interface. #cite(<bpf-verifier>)

== The two event facts we join <sec-08-event-join>

The conservative measurement needs two facts on the same target. `sched_waking` is the preferred start observation when it exists and its format is validated: it runs in waking context, so its timestamp is a clear definition of the start boundary. `sched_switch` supplies the end observation when its record identifies the *next* task that is selected. Store `t0` when the first event reports PID *P*; when the second event reports `next_pid == P`, compute `t1 - t0`, export or aggregate the result, and remove the key.

The current sample does *not* ship a decoder. An earlier draft paired `sched_wakeup` with `sched_switch` and used copied offsets; review found that the offsets were unproven and one commonly identified a different field. The programs were removed from the default object, and the runner now refuses sample 07. `sched_waking` and `sched_wakeup` also define different start boundaries, so a future implementation must choose one explicitly rather than treating their names as interchangeable.

The following timeline is a conceptual model, not a claim that every wakeup follows the same CPU path. Its direct arrow from run queue to switch represents immediate selection; its other route represents a runnable task that was not selected yet. The diagram also makes cleanup part of the measurement: a successful end correlation removes the timestamp rather than allowing stale state to contaminate a future PID reuse.

#figure(
  image("../../assets/diagrams/generated/08-scheduler-latency.svg", width: 100%),
  caption: [Conceptual timeline for a wakeup-to-observed-run measurement. The actual target's event fields and offsets must be checked in TraceFS before an eBPF program decodes them.],
) <fig-08-scheduler-timeline>

In #figure-ref(<fig-08-scheduler-timeline>, title: "the scheduler timeline"), `t0` and `t1` come from a monotonic kernel clock rather than wall-clock time. A monotonic duration avoids a wall-clock adjustment creating a negative apparent scheduling delay. Still, the timestamp is taken at trace instrumentation, not at an unknowable instant inside the scheduler. The word *observed* in the definition is a reminder of that placement.

A PID alone is a bounded, reusable identity. A task can exit, the kernel can reuse the numeric PID, a second wakeup can overwrite the first timestamp, or a task can be woken repeatedly before a matching switch. A robust production design decides whether the newest wakeup replaces the prior one, records an overwrite counter, uses a generation or additional identity where available, and expires old entries. This sample does none of those accounting refinements, so an absent or surprising result must never be read as proof that no latency occurred.

== The repository sample: a deliberate quarantine <sec-08-current-sample>

The repository keeps the sample directory and design discussion, but the default eBPF object contains no scheduler-field decoder. The runner's refusal is the canonical executable behavior:

#code-listing(
  [Canonical sample-07 quarantine in the runner],
  read("../../../samples/runner/src/main.rs").split("\n").slice(529, 534).join("\n"),
  language: "rust",
  source-path: "../../../samples/runner/src/main.rs",
) <lst-08-runner-quarantine>

This is a positive safety outcome. A future implementation needs archived exact `events/sched/<event>/format` fixtures, generated decoder constants, fixture tests, and health counters for insertion failure, overwrite, unmatched switch, eviction ambiguity, producer loss, parse rejection, and PID reuse. A shared bounded map can be appropriate because wakeup and switch may occur on different CPUs, but it remains a cache rather than an authoritative timeline. #cite(<bpf-map>)

#portability-note(title: "The local format is the decoder contract")[Before any layout-dependent attach, read and archive the `id` and `format` files for both selected events on the booted target. Generate and test constants from that evidence. Do not substitute an offset from this chapter, a blog post, or another architecture.]

== Loader lifecycle and environment-gated behavior <sec-08-loader-lifecycle>

The runner checks the sample name and returns the quarantine error *before* requiring root, opening an object, loading a program, or attaching a hook. Thus ordinary users can confirm the stop condition without changing kernel state. Other tracepoint samples illustrate Aya's load-then-attach lifecycle, but there is no sample-07 attachment path to exercise until the fixture gate is implemented. #cite(<aya-book>)

This is the correct scope: do not use a scheduler tracing exercise to influence task selection, priority, affinity, cgroups, or system-wide scheduling policy. Any policy experiment belongs to a separately designed feature in a disposable VM, never to this observation collector.

#security-note(title: "Do not turn a delay probe into a scheduler control")[This chapter loads no policy, changes no scheduling knob, and recommends no priority, affinity, memory-limit, or privilege-tuning workaround. A missing event, rejected object, or denied attach is an honest unavailable result. Do not weaken host protections or grant a general-purpose shell extra privilege merely to make the sample run.]

== Verifier reasoning: safety is not correctness <sec-08-verifier-reasoning>

There is no current scheduler bytecode for the verifier to accept. For a future decoder, the verifier must prove bounded context reads, nullable map handling, initialized event bytes, bounded control flow, and reservation lifetime. The author must separately prove that each generated offset names the intended field on the archived target format. #cite(<bpf-verifier>)

#verifier-note(title: "What future acceptance would establish—and what it would not")[Verifier acceptance could establish that selected bytecode obeyed pointer, helper, stack, and control-flow rules for one target and program type. It would not establish that a field has the intended scheduler meaning, that two events form a complete history, that no LRU eviction occurred, or that the interval explains application latency.]

== A safe, reproducible procedure <sec-08-procedure>

The safe procedure has two levels. Level 0 is an audit that changes no kernel state. Level 1 builds the object as an ordinary user. Attachment is a separate, environment-gated action that should be attempted only in an approved disposable NixOS VM after the source issue below is corrected and the local fixtures validate every decoded field. The repository's continuous integration does not load or attach the object, so neither a successful build nor a passing documentation check demonstrates runtime support.

First, enter the pinned development environment and record the harmless local evidence. The following commands read files, inspect the workspace, or compile user-space/eBPF artifacts; they do not attach a repository eBPF program.

#terminal-listing(title: "Read-only audit and ordinary-user build", ```sh
cd /home/ubuntu/learn-eBPF-00
nix develop
./scripts/check-kernel.sh

tracefs=/sys/kernel/tracing
[ -d "$tracefs" ] || tracefs=/sys/kernel/debug/tracing
for event in sched_waking sched_wakeup sched_switch; do
  if [ -r "$tracefs/events/sched/$event/id" ]; then
    printf '\n== sched/%s id ==\n' "$event"
    cat "$tracefs/events/sched/$event/id"
    printf '== sched/%s format ==\n' "$event"
    sed -n '1,120p' "$tracefs/events/sched/$event/format"
  else
    printf '\nMISSING OR INACCESSIBLE: sched/%s\n' "$event"
  fi
done

cd samples
cargo xtask check
cargo xtask build-ebpf
cargo build -p sample-runner
```)

Record `uname -r`, `uname -m`, the repository revision, `Cargo.lock`, the exact format text, and any build error. The safe procedure ends after audit/build. Running `./target/debug/sample-runner run 07-scheduler-latency` as an ordinary user should return the quarantine error before attachment; do not bypass that check or guess offsets.

== Expected output and interpretation <sec-08-expected-output>

The only unconditional expected result of the audit phase is a report of what the current target exposes or cannot expose. `check-kernel.sh` labels unavailable configuration evidence as `UNKNOWN`; it does not attach anything. The build phase either produces `target/ebpf/samples-ebpf` and `target/debug/sample-runner` under the pinned toolchain or returns an ordinary build diagnostic.

#expected-output(title: "The safe expected result")[The current runner reports: `07 is quarantined: the default object contains no scheduler-field decoder; generate and test a target tracepoint-format fixture rather than assuming offsets`. No eBPF program is loaded or attached on that path. A future fixture-validated result would still be a best-effort correlation, not a service-level objective.]

== Portability, limits, and cleanup <sec-08-portability>

The dynamic feature boundary is broader than a version number. The target must expose accessible scheduler events in TraceFS; the selected records must contain the fields, widths, offsets, and meanings the decoder uses; the eBPF program and its helpers must be accepted for tracepoint use; and the actual loader identity must have authority under the host's capability, lockdown, Linux Security Module, container, and mount policy. BPF Type Format (*BTF*) is not required by this particular context-reader design, but the absence of BTF does not make a layout-dependent tracepoint decoder portable. Feature-test the exact hook and object on the booted kernel. #cite(<bpf-design-q-and-a>)

The correlation boundary is equally important. It excludes time before the observed wakeup, timer expiry and interrupt delivery details, time spent on a remote CPU before a migration becomes visible, user-space resumption after the switch, application-level locks, input/output (*I/O*) completion, and work queued after the thread runs. It also cannot distinguish all repeated wakeups for one PID. A diagnosis should combine this metric with a clearly scoped workload trace and, where appropriate, CPU utilization and runnable-pressure tools—not with an unsupported private run-queue read.

Cleanup for the audited procedure is simply process exit: no eBPF object was attached. A later implementation must define bounded duration, owner-scoped links, partial-attach unwind, and no default pins before its quarantine can be removed.

== Exercises <sec-08-exercises>

#exercise(title: "Define the measurement boundary")[Write two one-sentence definitions: one that starts at `sched_waking`, and one that starts at `sched_wakeup`. For each, list one reason the two values might differ. Do not claim either is an end-to-end request latency.]

#exercise(title: "Audit a target without attaching")[Run the TraceFS portion of #section-ref(<sec-08-procedure>, title: "the safe procedure") on an authorized development target. Archive the local formats, then list the generated constants and fixture tests a reviewed replacement would need. Confirm #listing-ref(<lst-08-runner-quarantine>, title: "the quarantine") remains the executable default.]

#exercise(title: "Design the missing health counters")[Propose fixed-width counters for map-update failure, LRU replacement or eviction where observable, unmatched switch, repeated wakeup overwrite, ring reservation failure, malformed consumer record, and expiry. For each counter, state whether it is per-CPU or shared and why.]

#exercise(title: "Reason about migration")[Imagine a waking CPU and a destination CPU are different. Explain why a shared PID-to-timestamp map is useful for this correlation, while a per-CPU counter is useful for loss accounting. State why neither choice gives a globally atomic snapshot.]

== Chapter summary <sec-08-summary>

A scheduler measurement begins by separating *sleeping*, *runnable*, and *running*. Run queues and policy machinery are private, per-CPU kernel implementation state; static tracepoints provide safer event facts but not a stable ABI. The honest metric joins a target-validated wakeup event to a target-validated `sched_switch` next-task field and calls the result wakeup-to-observed-run latency.

The current `07-scheduler-latency` sample demonstrates a stronger engineering lesson: an unproven decoder should not ship merely because it once compiled. The default object contains no scheduler-field program, and the runner refuses attachment until generated target-format fixtures and health accounting exist. The design remains useful; the unsupported implementation is not silently presented as runnable.

== Next steps <sec-08-next-steps>

The next chapter, #chapter-ref(<ch-09>, title: "Page Faults"), applies the same discipline to memory-management observations: use locally available exception events, aggregate carefully, and avoid interpreting an observed page fault as proof of disk I/O, a crash, or a private page-table walk. The transferable habit is simple: define the event boundary, prove the decoder against the running target, count the ways observation can fail, and preserve a safe no-attach fallback.
