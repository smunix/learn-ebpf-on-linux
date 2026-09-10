#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, kernel-detail, portability-note, security-note, verifier-note
#import "../../components/code.typ": code-file, code-listing, terminal-listing
#import "../../components/crossrefs.typ": figure-ref, listing-ref, section-ref, table-ref
#let source-slice(path, first, last) = {
  let lines = read(path).split("\n")
  lines.slice(first - 1, last).join("\n")
}


#chapter-opener(part: [01 — Foundations], chapter: [01])

= Why eBPF Exists <ch-01>

Linux is already the place where packets arrive, processes change state, files are opened, and access-control decisions are made. An application that wants to observe or constrain those events faces a difficult choice: move large volumes of data out of the kernel for later analysis, or modify the kernel itself. *extended Berkeley Packet Filter (eBPF)* exists to make a third option practical: a small, purpose-bound program can run at a defined kernel execution point after the kernel has checked it against a conservative safety model. It can then communicate through explicit kernel objects rather than arbitrary memory access. This chapter builds the mental model needed to use that power without treating it as magic, a general kernel module mechanism, or a shortcut around Linux security boundaries.

== Prerequisites <ch01-sec-prerequisites>

This is a conceptual and read-only chapter. You should be comfortable with the distinction between the Linux kernel and user space, know that a process has a user identity, and be able to run a command from a shell. No Rust, eBPF object, privileged loader, or kernel configuration change is required to complete the primary exercise. A disposable virtual machine (VM) is still the correct place for later attachment experiments because an eBPF program, once accepted, executes in the kernel.

The chapter refers to an *application binary interface (ABI)*, the binary-level agreement on data layout and calling conventions; an *Executable and Linkable Format (ELF)* object, the usual container for compiled eBPF code and metadata; and a *control group (cgroup)*, the Linux hierarchy used for resource accounting and some policy scopes. These definitions are deliberately introduced before the details: the boundary, not the programming language, is the important starting point.

== Learning objectives <ch01-sec-objectives>

After working through this chapter, you should be able to:

- distinguish classic BPF from eBPF and explain why the latter is not arbitrary code running in the kernel;
- describe the contract formed by a program type, hook, context, helper set, return value, map, authority, and lifecycle;
- separate observation from enforcement, and explain why audit-first design is safer than beginning with denial;
- identify realistic eBPF use cases without promising universal portability or performance; and
- run and interpret the repository's attachment-free `00-lab-check` preflight without mistaking its result for a successful eBPF load.

== From packet filtering to constrained kernel extension <sec-history>

The original *Berkeley Packet Filter (BPF)* was developed for packet capture. “BSD” means *Berkeley Software Distribution*, the family of Unix systems in which that early filter work became widely known. Its central idea was economical: test packets close to where they arrive and copy only the packets that a consumer has selected. The older, restricted model is now usually called *classic BPF (cBPF)*. That history matters because it explains both eBPF's event-driven character and its suspicion of unconstrained in-kernel computation.

Modern Linux uses BPF as the name of a broader subsystem and instruction-set family. eBPF retains a small virtual-machine instruction set but applies it to more than packets. A program can be associated with a tracing point, a network receive path, a socket or cgroup operation, or a security hook. The program type establishes the initial context and substantially constrains what the program may do. Linux documents eBPF programs as subject to program-type-specific rules rather than as interchangeable snippets of kernel code. @bpf-design-q-and-a

That distinction answers the first question a beginner should ask: *why not just load a kernel module?* A module has broad native-kernel power and a much larger failure and review surface. It can make arbitrary calls, retain state, and damage a running system if it is wrong. An eBPF loader instead asks the kernel to create named state, verify a compiled program, and attach that program to a permitted hook. The kernel may reject the request before it runs. This does not make eBPF harmless or automatically correct; it deliberately narrows the available operations and requires the author to work through an explicit contract.

#concept(
  title: [The contract, not “a script in the kernel”],
  [
    Think of an eBPF program as a *verified callback with a bounded interface*. The program type says what kind of callback it is. The hook says when it can run. Its context, permitted BPF helpers, map types, return convention, authority checks, and attachment lifetime say what the callback can safely mean. Change any one of those elements and a previously valid program may become unavailable or incorrect.
  ],
)

A *hook* is the named or typed execution point at which the kernel may invoke the program. A *BPF helper* is a kernel operation exposed through a controlled calling interface to eligible program types, not an arbitrary function pointer. A *BPF map* is a kernel-resident data structure that provides explicit shared state between eBPF execution and user space. Maps are the normal route for counters, bounded configuration, and carefully defined telemetry; they are not a license to pass pointers across the protection boundary. Linux's map documentation describes these objects as the shared state mechanism used by BPF programs and user-space processes. @bpf-map

The result is a useful form of extensibility. A team can answer a focused question—“how often did this event occur?”, “which destination did this workload attempt to contact?”, or “would this narrow file rule match?”—without carrying an out-of-tree kernel patch. The cost is precision. An eBPF program cannot assume it may access a convenient kernel structure, call a familiar function, or attach wherever a blog post did. It must be accepted on the target kernel for the chosen purpose.

== A hook landscape: purpose determines the boundary <sec-hook-landscape>

The hook landscape in #figure-ref(<fig-hook-landscape>, title: [the kernel-hook landscape]) places the loader, verifier, hooks, maps, and user-space application in one picture. It is deliberately a landscape rather than a compatibility chart. The diagram identifies families of places where eBPF may participate; it does not say that every Linux kernel exposes each family, that every interface permits every helper, or that a given user has authority to attach there.

#figure(
  image("../../assets/diagrams/generated/01-hook-landscape.svg", width: 100%),
  caption: [A purpose-first view of eBPF: a user-space loader offers a constrained object to the kernel; a verifier decides whether it may load; a selected hook can exchange bounded state through maps. The same word “eBPF” covers different contracts, not one universal attachment mechanism.],
) <fig-hook-landscape>

Tracing hooks observe execution. A static tracepoint, for example, is an intentionally exposed event that user space can discover through the tracing filesystem (*tracefs*). Dynamic probes and function-oriented mechanisms have different coupling and portability consequences. Network hooks sit on packet or socket paths. *eXpress Data Path (XDP)* is a receive-side packet-processing hook; its packet and action semantics should not be generalized to tracing or security programs. @xdp-rxq A cgroup hook applies at the scope of a cgroup hierarchy, which is not the same thing as a durable container identity. @cgroups-v2 Finally, a *Linux Security Module (LSM)* hook participates in security decisions and therefore deserves a stronger rollout discipline than a counter or observer. Linux describes BPF LSM as a privileged mechanism for audit and mandatory-access-control policy. @bpf-lsm

The phrase “kernel extensibility” can hide these distinctions. In this book, it means deliberately adding a narrowly reviewed reaction to one defined kernel event. It does *not* mean installing a general-purpose runtime, monkey-patching arbitrary kernel functions, or accepting unreviewed hook names from an application user. A production loader should keep the program and hook selection in a small allow-list. The early laboratory will be narrower still: the primary sample does not load a program at all.

== Observation and enforcement solve different problems <sec-observation-enforcement>

Observability asks what happened or how often it happened. Enforcement changes the outcome of an operation. This is not a difference in logging style. A tracing program that increments a counter can be useful even if user space is slow to read it. A decision program may need a defined return value before the underlying action continues, and a mistake can interrupt a legitimate workload. The kernel's verifier is relevant to both, but verifier acceptance does not establish that a measurement answers the right question or that a rule is an appropriate security policy. @bpf-verifier

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (1.18fr, 1.6fr, 1.75fr, 1.72fr),
    inset: 6pt,
    stroke: 0.35pt + rgb("#B8CDD2"),
    table.header(
      [*Intent*], [*Representative hook family*], [*Safe early result*], [*Primary risk to manage*],
    ),
    [Observation], [Static tracepoint or other tracing hook], [A bounded counter or sampled, schema-defined event], [Misinterpretation, excess collection, overhead, or loss],
    [Network handling], [XDP, traffic control (TC), or socket/cgroup hook], [Classify or count; pass unfamiliar traffic in an isolated lab], [Breaking connectivity or parsing beyond proved bounds],
    [Workload attribution], [cgroup-related hook plus host-side lifecycle data], [Record a cgroup identifier with time and scope], [Mistaking a cgroup path or identifier for a container identity],
    [Security audit], [BPF LSM hook], [Emit a narrow audit decision and reason], [Collecting sensitive context or assuming the audit is complete],
    [Security enforcement], [BPF LSM hook with its documented decision contract], [No denial by default; first validate audit results], [Denying legitimate work, incomplete identity, recovery failure, or unsafe rollout],
  ),
  caption: [Purpose-first eBPF use cases. Each row has a different context, return convention, authority model, and failure mode; no row inherits another row's guarantees.],
) <tab-use-cases>

The table's safe early results are intentional. A scheduler counter exposes a narrow fact: the selected event fired while the attachment existed. It does not diagnose application latency, identify a process, or prove system health. A network classifier can count frames, but an unaligned parse or an unsafe default action can damage connectivity. A cgroup identifier can be a useful correlation key, but names and paths can change, and cgroup namespaces can present different views. A security audit can explain what a rule *would* see, but an event stream can lose records and is not itself the decision mechanism.

#security-note(
  title: [Audit is the default; denial is a separate opt-in experiment],
  [
    Do not begin this book by attaching a deny-capable program. When a later exercise introduces enforcement, it must be explicitly selected, restricted to a disposable cgroup in a recovery-capable VM, and preceded by an audit-only observation period. Its rule must have a defined object identity and rollback path. Telemetry loss must never silently decide whether an operation is allowed or denied. This chapter and `00-lab-check` perform no enforcement.
  ],
)

This posture is threat-aware rather than timid. eBPF can reduce observation cost by filtering and aggregating near the event source, but it also expands the impact of a bug in a privileged loader or a bad policy. Threat modeling therefore starts with the object being protected, the actor who controls loader inputs, the authority delegated to the loader, the information a program could expose, and the recovery action if an attachment is wrong. The right initial response to uncertainty is a smaller hook scope and an audit record—not a broader deny rule.

Other Linux controls remain important. *secure computing mode (seccomp)* filters a process's system-call interface and is complementary to capabilities, namespaces, LSM policy, and application design; it is not an eBPF map-and-helper program. @seccomp Linux capabilities divide historically broad administrative authority into named powers. On targets that support the relevant capability model, an observability deployment should plan for the least authority required for its exact operation rather than reflexively granting broad administration. @capabilities

== What happens between source code and a hook <sec-lifecycle>

The word “load” is often used too casually. A practical eBPF lifecycle contains separate decisions. A developer compiles an eBPF crate into an ELF object. A user-space loader parses the object and asks the kernel to create its maps and verify a program. If verification succeeds, the kernel returns file descriptors for accepted objects. The loader then performs an attachment operation appropriate to the chosen program and hook. When that hook fires, the program may run and update a map or attempt a bounded event delivery. A user-space process can read the map or consume that channel under its own error and loss rules.

In this repository, *Aya* is the Rust ecosystem used for this split. The user-space side can use ordinary Rust facilities for configuration, error reporting, and controlled shutdown. The eBPF side is compiled for the constrained BPF target and must fit the program type's permitted operations. Aya makes the interface more ergonomic; it does not waive a kernel contract or eliminate version matching. The repository pins Aya dependencies in its Cargo workspace and pins a Rust toolchain, so examples should be built through that declared environment rather than an arbitrary system compiler. @aya-book

The kernel verifier is the key gate between object and execution. It explores reachable program paths and tracks register state, pointer provenance, bounds, alignment, initialized stack bytes, helper arguments, and nullable values. A map lookup, for instance, can fail; dereferencing its result before a successful branch is not safe merely because “the map should have the key.” Helper calls also have specified calling effects, so a program must respect the state they invalidate. The verifier rejects ambiguity rather than guessing what a path means. @bpf-verifier

#verifier-note(
  title: [Verification is a proof obligation with a limited conclusion],
  [
    “Verified” means that the target kernel accepted the emitted bytecode under the selected program type and available interfaces. It does *not* mean bug-free, privacy-preserving, semantically portable, lossless, or low-overhead. The Rust compiler also cannot turn verifier acceptance into a proof of a tracepoint field's meaning, a packet pointer's Rust alignment, or a counter's interpretation. Treat the verifier log and target result as evidence for one object on one stated target.
  ],
)

Object lifetime is equally concrete. A file descriptor is one reference, not a cleanup promise. An attachment, a pin in the *BPF filesystem (bpffs)*, or another kernel reference can retain an object after a process has changed state. The early labs avoid pins because persistence turns a short experiment into an operational system with ownership, permissions, schema, upgrade, and rollback questions. A clean early result is therefore not “the process exited”; it is “the owned references were released and no deliberate persistent reference was created.”

*BPF Type Format (BTF)* and *Compile Once – Run Everywhere (CO-RE)* are later aids, not universal escape hatches. BTF provides compact type metadata, and CO-RE can relocate eligible type accesses against target BTF information. That can reduce direct coupling to a kernel structure's layout, but it cannot make an absent hook, unavailable helper, denied privilege, changed semantic, or unreadable BTF object appear. @libbpf-core The first durable habit is to feature-probe and record the booted kernel, not to infer support from a version number alone.

== Constraints are the design language <sec-constraints>

eBPF's constraints are what make kernel extension reviewable. The program must terminate within the verifier's accepted control-flow model. It has a limited stack budget, and every helper-visible byte must be initialized. Pointers have tracked origins and bounds; data obtained from a map must be checked when lookup can return null. Helpers are allow-listed by program type. A return value is part of the hook contract, not a generic success convention. Modern kernels can accept some bounded loops, but a finite loop can still be rejected if its analysis cost or proof is not acceptable on the target. @bpf-design-q-and-a

These restrictions lead to practical design choices. Count before streaming. Use a per-central-processing-unit (per-CPU) map when a counter can be aggregated later rather than incurring unnecessary shared contention. Keep data records fixed-size, versioned, bounded, and explicitly initialized when a later lesson needs transport. Filter before exporting events. Keep `unsafe` Rust operations small enough that the invariant can be stated beside them. Above all, make the fallback visible: a failed map update, unavailable event, rejected object, or unsupported feature is an operational result, not a cue to quietly substitute a broader hook.

#portability-note(
  title: [Discover locally; do not universalize a tutorial],
  [
    A static tracepoint is discoverable in tracefs, and its `format` file describes the active record layout on that target. It is not a blanket stable ABI promise. Before decoding any tracepoint bytes, verify the event, identifier, fields, offsets, widths, and semantics on the booted kernel. The first runtime counter recommended by this book avoids the issue by reading no event payload at all. The repository's primary sample in this chapter is even narrower: it performs read-only environment checks and does not attach.
  ],
)

Portability also includes authority. A root user identifier (UID) is not a complete statement of BPF permission, and a program that an administrator can attach may still be unavailable to a production service identity. Namespace context, LSM policy, performance-event restrictions, kernel configuration, mount visibility, and program-specific capability checks matter. Conversely, a green capability check does not prove an event exists or a CO-RE relocation will succeed. The correct support statement is always a compound one: this object, built from this source, was accepted and attached to this hook on this booted kernel under this stated authority and lifecycle.

== Primary sample: `00-lab-check` is an attachment-free preflight <ch01-sec-lab-check>

The primary sample deliberately sits at capability tier zero. Its manifest, shown in #listing-ref(<lst-lab-manifest>, title: [the canonical lab-check manifest]), declares `programs = "none"`. There is no eBPF object named by this sample, no hook to attach, and no enforcement option. This makes it a safe first contact with the environment rather than evidence that a future program will load.

#code-listing(
  [Canonical `00-lab-check` manifest],
  source-slice("../../../samples/00-lab-check/sample.toml", 1, 3),
  language: "toml",
  source-path: [samples/00-lab-check/sample.toml],
) <lst-lab-manifest>
The shared runner implements the command in #listing-ref(<lst-lab-check-runner>, title: [the canonical runner function]). It prints a feature matrix headed `learn-eBPF lab feature matrix (read-only)`. It reads the kernel release string from `/proc/sys/kernel/osrelease`; tests whether `/sys/kernel/btf/vmlinux` is a file; reads the active LSM list when `/sys/kernel/security/lsm` is available; and checks whether `/proc/filesystems` mentions `cgroup2`. It tests whether the conventional bpffs path is a directory and whether either conventional tracefs path is a directory. Finally, it reports whether the process has effective user identifier (EUID) zero. The function does not call the BPF system call, create a map, load a program, attach a hook, mount a filesystem, or write under bpffs.

#code-listing(
  [Read-only implementation of the `lab-check` subcommand],
  source-slice("../../../samples/runner/src/main.rs", 83, 132),
  language: "rust",
  source-path: [samples/runner/src/main.rs, lines 83–132],
) <lst-lab-check-runner>

The details of those probes matter. `kernel BTF` means the named path is a regular file; it does not establish that the file is readable or that a particular object can relocate against it. `cgroup v2` means `cgroup2` was found in the kernel's advertised filesystem list; it does not establish that cgroup version 2 is mounted, delegated, or the intended workload scope. `tracefs` means one of two directories exists; it does not confirm that `sched/sched_switch` or another named event exists or is readable. `effective root` checks only EUID zero. The README's negative control—running it unprivileged—therefore correctly yields an `effective root unsupported` row while the other read-only probes may still succeed.

== Safe, reproducible procedure <ch01-sec-procedure>

Use the procedure below as a documentation and environment preflight. It is safe to perform on an ordinary development machine because the lab-check path is read-only, but the repository recommends a disposable NixOS VM for all subsequent kernel-facing work. The procedure avoids changing sysctls, mounting filesystems, setting file capabilities, pinning BPF objects, or granting broad authority to a shell or compiler.

#terminal-listing(
  title: [Read-only `00-lab-check` procedure],
  "nix develop\njust check\ncd samples\ncargo xtask build-ebpf\ncargo build -p sample-runner\ncargo run -p sample-runner -- lab-check",
) <lst-lab-check-procedure>

`nix develop` selects the repository's pinned development environment, and `just check` performs the repository's non-privileged validation scope. The two explicit build commands are the sample README's documented workspace preparation: the eBPF build path can require the pinned Rust toolchain and `bpf-linker`, even though the `lab-check` subcommand itself names no eBPF program. `cargo run -p sample-runner -- lab-check` invokes only the read-only command described above. Build availability is *environment-gated*: if the pinned toolchain or `bpf-linker` is absent, record that condition rather than installing a random replacement, using `sudo cargo`, or weakening host policy. The feature matrix itself remains useful only after the runner has been built with the declared project environment.

#expected-output(
  title: [What this command can and cannot establish],
  [
    The first line is literally `learn-eBPF lab feature matrix (read-only)`. The following rows are labeled `Linux`, `kernel BTF`, `BPF LSM active`, `cgroup v2`, `bpffs`, `tracefs`, and `effective root`; each row is dynamically reported as `supported` or `unsupported` with the observed detail. The closing line states that compilation is safe and that attachment requires listed kernel features and BPF privileges. Do not pre-fill “supported” values: they are properties of the running environment. A successful run establishes only that these limited probes completed; it is not a verifier, load, attach, performance, or policy test.
  ],
)

There is no verifier reasoning to perform for this command. The verifier runs only when a loader presents an eBPF program for load. Here `programs = "none"`, and the runner's `lab_check` function makes filesystem reads and an EUID check only. This clean absence is valuable: it lets a beginner separate *environment discovery* from *kernel program acceptance* before a later chapter combines them.

== Cleanup <ch01-sec-cleanup>

No cleanup command is required for `00-lab-check`. It creates no BPF map, program, attachment, link, pin, mount, configuration change, or policy state. Ending the command only ends the process. If a later experiment creates a kernel object, do not assume this section applies: verify the attachment's owner and its removal path, and check for deliberate pins before declaring the system clean.

== Exercises <ch01-sec-exercises>

1. Run `00-lab-check` as your normal user and save the complete output with the date, `uname -r`, and architecture in your lab notes. For every `unsupported` row, identify whether it represents a missing feature, an inaccessible path, or merely a deliberately narrow probe. Do not change the host to turn a row green.

2. Read `samples/runner/src/main.rs` around the listing in #listing-ref(<lst-lab-check-runner>, title: [the lab-check function]). Make a table distinguishing a *file exists* check, a *file read* check, and a *semantic capability* check. Explain why each of `kernel BTF`, `tracefs`, and `cgroup v2` has a weaker meaning than its label might suggest.

3. On a system where tracefs is readable, inspect the directory for `sched/sched_switch` and its `format` file without writing anything. Identify the difference between discovering a local event definition and claiming a cross-kernel ABI. Do not write a context decoder yet.

4. Design, on paper, an audit-only file-access experiment. State the hook family, exact object identity, payload minimization, decision return contract, cgroup or workload scope, rollback plan, and what evidence would be required before any denial is considered. The correct first implementation remains audit-only in a disposable VM.

== Chapter summary <ch01-sec-summary>

BPF began as a way to filter packets before unnecessary copying; Linux eBPF generalizes the controlled-program idea to several carefully distinguished hook families. Its value is not unconstrained code execution. Its value is an explicit, verifier-gated contract for a narrow reaction to a kernel event. The program type, hook, context, helpers, maps, return value, authority, and lifetime form one unit of design.

Observation and enforcement are therefore different activities. Counters and bounded audit records can support diagnosis, while enforcement changes outcomes and requires identity, rollout, recovery, and threat-model evidence that a counter does not. The safe default is audit-first. Denial, when later taught, is explicitly opt-in and confined to a disposable cgroup in a recovery-capable VM.

The repository's `00-lab-check` reinforces the distinction. It is a read-only feature matrix, not an eBPF program. It reports limited path, filesystem-list, LSM-list, and EUID observations without loading or attaching anything. Its result is a truthful starting point: an environment may be unavailable, partially visible, or promising, but only a correctly scoped future object can produce target-specific verifier, load, attach, and cleanup evidence.

== Next steps <ch01-sec-next-steps>

The planned next chapter, *The NixOS Laboratory and Least Authority*, turns the feature matrix into a reproducible test record. It will separate the pinned build environment from the booted kernel, inspect mounts and event formats, record the service's actual authority context, and explain why a truthful “unavailable” is safer than broadening privileges or silently changing hooks. No cross-reference target is emitted here because the next chapter source has not yet been added to this repository.
