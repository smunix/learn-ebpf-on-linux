#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-file, code-listing, terminal-listing

#let lab-check-source = read("../../../samples/runner/src/main.rs")
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "V", chapter: "16")
= Kernel-Version Survival <ch-16>

An extended Berkeley Packet Filter (eBPF) feature is not available merely because a release string looks recent, an object compiled, or a documentation page describes the facility. It is available only when the *booted* kernel, its configuration, the active security policy, the program and attachment type, the selected hook, the loader's authority, and the emitted object agree. This chapter turns that statement into a repeatable operating method. The immediate practical tool is `00-lab-check`, a deliberately read-only environment audit. It records a few useful facts without loading or attaching an eBPF program. It is a starting point for evidence, not a certificate that a later program will work.

The goal is survival across kernels without guessing. A a portable observer selects a capability tier, records its decline reason, and remains inactive when no safe tier exists. This approach prevents two expensive mistakes: attaching to a different interface because the intended one was absent, and treating an unavailable security feature as a reason to grant broader privilege. The distinction matters especially for the Linux Security Module (LSM) framework, where an audit experiment is reversible but an accidental denial can block ordinary system work.

== Prerequisites <ch16-sec-prerequisites>

Before beginning, use a Linux virtual machine (VM) or another authorized disposable host. Be able to run ordinary Cargo commands as an unprivileged build user, read basic pseudo-files such as `/proc` and `/sys` when the host allows it, and distinguish a *build* from an eBPF *load* and *attachment*. Have a checkout of this repository whose `samples/Cargo.lock` is retained with the results. The workspace declares Rust edition 2024 and pins Aya 0.14.0, Aya build 0.2.0, and Aya eBPF 0.2.1; use the repository's pinned toolchain rather than silently substituting an older compiler.

This chapter does not ask a reader to lower `perf_event_paranoid`, enable unprivileged BPF, grant a general-purpose shell `CAP_SYS_ADMIN`, change memory limits, or pin an object in the BPF filesystem (bpffs). Linux capabilities divide privileged operations more finely than a UID 0 check, but the exact authority required remains operation-, kernel-, namespace-, and policy-dependent. A successful command run by an administrator is not proof that the intended service identity can run it. #cite(<capabilities>)

== Learning objectives <ch16-sec-objectives>

After completing this chapter, you should be able to:

- separate diagnostic kernel-version metadata from an on-target feature decision;
- interpret exactly what `00-lab-check` reports, including what each positive result does *not* establish;
- probe a selected program type, helper, hook, BPF Type Format (BTF) object, and tracepoint format without inventing a compatibility claim;
- preserve a target-local tracepoint-format fixture and account for architecture, byte order, and application binary interface (ABI) concerns;
- select and expose an enriched, baseline, user-space, or unavailable fallback tier; and
- define a test matrix that distinguishes audit-only LSM readiness from any opt-in enforcement experiment.

== The mental model: a feature is a conjunction <ch16-sec-mental-model>

A kernel release is useful context. Record `uname -r`, the machine architecture, distribution image identity, loader version, and object hash. Do not use any one of them as the predicate `feature_available`. Vendors backport selected changes, distributions disable configuration options, container policy hides host facilities, and helper availability depends on the exact eBPF program type. The kernel verifier also decides whether *this* bytecode may run under *this* context. Kernel documentation explicitly treats attempted loading as the meaningful evidence for a particular program and host. #cite(<bpf-design-q-and-a>)

A practical feature decision is a conjunction of independently observable statements:

$"usable" = "object matches architecture" and "kernel facility present" and "selected hook exists" and "program type permits helper" and "policy permits operation" and "load verifies" and "attach succeeds"$

The formula is a reasoning aid, not an instruction to perform every operation up front. Start with harmless reads. When an object is necessary, use the smallest audit-only object that can answer one question, retain the error and verifier diagnostics, and detach immediately after a bounded smoke observation. A failed term selects a planned downgrade; it does not invite automatic privilege escalation, a guessed offset, or a substitute hook with different semantics.

#concept(title: "Compatibility is an observed contract")[
  A version string describes one property of a host. A usable eBPF capability is a contract among a particular object, a target kernel configuration, an attachment interface, and the deployment identity. Record the contract's evidence. When a term is unknown, report *unknown* or select a lower tier; never convert absence of evidence into support.
]

The distinction between Compile Once—Run Everywhere (CO-RE) and general portability belongs here. CO-RE uses BTF metadata in an Executable and Linkable Format (ELF) object and on the target kernel to relocate eligible type and field accesses. It can adapt a supported layout difference. It cannot create a missing BTF file, tracepoint, helper, program type, attachment type, privilege, LSM activation, or unchanged semantic meaning. A CO-RE object whose necessary target BTF or relocation cannot be resolved must fail into a genuinely BTF-free object or into no eBPF feature; it must not be treated as a baseline object by wishful loading. #cite(<libbpf-core>)

== Start with the repository's read-only audit <ch16-sec-lab-check>

The sample manifest for `00-lab-check` declares `programs = "none"`. The command dispatches to `lab_check()` and returns after printing local facts. It does not instantiate Aya's `Ebpf` loader, open an eBPF object, invoke the BPF system call, attach a hook, create a map, pin a reference, or modify a host setting. The canonical sample manifest and README are shown in #listing-ref(<lst-lab-check-manifest>, title: "sample manifest") and #listing-ref(<lst-lab-check-readme>, title: "README contract"). They establish the repository-facing command; the current runner source establishes the behavior this chapter describes.

#code-file(
  "../../samples/00-lab-check/sample.toml",
  title: [Canonical `00-lab-check` sample manifest],
  language: "toml",
  source-path: "samples/00-lab-check/sample.toml",
) <lst-lab-check-manifest>

#code-file(
  "../../samples/00-lab-check/README.md",
  title: [Canonical contract for `00-lab-check`],
  language: "text",
  source-path: "samples/00-lab-check/README.md",
) <lst-lab-check-readme>

The README defines this subcommand as a read-only fact collector. `LabCheck` has no options and no enforcement branch, so passing `--enforce` after `lab-check` is not supported. It accurately promises `present`, `absent`, and `unknown` results, no elevated authority, and no cleanup. The runner source below is the canonical behavior relevant to this chapter.

#code-listing(
  [Canonical `lab-check` implementation],
  lab-check-source.split("\n").slice(95, 215).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs, lines 96–215",
) <lst-lab-check-implementation>

The program labels a Linux process target as present or absent and prints `/proc/sys/kernel/osrelease`, or `unreadable` if that read fails. Its BTF test distinguishes a readable regular `/sys/kernel/btf/vmlinux` file from an absent path and from an unknown state caused by a metadata or open failure. That is useful evidence that target BTF may be accessible, but it does not prove that a future loader can parse it or resolve a chosen CO-RE relocation. It reads `/sys/kernel/security/lsm`, checks for a comma-separated entry exactly named `bpf`, and reports the full list. An unreadable securityfs result is `unknown`; it is not a claim that no LSM is configured.

The mount checks are stronger than a filesystem-registration test but remain deliberately scoped. The runner reads `/proc/self/mountinfo` and reports whether cgroup v2, bpffs, and tracefs are mounted *in this mount namespace*. It does not prove cgroup delegation, bpffs pin permission, or a workload's cgroup membership. It also attempts to open a `format` file for `sched/sched_switch`, `syscalls/sys_enter_openat`, and `exceptions/page_fault_user` under either conventional tracefs root. A readable format is present; an inaccessible or missing one becomes `unknown` because the code does not distinguish the two. It does not read an event identifier, parse fields, validate offsets, or prove a later attachment.

Finally, “effective UID 0” reports EUID zero as present and nonzero as absent, explicitly noting that this runner currently requires UID 0 for attachment. This is a conservative runner limitation, not a statement of the kernel's universal eBPF authority model. The command also prints the raw `CapEff` line from `/proc/self/status` when that file is readable; it does not decode capabilities or decide whether they satisfy a selected BPF operation. The final interpretation line explicitly says that successful verifier load, attach, observation, and detach must be tested separately. In particular, the sample does not invoke `bpftool`, test BPF system-call availability, probe a helper or program type, validate an LSM hook, or load an eBPF object.

=== Safe, reproducible procedure <ch16-sec-procedure>

Run the documented workflow from the `samples` workspace as an ordinary user. Building the runner may create files below `target`, but `lab-check` itself remains attachment-free. If the pinned workspace toolchain is unavailable, record the mismatch rather than using `sudo` or changing dependencies.

#terminal-listing(
  title: "Build normally, then run the read-only audit",
  "cd samples\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check\n",
)

The function in #listing-ref(<lst-lab-check-implementation>, title: "read-only implementation") consumes no generated eBPF object. Run the same command under the eventual service identity where feasible. A nonzero EUID is expected to report `effective UID 0` as absent; that result neither grants nor disproves a more precisely configured capability set.

#expected-output(title: "Output contract, not invented host values")[
  A successful process prints `learn-eBPF read-only local facts (not a load/attach proof)`. It then prints `present`, `absent`, or `unknown` rows for the Linux process target, readable kernel BTF, active BPF LSM, cgroup-v2/bpffs/tracefs mounts, three tracepoint-format paths, effective UID 0, and effective capabilities. The final interpretation line is printed even when facts are unavailable. Exact statuses and details are environment-gated; this chapter intentionally does not predict them.
]

The audit requires no cleanup because it has no attachment or pin to remove. The ordinary build artifacts are not kernel state. If you want to remove only those local artifacts after recording the result, run `cargo clean` from `samples`; do not remove anything in `/sys/fs/bpf` merely because bpffs is mounted on an unrelated host.

=== Extend the audit with evidence, not guesses <sec-extend-audit>

A later tracepoint program needs a local event contract. Use the first readable tracefs mount and preserve both the event identifier and the entire `format` file with the test result. The command below reads only; it neither enables tracing nor attaches a program. The `format` file is a fixture for one booted target, not a source of hard-coded offsets that can be copied to another host.

#terminal-listing(
  title: "Read a scheduler tracepoint fixture without attaching",
  "set -eu\nfound=0\nfor tracefs in /sys/kernel/tracing /sys/kernel/debug/tracing; do\n  event=\"$tracefs/events/sched/sched_switch\"\n  if [ -r \"$event/id\" ] && [ -r \"$event/format\" ]; then\n    printf 'tracefs=%s\\n' \"$tracefs\"\n    printf 'event=sched/sched_switch\\n'\n    printf 'id='; cat \"$event/id\"\n    sha256sum \"$event/format\"\n    sed -n '1,160p' \"$event/format\"\n    found=1\n    break\n  fi\ndone\n[ \"$found\" -eq 1 ] || printf '%s\\n' 'sched/sched_switch is unavailable or unreadable'\n",
)

Store the unabridged format text in the test artifact together with `uname -r`, `uname -m`, the tracefs path, the event name, the event identifier, and a Secure Hash Algorithm 256 (SHA-256) digest. The identifier tells a tracing consumer which event is selected on that host. The format specifies the target-local record layout, including field offset, size, signedness, and any padding. It does not confer a stable application binary interface across all kernels. Upstream explicitly gives no blanket stable-ABI promise for tracepoints, and raw tracepoint arguments have an even stricter compatibility boundary. #cite(<bpf-design-q-and-a>)

A context-decoding program must enable a layout-dependent variant only after validating the exact required fields against this fixture. For example, a claimed `u32` at offset 56 is not justified because a tutorial used that number. The reader must demonstrate that the active format declares the field at that offset with the required width and interpretation. A payload-free counter can attach after event discovery without reading the context; that is why it is a stronger baseline than an early parser.

For feature facts beyond this sample, an authorized operator can ask the kernel through `bpftool` and retain JavaScript Object Notation (JSON) output as a diagnostic artifact:

#terminal-listing(
  title: "Optional authorized BPF feature probe",
  "bpftool -j feature probe kernel\n",
)

This command is informative, not a replacement for a program trial. Run it under the intended service authority when policy permits. Do not use `full` as a routine probe: helper probing can produce kernel warnings. More importantly, a `bpftool` installed from a different build knows a different vocabulary, and a probe run by an administrator can see facilities unavailable to the service. The decisive helper question remains: *does the selected object load for this program and attachment type under the production identity?* Helpers are allow-listed interfaces, and their contracts—including context, argument type, and return discipline—are specific to program type and target kernel. #cite(<bpf-verifier>)

== Verifier reasoning belongs after selection <ch16-sec-verifier-reasoning>

There is no verifier event in `00-lab-check`. The source contains no eBPF bytecode load, so a green read-only matrix cannot prove a later eBPF program safe, accepted, or attachable. This negative fact is useful: it prevents a reader from misreading a feature audit as a successful verifier test. Preserve the audit next to, rather than instead of, a future load log.

#verifier-note(title: "A probe does not discharge the proof obligation")[
  On a selected variant, the verifier must still prove every reachable path safe. That includes initialized stack bytes, a valid return value, typed pointer provenance, bounds and alignment, nullable map-result checks, legal helper arguments, bounded control flow, and release of tracked references. A helper call changes verifier state: argument registers R1 through R5 are caller-saved, while R6 through R9 are callee-saved. A feature row cannot establish any of those per-object facts. #cite(<bpf-verifier>)
]

Treat the first harmless selected object as a narrow experiment. Request verifier diagnostics in continuous integration (CI) and staging, retain the raw log, and classify an error as authorization, missing facility, relocation, proof, resource, or loader failure. Do not parse diagnostic prose as a durable machine protocol. Repair the proof—for example, dominate a map-value dereference with its null check—rather than suppressing the log or trying a more privileged shell. #cite(<bpf-verifier>)

A helper report is similarly incomplete. The verifier checks the type-specific allow-list, prototype, argument categories, range, alignment, and return lifetime. A tracing context and an LSM context are not interchangeable. If a helper is absent or rejected, select a design that does not need it. Never cast an integer into a pointer, reuse R1 through R5 after a helper, or bypass a bounds check to force a “portable” build.

== LSM configuration is a runtime precondition <sec-lsm-configuration>

An LSM is the kernel framework that dispatches security checks over objects and operations. BPF LSM is the `bpf` member of that framework; it permits privileged BPF programs to attach to BTF-described LSM hook stubs when the kernel was built and booted for that purpose. For ordinary integer authorization hooks, the normal contract is zero to permit and a negative error number to deny. A preceding nonzero result in a BPF LSM chain must be preserved. Cgroup LSM is a separate attachment model with different boolean-grant aggregation; never copy ordinary error-number return logic into it. #cite(<bpf-lsm>)

This chapter's lab check asks only whether the active list contains `bpf`. It does not establish `CONFIG_BPF_LSM=y`, BTF readability, a particular hook declaration, helper eligibility, lockdown state, or loader authority. It also cannot establish that `bpf` runs early enough to observe a decision: LSM order is part of the security contract, and an earlier non-default LSM decision may prevent later checks for an integer hook. Read and retain the complete active list, rather than reducing it to a Boolean feature flag.

On NixOS, an LSM list should be declared through the distribution's reviewed configuration rather than appended as an ad hoc, competing boot parameter. The NixOS expression must be pinned and reviewed for its release; after a recovery-capable reboot, `/sys/kernel/security/lsm` is the evidence of the actual effective order. On every distribution, record the pre-change and post-change lists and retain a recovery path. A configuration file that evaluates does not prove that a BPF LSM object will load. #cite(<bpf-lsm>)

#security-note(title: "Audit is the default; denial is an explicit experiment")[
  This chapter never enables enforcement. If a future lesson tests a denial-capable BPF LSM program, begin with the same identity and rule-matching path in audit mode, within a disposable VM or disposable cgroup whose recovery procedure has been practiced. Enable one narrow, opt-in denial only after hook, return contract, object identity, telemetry loss behavior, link lifetime, rollback, and permitted-workload tests have passed. A telemetry failure must not silently reverse the already selected authorization decision.
]

A cgroup version 2 check has an analogous limit. A control group is a resource and policy domain, not automatically a container identity. The relevant future test needs a mounted version-2 hierarchy, the intended cgroup path or file descriptor, delegation and membership evidence, and a defined hierarchy policy. The presence of `cgroup2` in `/proc/filesystems` is a necessary hint, not attachment scope proof. #cite(<cgroups-v2>)

== Architecture, byte order, and data contracts <sec-architecture-endian>

Portability is not only about kernel versions. Record `uname -m`, user-space word size, BPF compiler target, and the object's ELF architecture before treating a build as target-ready. Toolchains commonly distinguish little-endian `bpfel` and big-endian `bpfeb`. CO-RE adjusts eligible BTF-described access; it does not transform a wrong-endian object, validate alignment, or redefine byte order. Cross-architecture support needs its own matrix entry.

The tracepoint fixture controls context access. Its widths and offsets are target facts. For an application event across the kernel/user-space boundary, define a separate wire contract: fixed-width integers, stated byte order, zeroed reserved bytes, schema version, record length, and validation before decoding. Rust `repr(C)` helps define an in-process layout but is not serialization. Do not transmit pointers, references, `usize`, `bool`, unspecified enums, or implicit padding as durable records.

A per-central-processing-unit (per-CPU) map adds another interpretation boundary. A reader aggregates several CPU slots and observes a snapshot, not one atomic global count. CPU topology, online CPUs, and map representation remain target properties. For data that lasts beyond one same-host run, decode bytes deliberately and test byte order on every claimed architecture. These rules apply even when no BTF is involved; BTF metadata describes types, not an application’s wire protocol. #cite(<bpf-map>)

#portability-note(title: "Keep two proofs separate")[
  Verifier acceptance proves the target kernel accepted the bytecode’s memory, control-flow, helper, and resource reasoning. Rust and ABI review must separately prove data representation, initialization, alignment, lifetime, aliasing, byte order, and semantic interpretation. Neither proof substitutes for the other.
]

== Deliberate fallback tiers <sec-fallback-tiers>

A fallback is a deliberately smaller service, not a hidden retry loop. It must say what remains observable, why the preferred path was declined, and what an operator should do next. #figure-ref(<fig-feature-fallback>, title: "feature fallback tree") illustrates the control flow: probe facts first, attach the preferred path only when its prerequisites are established, use an explicitly safe alternative when one exists, and otherwise report unsupported status. This is safer than attaching an inferred hook or quietly emitting no data.

#figure(
  image("../../assets/diagrams/generated/16-feature-fallback.svg", width: 100%),
  caption: [Feature selection is a sequence of evidence-backed decisions: probe BTF, hooks, helpers, and LSM state; select a full path only when its requirements are met; otherwise select a named fallback or declare the feature unavailable.],
) <fig-feature-fallback>

#figure(
  kind: "table",
  supplement: [Table],
  caption: [A portability decision record keeps a downgrade observable and testable.],
  table(
    columns: (1.05fr, 1.45fr, 1.65fr, 1.35fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header(
      [*Tier*], [*Required evidence*], [*Permitted behavior*], [*Exported reason when declined*],
    ),
    [0 — read-only audit], [Ordinary-user reads; each unavailable file reported], [Environment facts only; no object load or attachment], [`unknown`, `securityfs-unavailable`, or a path-specific unavailable result],
    [1 — baseline eBPF], [Readable selected event fixture; authorized load and attach of a payload-free object], [Bounded counter or similarly narrow observation], [`event-missing`, `tracefs-inaccessible`, `permission-denied`, `verifier-rejected`],
    [2 — fixed telemetry], [Tier 1 plus field fixture, record ABI tests, and selected transport support], [Versioned bounded records with loss accounting], [`format-incompatible`, `transport-unavailable`, `resource-limit`],
    [3 — BTF/CO-RE enrichment], [Readable target BTF, emitted relocations, and successful relocation/load], [Guarded minimal kernel-type enrichment], [`no-target-btf`, `relocation-failed`, `field-unsupported`],
    [4 — LSM audit], [BTF, BPF LSM configuration and active list, exact hook/helper support, authorized audit-only load], [Audit-only decision telemetry in a recovery-capable test target], [`bpf-lsm-inactive`, `hook-unavailable`, `policy-denied`],
    [5 — opt-in enforcement], [Tier 4 evidence plus narrow scope, rollback, lifecycle, identity, and negative tests], [One declared denial rule in a disposable VM or cgroup], [Remain audit-only or inactive; never broaden scope automatically],
  ),
) <tab-fallback-tiers>

The table is a policy for truthful operation, not a claim that every product needs all tiers. A simple counter can stop at Tier 1. A security tool may offer Tier 4 audit and deliberately omit Tier 5 enforcement. In every case, publish the selected tier and one normalized reason at startup and in health output. A missing event should be distinguishable from no events occurring; a failed BTF read should be distinguishable from an object with no relocations; and an unavailable LSM must not be mislabeled as audit coverage.

== Build a test matrix, not a minimum-version slogan <sec-test-matrix>

A minimum kernel release can be a documentation aid, but it is not the support boundary. The matrix must name every environment the project claims to support and attach evidence to each row. Start with one known disposable baseline, then add each distribution kernel family, configuration, architecture, and security context that matters. Run the same selected object under the actual deployment identity. A root-only test does not cover a narrowly-capable service; an `x86_64` result does not cover `aarch64`; and a BTF-present test does not cover a stripped or inaccessible BTF deployment.

For every row, retain the git revision, `Cargo.lock`, Rust/Aya versions, compiler target, object SHA-256, `uname -r`, architecture, image or NixOS input revision, relevant configuration values or explicit “unavailable,” active LSM list, cgroup scope evidence, tracepoint fixture, probe output, and selected tier. Retain full load and verifier diagnostics where a load is attempted. A test that cannot run records *why*; it is not an implicit pass.

Exercise positive and negative paths. The baseline needs missing-event or inaccessible-tracefs behavior, authority denial, a bounded authorized attach, and no-pin cleanup confirmation. A CO-RE row needs BTF-present success and BTF-absent selection of a BTF-free path. A decoder needs fixture-mismatch rejection. LSM audit needs BPF-LSM/active-list absence, BTF absence, hook rejection, and normal audit output. Before enforcement, add rollback, detach, link-health, filesystem-class, hard-link/rename, missing-policy, and telemetry-full tests.

The verifier component of the matrix is object-specific. Preserve a positive log for the oldest claimed target and keep intentional negative fixtures quarantined from normal attachment. Check that helper boundaries, nullable lookups, stack initialization, bounded loops, resource release, and program-type return values are represented in the test design. Kernel documentation describes the verifier’s abstract tracking of these facts; source intent alone cannot substitute for target acceptance. #cite(<bpf-verifier>)

=== Exercises <ch16-sec-exercises>

#exercise(title: "Interpret one local audit")[Run `00-lab-check` as an ordinary user. For each row, write one sentence stating exactly what the implementation tested and one sentence stating what it did not test. Pay particular attention to `cgroup v2`, `tracefs`, and `effective root`. Do not change a system setting to turn an `unsupported` row into `supported`.]

#exercise(title: "Create a tracepoint evidence record")[On an authorized disposable host, run the read-only tracepoint-fixture command in #section-ref(<sec-extend-audit>, title: "Extend the audit with evidence"). Record its kernel release, architecture, path, event identifier, format digest, and full format text. Then identify one field whose offset or size makes a copied tutorial decoder unsafe on a different target.]

#exercise(title: "Design an honest downgrade")[Choose one prospective enriched observation that needs BTF and one BTF-free baseline observation. Define the preconditions, selected-tier health field, one downgrade reason, what data is no longer collected, and one test for the downgrade. Your baseline must not access a kernel-structure field solely because the richer variant can.]

#exercise(title: "Review LSM readiness without enforcement")[In a recovery-capable VM, compare the configured and active LSM lists. Explain why a present `bpf` entry is necessary but insufficient for a `file_open` audit program. List the additional BTF, hook, helper, authority, verifier, and lifecycle evidence required before any policy test. Do not enable a denial rule for this exercise.]

== Chapter summary <ch16-sec-summary>

Kernel-version survival begins with a change in language: support is not a number, but an observed contract. `00-lab-check` is an intentionally modest Tier 0 audit. It reports Linux targeting, readable BTF, active `bpf` LSM membership, cgroup-v2/bpffs/tracefs mount state in its own mount namespace, readable format paths for three named events, EUID zero, and a raw effective-capability line. It loads nothing, attaches nothing, probes no helpers or program types, and creates no kernel state. That narrow behavior makes it safe to run early and makes its omissions visible.

The next evidence layer is target-specific: preserve tracepoint `id` and `format` fixtures; test helper and hook availability for the selected program type and service identity; treat verifier acceptance as a proof about the emitted object; and separate that proof from Rust layout, byte-order, and semantic review. BTF and CO-RE are useful layout-adaptation tools, not universal compatibility switches. LSM configuration similarly requires both build/runtime state and a hook-specific load test. Audit is the normal starting state; denial is an explicit, narrow, reversible experiment only in a disposable cgroup or VM.

A portable system exports its chosen tier, decline reason, and evidence boundary. It uses a test matrix rather than a minimum-version slogan. When the necessary terms cannot be proved, the correct result is a named reduced feature—or a truthful unavailable state.

== Next steps <ch16-sec-next-steps>

The next chapter applies this evidence discipline to security hooks in #chapter-ref(<ch-17>, title: "BPF LSM Fundamentals"). It moves from determining whether an LSM path is available to defining hook return values, preserving earlier BPF-LSM decisions, and keeping audit-first policy experiments narrow and recoverable.

#bibliography("../../references.yml", title: [References])
