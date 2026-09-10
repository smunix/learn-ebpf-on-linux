#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, kernel-detail, portability-note, security-note, verifier-note, exercise
#import "../../components/code.typ": code-file, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "01", chapter: "02")

= Build a Safe NixOS Lab <ch-02>

An extended Berkeley Packet Filter (eBPF) program is not an ordinary application: after the kernel verifier accepts it, it can execute in kernel context at an attached hook. That makes the laboratory part of the program’s correctness argument. A good lab does not merely make a demo run. It makes the target kernel, toolchain, authority, attachment boundary, and cleanup outcome visible—and makes an unsupported result safe and useful.

This chapter builds that posture before any repository program is loaded. Its primary companion, `00-lab-check`, is a read-only feature report. It does not create a BPF object, request verifier analysis, attach a hook, alter a kernel setting, or pin state. The next kernel-facing exercise should remain small, short-lived, and audit-oriented; this chapter establishes the evidence required before that step.

== Prerequisites <sec-ch02-prerequisites>

You need a checkout of this repository, flakes enabled on a NixOS `x86_64-linux` host or an isolated NixOS virtual machine (VM), network access sufficient to realize the locked flake once, and enough local disk space for Nix store paths. You should be comfortable reading shell output, rebooting a throwaway VM, and reverting a VM snapshot. For the runtime tiers later in the book, arrange authorization from the machine owner; do not use a production host as a substitute for a lab.

The repository’s supported development target is NixOS on `x86_64-linux`. A flake is a Nix project interface whose locked inputs make evaluation and dependencies reproducible. The checked-in `flake.lock` fixes the Nix Packages collection (Nixpkgs) revision and the Rust overlay revision, while the sample workspace separately declares Rust 1.98.1 and records its complete Cargo dependency graph in `Cargo.lock`. A lock is valuable evidence, but it is not a claim that the currently booted kernel has the features that the source expects. See the NixOS flake model for the distinction between declared inputs and the realized system. #cite(<nixos-flakes>)

== Learning objectives <sec-ch02-objectives>

After completing this chapter, you should be able to:

- distinguish a pinned user-space build environment from the kernel that is actually booted;
- explain the different roles of BPF Type Format (BTF), the BPF filesystem (bpffs), tracefs, and control group version 2 (cgroup v2);
- run the repository’s attachment-free `00-lab-check` and interpret each result without treating an `unsupported` row as a cue to weaken the host;
- plan tracepoint authority around the least broad applicable Linux capabilities rather than assuming either unrestricted root or universal `CAP_BPF` suffices;
- prepare a disposable NixOS VM and record a preflight dossier suitable for later load and attach experiments; and
- cleanly decline an unavailable feature, including all BPF Linux Security Module (LSM) enforcement, rather than auto-escalating authority or changing global policy.

== 1. The lab is a dependency graph, not a package install <sec-ch02-mental-model>

It is tempting to regard `nix develop` as the beginning and end of eBPF setup. It is not. The development shell supplies a compiler, linker, command-line tooling, and an evaluated package set. The kernel supplies the BPF system call, program-type support, trace events, type metadata, authorization decisions, memory accounting, and verifier. A loader needs both layers at the same time. A successful host build therefore cannot prove that an object will load, and a friendly kernel cannot compensate for an unpinned or mismatched compiler output.

#concept(title: [The laboratory contract])[
  Treat each experiment as a conjunction of independent facts: a reviewed object built from known inputs; a booted kernel with the needed interface; a named hook whose local contract is present; authority for the exact operation; and a bounded lifecycle with an owner and cleanup path. If any fact is absent, the correct outcome is *not available on this target*, not a broader privilege grant or a guessed substitute hook.
]

The repository’s flake declares only `x86_64-linux`, imports a locked Nixpkgs plus Rust overlay, and exposes a development shell, non-privileged checks, a NixOS module, and a VM audit. The shell includes Rust with `rust-src`, `rustfmt`, and Clippy; `bpf-linker`; `bpftool` from the plural Nix attribute `bpftools`; Clang, LLVM, LLD, libbpf, pahole, `just`, Typst, D2, ShellCheck, Python, Curl, and Git. It also sets `BPF_CLANG`, `BPFTOOL`, and `RUST_BACKTRACE`. The source lock identifies the package universe; the workspace’s `rust-toolchain.toml` and `xtask` choose the Rust toolchain expected for its eBPF build. Preserve both records when reproducing a result.

#figure(
  image("../../assets/diagrams/generated/02-lab-prereqs.svg", width: 100%),
  caption: [A successful lab is a flow of evidence: the pinned flake feeds read-only probing; the probe inspects the kernel, mounts, and authority; only a supported, isolated target may proceed to an audit-first sample. The repository contains this generated chapter diagram as `02-lab-prereqs.svg`; no file named `lab-dependency-flow.svg` is present.],
) <fig-lab-dependency-flow>

The diagram in #figure-ref(<fig-lab-dependency-flow>, title: [lab dependency flow]) has a deliberate red exit. It represents a failure mode worth preserving: a report that says a prerequisite is absent is much safer than a program that silently attaches somewhere else, changes a sysctl, or asks for sweeping administration authority. Keep that exit in your own automation.

A practical preflight record includes the Git revision, `flake.lock` revision, `Cargo.lock`, Rust version, and BPF object hash after a build. It also includes `uname -r`, `uname -m`, NixOS generation, the realized kernel package version when relevant, mount information, event files, effective service identity, and the unedited load error if a future experiment fails. This separates a documented interface from a fact observed under one identity on one booted target.

== 2. Separate the kernel facilities before relying on them <sec-ch02-kernel-facilities>

The names BTF, bpffs, and tracefs appear together in BPF tutorials, but they solve different problems. Conflating them produces fragile setup scripts. #table-ref(<tbl-ch02-facilities>, title: [kernel facilities and their first-lab roles]) gives the operational distinction.

#figure(
  table(
    columns: (1.2fr, 1.45fr, 1.7fr, 1.45fr),
    inset: 6pt,
    stroke: 0.4pt + rgb("#B8CDD2"),
    fill: (x, y) => if y == 0 { rgb("#E7F6F5") } else { none },
    table.header([Facility], [What it is], [Running-system evidence], [Role in this chapter]),
    [BTF], [Compact type and debug metadata used by the kernel and BPF toolchain. It can carry Compile Once – Run Everywhere (CO-RE) relocation information.], [`/sys/kernel/btf/vmlinux` is readable and nonempty.], [Useful to record; *not* required by `00-lab-check` or the payload-free first counter.],
    [bpffs], [A virtual BPF filesystem that can hold a named reference to a map, program, or BPF link.], [`findmnt -T /sys/fs/bpf`; inspect, do not mount from the application.], [Diagnostic only here. No introductory sample should pin an object.],
    [tracefs], [The tracing filesystem exposing static events, their IDs, and their target-local `format` descriptions.], [`findmnt -T /sys/kernel/tracing`; inspect `events/sched/sched_switch/id` and `format`.], [Required later for the selected tracepoint; learn its location now.],
    [cgroup v2], [The unified control-group hierarchy for resource control and scoped BPF attachment in later lessons.], [`findmnt -t cgroup2`, plus the intended mount and delegation context.], [Record separately. Seeing `cgroup2` in `/proc/filesystems` does not prove that the desired hierarchy is mounted or delegated.],
  ),
  caption: [Distinct kernel facilities, evidence, and the deliberately narrow initial role of each.],
) <tbl-ch02-facilities>

*BTF is metadata, not a privilege bypass.* It is compact type information associated with kernel and BPF objects. On kernels that provide base BTF, `/sys/kernel/btf/vmlinux` is the local source for inspection tools and BTF-aware loading. CO-RE can use eligible object and target metadata to adapt selected type accesses; it cannot create a missing trace event, helper, program type, permission, or semantic guarantee. The `libbpf` CO-RE documentation is explicit about the BTF-driven portability mechanism, not a promise that every object runs everywhere. #cite(<libbpf-core>) The first counter should ignore the tracepoint payload, so it has no need to turn BTF absence into an artificial blocker.

*bpffs is lifecycle state.* A pin gives a BPF object a pathname and keeps a reference after the original file descriptor closes. Deleting a pin releases only that reference; an attachment, another file descriptor, or another reference may still keep the object alive. That is a useful production mechanism only when ownership, schema compatibility, upgrades, expiry, rollback, and removal have been designed. In this lab, it is an exclusion: do not write under `/sys/fs/bpf` for `00-lab-check` or the first short observation. An empty bpffs directory is not an invitation to use it.

*tracefs is a discovery and decoding contract.* Static tracepoints are named event sites exposed under `/sys/kernel/tracing/events` on typical systems, with a legacy `/sys/kernel/debug/tracing` location still encountered. An event’s `id` participates in attachment; its `format` gives common fields and event-specific offsets and sizes. The layout is local evidence, not a blanket stable application binary interface (ABI). Before a later program reads context bytes, save the target’s `id` and `format` with the kernel metadata. A baseline counter observes only event occurrence and intentionally does not decode either file.

*cgroup v2 is scope, not a container name.* It groups processes for kernel resource control and underpins later cgroup-attached programs. A cgroup pathname can move and can look different inside a cgroup namespace, so it is not durable container identity. The cgroup v2 documentation describes hierarchy and delegation rules; later policy work must inspect the actual mounted hierarchy and membership, not infer scope from a package installation. #cite(<cgroups-v2>) This chapter only checks that the system can name cgroup v2 as a filesystem type; that is weaker than proving a usable attachment scope.

#kernel-detail(title: [Configuration requests are not runtime facts])[
  The opt-in module `nix/nixos-ebpf-lab.nix` requests `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_BPF_EVENTS`, debug BTF, securityfs, and BPF LSM support through `boot.kernelPatches` and `structuredExtraConfig`. It selects `linuxPackages_latest` by default, disables unprivileged BPF, and makes an LSM order containing `bpf` explicit. These are intended only for a disposable lab VM. A successful evaluation or build still does not prove the booted kernel, mounts, event, capability context, or later hook accepts an object.
]

The current module also asserts `x86_64-linux` and a kernel at least 5.7. Regard the version assertion as a narrow historical clue related to BPF LSM availability, not as a general eBPF readiness test and not as a prerequisite for `00-lab-check`. For BPF LSM later, compiled `CONFIG_BPF_LSM=y`, readable BTF, an active `bpf` entry in `/sys/kernel/security/lsm`, a supported hook, permitted authority, and a recovery-capable VM are all independent conditions. The BPF LSM documentation frames these programs as privileged tools for system-wide mandatory access control and audit policy. #cite(<bpf-lsm>)

== 3. Authority: least broad, operation by operation <sec-ch02-authority>

Linux capabilities split portions of traditional superuser authority into independently checked permissions. For contemporary BPF work, `CAP_BPF` governs relevant BPF operations and `CAP_PERFMON` is the performance-monitoring capability. Tracepoint work commonly interacts with both BPF loading and performance-event authorization. `CAP_SYS_ADMIN` remains broader compatibility authority, but it is not a responsible default simply because it may make an experiment succeed. The capability model is defined by Linux and further constrained by namespaces, security modules, perf policy, and the selected operation. #cite(<capabilities>)

The right question is not “am I root?” but “which operation will the intended service perform under which policy context?” The current sample runner makes a conservative implementation choice for kernel-facing subcommands: its `require_root()` checks only whether the effective user identifier is zero, even though its error message mentions root *or equivalent* `CAP_BPF`/`CAP_PERFMON`. That gate is a runner limitation, not proof that UID 0 is universally required. By contrast, `lab-check` has no root gate at all.

Do not compensate for a failed attachment by changing `kernel.unprivileged_bpf_disabled`, lowering `perf_event_paranoid`, setting an unlimited memory lock limit, adding capabilities to Cargo or a general-purpose shell, or granting `CAP_SYS_ADMIN` broadly. Those changes blur the cause of failure and enlarge a host’s attack surface. Build as an ordinary user. In a disposable VM, run only the reviewed loader under the narrowly chosen authority after preflight demonstrates that authority is the remaining condition. If no bounded authority design exists, leave the feature unavailable.

A single-element counter has modest resource needs. Older kernels may account BPF resources through `RLIMIT_MEMLOCK`, while newer systems can use memory cgroups. Do not set an infinite limit preemptively; record the exact error and target first. Similarly, a privileged `bpftool feature probe kernel` can be valuable evidence but is not the same as loading this repository’s object and may itself need BPF-related authority.

#security-note(title: [Audit is the default; denial is explicitly opt-in])[
  This chapter authorizes no enforcement experiment. Any later denial-capable BPF LSM work belongs only in a disposable, recovery-capable VM and must begin in audit mode. Opt-in denial must be narrowly bounded to a disposable cgroup or VM, use a reviewed identity and rollback procedure, and be independently observable. Telemetry loss or a failed lookup must never become a reason to deny. Never trial a broad BPF LSM rule, a global pathname rule, or an automatic policy loader on a workstation or production host.
]

This is not merely a conservative style preference. An LSM can participate in security decisions made throughout the system. Even the repository module changes LSM ordering only when explicitly enabled and comments that it belongs in a disposable VM. No early sample needs that configuration: the lab check is read-only, and the pedagogical baseline tracepoint counter does not need BTF, bpffs, or BPF LSM.

== 4. The primary sample: `00-lab-check` <sec-ch02-lab-check>

The primary sample establishes the safest possible starting tier: inspect the environment without asking the kernel to verify, load, or attach eBPF bytecode. Its manifest declares `programs = "none"`, which is a useful proof obligation in review: a command named as an eBPF sample does not necessarily contain a BPF program.

#code-file(
  "../../samples/00-lab-check/sample.toml",
  title: [Canonical `00-lab-check` manifest],
  language: "toml",
  source-path: "samples/00-lab-check/sample.toml",
) <lst-ch02-lab-manifest>

As #listing-ref(<lst-ch02-lab-manifest>, title: [the lab-check manifest]) shows, the runner is `sample-runner`; the sample directory itself does not supply an eBPF object. The canonical sample README records its intended read-only behavior, build route, invocation, expected output category, unprivileged negative control, and no-op cleanup. The runner implementation is the underlying source of record; it reads an operating-system release string, tests selected paths or text files, looks for the literal `bpf` in the runtime LSM list when readable, and prints an effective-user-ID status. It performs no BPF system call.

#code-file(
  "../../samples/00-lab-check/README.md",
  title: [Canonical `00-lab-check` operational README],
  language: "markdown",
  source-path: "samples/00-lab-check/README.md",
) <lst-ch02-lab-check-implementation>

The important discipline is to interpret these checks at their actual strength. The `Linux` row is a compile-target condition plus the kernel release string; it does not validate a BPF program type. `kernel BTF` asks whether the BTF path is a regular file, not whether it is readable or suitable for a particular CO-RE object. `BPF LSM active` reads `/sys/kernel/security/lsm` when securityfs exposes it, then looks for `bpf`; it says neither that a hook is available nor that an LSM object can load. The `cgroup v2` row searches `/proc/filesystems`, so it reports filesystem support rather than a mounted and delegated target cgroup. The `bpffs` and `tracefs` rows test directories rather than a mount type, permissions, event ID, or event format. Finally, `effective root` tests only effective UID zero, not ambient, permitted, inheritable, bounding, or file capabilities.

This narrowness is a virtue. It prevents a preflight tool from claiming capabilities it never tested. The README correctly states that an unprivileged run still probes and reports `effective root unsupported`; it also states that no verifier step occurs. The source’s final line says compilation is safe and attachment needs the listed features plus BPF privileges. Read “compilation” there as a repository safety posture, not as a proof that every build script or future object is free of operational risk.

== 5. Run the read-only preflight and preserve the evidence <sec-ch02-preflight>

Start by entering the pinned shell and running the sample from the `samples/` workspace. These commands do not load or attach an eBPF program. The first two exercises are intentionally useful on an ordinary development machine; a later runtime-tier command is not.

#terminal-listing(
  title: [Pinned, attachment-free lab preflight],
  "nix develop\njust check\njust kernel-audit\njust smoke\ncd samples\ncargo run -p sample-runner -- lab-check",
) <lst-ch02-preflight-commands>

`just check` parses shell scripts, verifies repository-local Markdown links, parses safe snippets, and evaluates flake outputs without builds. `just kernel-audit` reads available kernel configuration, BTF, architecture, and runtime LSM information. `just smoke` invokes the audit-first smoke harness, which refuses its optional privileged `bpftool feature probe kernel` unless both `--probe` and `--allow-privileged` are supplied. Even that explicit probe does not load or attach a repository program. The commands are concise by design; use #listing-ref(<lst-ch02-preflight-commands>, title: [the read-only preflight]) unchanged before deciding whether to build a VM experiment.

#expected-output(title: [What `00-lab-check` actually promises])[
  The command begins with `learn-eBPF lab feature matrix (read-only)`. It then prints rows labelled `Linux`, `kernel BTF`, `BPF LSM active`, `cgroup v2`, `bpffs`, `tracefs`, and `effective root`, each marked `supported` or `unsupported`, followed by a detail derived from the current system. It ends by stating that compilation is safe and attachment requires the listed kernel features and BPF privileges. Kernel release strings, mounted filesystems, LSM order, and effective UID are environment-gated runtime facts, so this chapter deliberately does not invent a fixed transcript. An `unsupported` row is a useful preflight result.
]

Capture the output together with `uname -a`, `nixos-version`, `nix flake metadata --json` or the checked-in lock revision, the current `Cargo.lock` hash, and the date. For later tracepoint work, add the following target-specific evidence without yet loading an object:

```sh
EVENT=/sys/kernel/tracing/events/sched/sched_switch
findmnt -T /sys/kernel/tracing
findmnt -T /sys/fs/bpf
findmnt -t cgroup2
cat "$EVENT/id"
sed -n '1,160p' "$EVENT/format"
test -r /sys/kernel/btf/vmlinux && stat -c '%s bytes' /sys/kernel/btf/vmlinux
```

The `EVENT` commands are prerequisites for the next baseline design, not a claim that `00-lab-check` currently performs them. That distinction matters: the sample presently reports tracefs directory presence, whereas a tracepoint attachment needs the chosen event’s ID and the format should be saved before any payload decoding. If a command fails, record which condition failed—missing event, inaccessible tracefs, absent BTF, policy denial, or missing tool—rather than repairing all possible conditions at once.

== 6. A reproducible, disposable VM procedure <sec-ch02-disposable-vm>

Use a fresh VM disk or snapshot for each kernel-facing learning session. The repository supplies `checks.x86_64-linux.vm-test`, an isolated NixOS test that enables the lab module, allocates 2 GiB of memory, waits for multi-user mode, and checks readable base BTF, an active `bpf` LSM entry, and a `bpftool btf dump` invocation. It is an *audit VM test*: it does not build, load, verify, or attach a repository eBPF program. Its passing result proves only those audited conditions under the VM configuration.

A safe procedure is as follows.

1. *Freeze inputs and create recovery.* Work from a clean commit and retain `flake.lock`, `Cargo.lock`, and `samples/rust-toolchain.toml`. Build or boot a disposable VM, take a snapshot before enabling the lab module, and ensure you can power it off or revert it without relying on an in-guest policy decision.

2. *Choose the smallest tier.* For this chapter, run the read-only checks only. Do not enable the lab module merely to run `00-lab-check`. The module’s BPF LSM configuration is unnecessary for a no-attachment preflight and expands the VM’s configuration surface.

3. *If a later BTF or LSM lesson truly requires it, enable the module explicitly in that disposable VM.* Review the requested kernel options and the `security.lsm` list. Preserve other LSMs required by the VM image. Rebuild, reboot into the resulting generation, and use `uname -r` plus `/sys/kernel/security/lsm` to confirm the booted outcome. A declarative Nix expression requests a configuration; it does not retroactively change a kernel that is still running.

4. *Run read-only preflight under the future service identity.* An interactive administrator’s shell can hide the capability and namespace restrictions of a service. Record the identity actually intended for a later loader, including effective UID and available capabilities where policy permits inspection. An `euid=0` success in `lab-check` does not establish `CAP_BPF`/`CAP_PERFMON` behavior for a non-root service.

5. *Set an explicit stop condition.* Stop at Tier 0 when the selected event, tracefs access, authorization, or build identity is missing. Do not substitute another tracepoint; do not modify global sysctls; do not pin objects. Escalate only after a subsequent chapter gives a program-specific load, attach, and cleanup plan.

The VM test is run with `just vm-test`, equivalent to building its flake check. Because the shell and test use the locked flake, repeating them at the same commit gives a meaningful configuration baseline. It does not eliminate version-sensitive behavior from the target kernel or make a kernel source snapshot a release guarantee.

== 7. Verifier reasoning begins before verifier execution <sec-ch02-verifier-reasoning>

`00-lab-check` never invokes `BPF_PROG_LOAD`; therefore the kernel verifier does not analyze it. This is an important expected outcome, not missing coverage. The sample belongs to Tier 0: environment audit. The first object-loading exercise belongs to Tier 1 and needs a different evidence chain.

#verifier-note(title: [From preflight to a verifiable first object])[
  A later payload-free tracepoint counter should attach only to locally discovered `sched/sched_switch`, ignore its context, update one per-CPU counter, run for a fixed short duration, read a user-space aggregate, and drop its owning object without pins. The verifier then has a small, auditable proof obligation: the map lookup result must be checked before dereference; the pointer must not survive an invalidating helper boundary; and every return path must be valid. This chapter supplies the event, authority, and cleanup evidence that makes a verifier result interpretable.
]

The verifier proves the kernel’s conservative safety model for actual bytecode under a specific program type. It does not prove that a tracepoint exists, that the event’s meaning is stable across kernels, that the measurement answers a performance question, that output is lossless, or that the service identity is authorized. The kernel’s verifier documentation explains why it tracks pointer state, initialized memory, helper contracts, and reachable paths; an accepted program should be reported as “accepted by this target verifier,” not “bug-free.” #cite(<bpf-verifier>)

For the next tracepoint counter, `sched/sched_switch` should be discovered through tracefs before use. Its `format` should be captured even though the counter will not read its payload. That practice prevents a later tutorial offset from quietly entering the first sample. A static tracepoint is easier to discover than an arbitrary probe location, but it is not a universal stable ABI; the BPF design guidance cautions against treating tracepoints as such. #cite(<bpf-design-q-and-a>)

== 8. Portability boundaries and safe decline paths <sec-ch02-portability>

The lab is NixOS-first, not NixOS-universal. A custom `boot.kernelPackages`, a minimized image, a hardened kernel, a different architecture, an older guest kernel supplied by a hypervisor, a container, or a changed Nixpkgs revision can alter the outcome. Nix can reproduce declared package inputs and a machine configuration; it cannot guarantee that every external target shares them.

The flake itself only exposes `x86_64-linux`. This restriction is deliberate. Do not remove it by editing an assertion and then represent a successful evaluation as portability. Instead, create a separate target matrix that records architecture, booted kernel, kernel configuration evidence or “unavailable,” BTF state, tracefs event fixture, authority context, object hash, and final load/attach/detach result. An absent BTF file is compatible with the audit sample and baseline counter, but it must disable BTF-dependent and BPF-LSM tiers clearly.

There is also a source-versus-release boundary. The lab module uses the documented `structuredExtraConfig` spelling. Current kernel and Nixpkgs defaults can guide exploration, but the booted VM is the source of record for whether an option, mount, LSM order, or tracepoint is present. Likewise, the sample workspace pins Aya 0.14.0, `aya-ebpf` 0.2.1, and a Rust toolchain declaration; do not replace these with floating web documentation or a different host compiler and call the result equivalent. The Aya Book is useful for the Rust/Aya build model, while the local lockfiles establish this repository’s concrete dependency identity. #cite(<aya-book>)

A final portability issue is lifecycle. A normal process exit is not magic deletion: BPF objects persist as long as references such as file descriptors, attachments, or pins exist. The easy rule for this chapter is more conservative: do not create such objects at all. In later chapters, make the owner and removal behavior explicit. A bpffs path is persistence, not cleanup.

== 9. Cleanup and incident-safe stopping <sec-ch02-cleanup>

For `00-lab-check`, cleanup is intentionally none: the command reads pseudo-files and exits. Confirm that the command did not invoke a `run` subcommand, did not create `/sys/fs/bpf` entries, and did not alter sysctls or mounts. The sample README makes the same no-mutation claim.

For the surrounding lab session, leave the VM in a known state. Save the preflight report outside the VM if it will be reverted. Exit the development shell, shut down the guest, and revert to the snapshot if you enabled a test-only kernel or LSM configuration. If a future privileged loader has been executed, stop it first, verify that it owns no intentional pins, and follow that chapter’s detach and rollback procedure before reverting. Do not use a reboot as evidence of correct cleanup; it is recovery, not a lifecycle test.

If a preflight identifies an unsupported condition, your cleanup is even simpler: preserve the record, make no system-wide adjustment, and stop. A reproducible refusal is better engineering than an accidental success obtained by weakening an unrelated control.

== Exercises <sec-ch02-exercises>

#exercise(title: [Build a preflight dossier])[
  In a disposable VM, run the commands in #listing-ref(<lst-ch02-preflight-commands>, title: [the preflight listing]). Record the Git revision, `flake.lock` revision, `uname -r`, architecture, BTF-file status, LSM-list status, and complete `lab-check` output. For each unsupported row, classify it as absent, inaccessible, unknown, or not required for Tier 0. Do not change any configuration.
]

#exercise(title: [Compare an ordinary-user report])[
  Run only `cargo run -p sample-runner -- lab-check` as an ordinary user and compare it with a run from an administrator context if your disposable VM policy permits one. Explain why a different `effective root` row does not prove the exact capability set needed for a future tracepoint loader. Confirm that both runs remain attachment-free by reading #listing-ref(<lst-ch02-lab-check-implementation>, title: [the implementation]).
]

#exercise(title: [Inspect, do not decode])[
  On a target where tracefs exposes `sched/sched_switch`, save its `id` and `format` as test evidence. Identify the common fields and event-specific fields, but write no code that accesses an offset. State why the future payload-free counter can proceed without making a layout claim and why a later decoder must be target-gated.
]

#exercise(title: [Design the refusal])[
  Write a one-paragraph runbook for the case where BTF is missing. It must say which exercises remain available (Tier 0 and the BTF-free counter once its own tracepoint and authority checks pass), which later exercises do not, what evidence to capture, and which tempting changes are forbidden. Include no command that alters `unprivileged_bpf_disabled`, `perf_event_paranoid`, or a global capability assignment.
]

== Chapter summary <sec-ch02-summary>

A safe NixOS eBPF laboratory is a verified arrangement of inputs and runtime facts, not a command that happens to install `bpftool`. The flake and lockfiles preserve a reviewable tool universe; the booted kernel, mounted filesystems, target event, policy context, and service identity determine whether a later object can run. BTF supplies type metadata, bpffs supplies optional named references, tracefs supplies event discovery and local format evidence, and cgroup v2 supplies later scope—not interchangeable “BPF setup.”

The `00-lab-check` sample is deliberately modest. Its canonical manifest declares no program, and its runner reports only read-only, coarse prerequisites. It does not engage the verifier, prove a cgroup mount or capability set, inspect a particular event, or load an object. That restraint makes it safe to run early and makes its `unsupported` results honest. Preserve them rather than tuning around them.

For every later kernel-facing step, use the same order: pin and record the build, boot an isolated target, preflight the exact interface and authority, run one bounded audit-first experiment, preserve raw diagnostics, and perform explicit cleanup. Enforcement is never the default: it is a separate, opt-in activity with a disposable cgroup or VM, recovery, audit evidence, and a rollback plan.

== Next steps <sec-ch02-next-steps>

Continue with #chapter-ref(<ch-03>, title: [The First Event]) only after this chapter’s Tier 0 record is complete for the target VM. The next exercise connects the environment contract to a small object contract: program type before syntax, context before field access, return convention before attachment, and ownership before teardown.
