#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref, definition-target
#import "../../components/terms.typ": acronym

// Keep excerpts canonical: `read` imports the sample file and slices it only for display.
#let source-file(path, title, language: "text", lines: none) = {
  let source = read(path)
  let selected = if lines == none {
    source
  } else {
    let all = source.split("\n")
    all.slice(lines.first() - 1, lines.last()).join("\n")
  }
  code-listing(title, selected, language: language, source-path: path)
}

#chapter-opener(part: "V", chapter: "15")
= BTF and CO-RE in Practice <ch-15>

A kernel type is not a promise that its byte layout will remain fixed. This chapter turns that fact into a practical method for writing a small, observable eBPF program that can adapt a *supported* structure access to the kernel it meets. The method is useful precisely because it has boundaries: it reconciles type layout, not hooks, privileges, policy, or meaning.

== Prerequisites <ch15-prerequisites>

Before proceeding, be comfortable with the eBPF load/attach lifecycle, the idea that the verifier proves every reachable path, and an audit-only tracepoint program. You need an isolated Linux virtual machine (VM) or similarly disposable lab, the repository's pinned development environment, and the ability to inspect—but not alter—the running kernel. The worked sample needs a readable `/sys/kernel/btf/vmlinux`, the `sched_process_fork` BTF tracepoint, an eBPF-capable toolchain, and the runner's current effective-root gate. A successful build or a kernel-version string is not a substitute for those observations.

== Learning objectives <ch15-objectives>

After this chapter, you should be able to explain the distinct roles of local and target BPF Type Format (BTF) metadata; locate BTF and Compile Once—Run Everywhere (CO-RE) relocation data in an Executable and Linkable Format (ELF) object; distinguish field, type, and enum relocation questions; inspect an object without attaching it; and design an explicit BTF-present/BTF-absent capability decision. You should also be able to recognize why a `task_struct` access remains a target-dependent observation even after relocation, and why a verifier acceptance result is necessary but not a portability certificate.

== The mental model: an object asks a target a typed question <ch15-mental-model>

#definition-target("ch15-btf-definition", "BPF Type Format (BTF)")[BTF is compact type metadata carried by BPF objects and, on suitably configured Linux systems, exposed for the running kernel. It gives a loader a graph of names, kinds, members, and layout-related information rather than a collection of unlabelled byte offsets.]

#definition-target("ch15-core-definition", "Compile Once—Run Everywhere (CO-RE)")[CO-RE is a loader-time reconciliation process. The object describes the type access it was compiled to express; the loader compares that local description with the target kernel's BTF and adjusts eligible instruction constants before the program is loaded.]

Think of a source access such as `task_struct.pid` as a question, not as the number of bytes from a task pointer. At build time, the compiler associates the access with a *local* type graph: the kernel types against which the eBPF object was compiled. It places local BTF in the object and, for an eligible CO-RE-aware access, records relocation information. At deployment, the loader reads *target* BTF from the booted kernel, commonly `/sys/kernel/btf/vmlinux`, matches the relevant type and member, and writes a target-correct offset or immediate into the BPF instructions. The instruction stream that reaches the verifier therefore reflects the target layout rather than a build-host layout. CO-RE is a portability technique for BTF-described accesses, not a claim that one binary is compatible with every Linux system. @libbpf-core

#concept(title: "Two type graphs, one intended access")[Local BTF says what the object meant when it was built. Target BTF says what this running kernel exposes now. A local type ID is an index in the object's BTF; it is *not* a target-kernel type ID and must never be compared as though the two numbering spaces were shared. The loader performs the match.]

#figure(
  image("../../assets/diagrams/generated/15-core-relocation.svg", width: 100%),
  caption: [A CO-RE relocation begins with local intent and ends in a target-specific instruction constant. The failure branch is a design decision: select a reduced feature or stop, rather than guess an offset.],
) <fig-core-relocation>

#figure-ref(<fig-core-relocation>, title: "CO-RE relocation flow") makes the separation visible. The source access and local BTF become an ELF-side record. The loader queries the target BTF. A compatible match yields a patched instruction; an incompatible type or missing field must lead to a known fallback. Notice what is absent from the diagram: a tracepoint attachment, a helper allow-list, credentials, and runtime semantics. None is encoded by a member offset.

== What BTF actually contributes <ch15-btf-encoding>

BTF is deliberately compact. Its `.BTF` ELF section has a header followed by type records and a string table. A type record has a kind—such as integer, pointer, array, structure, union, enumeration, function prototype, or variable—and kind-specific payload. Structure and union records describe members by referring to names in the string table and to other type IDs. Type IDs index the local graph, which allows a compiler, loader, or tool to follow `task_struct` to a member such as `pid` without treating source spelling alone as a layout guarantee. BTF also supports typed map and program metadata, source-oriented diagnostics, and tool inspection; it is not merely a CO-RE sidecar. @libbpf-core

The companion `.BTF.ext` section is related but distinct. It carries extensible subsections for function information, line information, and CO-RE relocation information. Function and line records improve attribution of BPF instructions. CO-RE records tell a loader which *instruction* needs a target-dependent constant. Consequently, seeing `.BTF` in an object proves that type metadata exists, while seeing `.BTF.ext` proves that extended metadata exists; neither observation alone proves that the selected target can resolve every relocation.

#kernel-detail(title: "Record shape and patch site")[In the current CO-RE record model, a relocation identifies an instruction offset, a root local BTF type ID, an access-string offset into the BTF string table, and a relocation kind. The surrounding `.BTF.ext` information is grouped by program section. A field relocation normally changes an instruction's offset; type and enum queries normally change an instruction immediate. The loader must not treat a CO-RE relocation as an ordinary ELF symbol relocation or patch a jump target.]

An access string describes a path through the local type graph. The exact compact encoding and the relocation-kind set are toolchain interfaces, so they should be inspected on the object produced by the pinned compiler rather than reverse-engineered from a tutorial. The useful design conclusion is stable: a relocation is evidence that the compiler emitted a target question. A handwritten Rust structure with a field access is not, by itself, evidence that such a question exists.

=== Local bindings are intent, not a portable copy of the kernel <ch15-local-bindings>

Rust eBPF projects commonly use generated `vmlinux` bindings to make a kernel type name and member available to source code. `#[repr(C)]` describes the Rust representation expected at the source boundary; it does not turn a checked-in approximation into a durable copy of kernel internals. The local declaration must correspond to the BTF and relocation workflow that emitted the object, and the resulting object must be inspected. In particular, padding arrays used to skip a changing prefix of a kernel structure deserve suspicion: they encode an assumption that only a validated relocation pipeline can safely neutralize.

The checked-in `vmlinux.rs` is visibly quarantined and contains hand-maintained filler arrays before `pid`; it is not compiled into the default object. The repository supplies `scripts/generate-target-bindings.sh`, which pins an `aya-tool` revision, generates selected types from the booted kernel's `/sys/kernel/btf/vmlinux`, and records BTF and output digests. Generation is necessary evidence, not a portability certificate: inspect `.BTF.ext`, retain the manifest, and test both BTF-present and BTF-absent targets.

== The primary sample: one typed process observation <ch15-primary-sample>

The `06-core-process-inspector` sample declares a BTF tracepoint program for `sched_process_fork`. It obtains argument 1 as a pointer to `task_struct`, asks `bpf_probe_read_kernel` to read that task's `pid`, and emits the value as a process event. The common event constructor supplies other audit metadata, but the sample-specific payload is the child PID stored in `value`. It does not reconstruct a pathname, maintain a process inventory, infer container identity, or deny an operation. The runner loads the program as `BtfTracePoint`, supplies BTF read from sysfs, and attaches only after loading succeeds.

#source-file(
  "../../../samples/ebpf-programs/src/main.rs",
  "Audit-only BTF tracepoint program",
  language: "rust",
  lines: (104, 110),
) <lst-core-program>

#source-file(
  "../../../samples/runner/src/main.rs",
  "Runner path for the CO-RE process inspector",
  language: "rust",
  lines: (270, 278),
) <lst-core-runner>

#listing-ref(<lst-core-program>, title: "the eBPF program") is intentionally short. The important operation is not the Rust `unsafe` token; it is the combined kernel contract. The BTF tracepoint context gives the program a typed argument according to the target's BTF-described tracepoint prototype. The helper receives an address in kernel memory and returns an error that the sample turns into zero. The program then emits its fixed in-host event record and returns zero. In this particular tracepoint program, zero is its normal return value; do not transfer that convention to a different program type without checking that type's return contract.

#listing-ref(<lst-core-runner>, title: "the runner attachment path") exposes the runtime gate. `Btf::from_sys_fs()` must obtain target BTF. `p.load("sched_process_fork", &btf)` must resolve the target's typed tracepoint and the object's BTF requirements before `p.attach()` occurs. The code does not select another object when BTF is absent and does not attempt an untyped attachment. It will therefore fail rather than silently degrading—honest behavior for a specimen, but not the full tiered product design taught later in this chapter.

=== What the verifier can and cannot establish <ch15-verifier-reasoning>

The verifier reasons over abstract states: possible register types, scalar ranges, pointer provenance, stack initialization, helper prototypes, and all feasible paths. It does not execute this program once and trust the observed fork. For the sample, the relevant proof questions include whether `ctx.arg(1)` yields a context-permitted pointer category; whether the helper is allowed for this program type; whether its pointer argument has an acceptable provenance; whether the event path supplies initialized bytes to the ring buffer; and whether every exit returns a defined value. Verifier acceptance is evidence that the final, relocated instruction stream met those safety rules on that target. @bpf-verifier

#verifier-note(title: "Relocation precedes the proof you care about")[The verifier checks the program after the loader has selected and applied target-specific relocation values. A build-host offset that looked plausible is irrelevant if the target relocation cannot be resolved. Conversely, a verifier-accepted `pid` read does not prove that `pid` is the right application-level identity, that every child event is delivered, or that the tracepoint exists on another kernel.]

The helper call is a state boundary. Under the BPF calling convention, caller-saved argument registers may no longer retain usable values after a helper, while the return register becomes the helper's documented result. A failure branch represented by `unwrap_or(0)` avoids dereferencing a nonexistent value, but it makes the observed value `0` ambiguous: it can mean a helper read failed or that the supplied fallback was used. The code does not export a separate failure counter. That limitation matters when reading results; absence of an error line is not a guarantee of complete observations.

The event emission path deserves equally careful reading. `emit` reserves a ring-buffer slot; if reservation fails, it increments a per-CPU drop counter. The repaired runner reports the summed producer reservation failures and consumer parse rejections after draining. Those counters make transport health visible without making the stream lossless: the ring remains bounded, and producer failure is a loss condition rather than a reason to retry or block in eBPF. @bpf-ringbuf

== Field, type, and enum relocation questions <ch15-relocation-kinds>

The word “relocation” hides several different questions. #table-ref(<tbl-core-questions>, title: "CO-RE questions") separates them because their safe fallbacks differ.

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (1.08fr, 1.46fr, 1.7fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header(
      [*Question family*], [*What the loader can derive from target BTF*], [*Safe design response*],
    ),
    [Field], [Byte offset, byte size, existence, signedness, and bitfield-related shift facts for a path such as `task_struct.pid`.], [Read only after a successful required-field relocation. For an optional member, arrange a relocation-backed existence test and a reduced path that never touches the absent field.],
    [Type], [Whether a named local type matches or exists on the target, plus size and target-type information where the relocation kind requests it.], [Limit the feature to a compatible type family. Do not reinterpret an unrelated target structure merely because a name is similar.],
    [Enum], [Whether an enumerator exists and, when it does, the target value of that enumerator.], [Use a relocation-backed availability decision for optional behavior; never hard-code a new enum value into an older target's instruction stream.],
    [Outside CO-RE], [Nothing about hook availability, helper permission, credentials, event layout, or semantic lifetime.], [Probe and test those contracts separately; choose a baseline or unavailable tier if they do not hold.],
  ),
  caption: [CO-RE relocation questions and the distinct design response each demands.],
) <tbl-core-questions>

A field-byte-offset relocation is the familiar case. Suppose a task member moves because scheduler state, optional configuration, or alignment changes earlier in `task_struct`. The loader finds the matching member in target BTF and patches the BPF memory-access offset. Field size and signedness relocations can similarly let generated code adapt how it handles a member. Bitfields require extra care because a correct byte offset alone is insufficient; shifts and width govern which bits are meaningful. None of those mechanics licenses a source program to take arbitrary kernel pointers or to ignore helper error returns.

An optional field is different from a required field. A required-field relocation can reasonably make the enriched object fail its load when the target lacks the member. For an optional field, source and compiler support must emit an existence relocation, and the code structure must use its relocated result to keep the memory access unreachable when the field does not exist. An unconditional read followed by an `if` in user space is not a fallback: the loader and verifier must process the invalid access first. This is why optionality belongs in the eBPF control flow and in the object inspection plan, not only in a README.

Enum relocation answers a scalar question rather than a memory-offset question. A target can add, omit, or assign a different value to an enumerator. CO-RE can patch an eligible immediate or report availability, allowing a program to gate a small feature on the target's enum facts. It does not mean the surrounding subsystem has identical behavior. A newly present action value might be syntactically usable yet interact differently with a driver, program type, or policy configuration. Test the behavior that matters.

== `task_struct` drift: layout is only half the risk <ch15-task-struct-drift>

`task_struct` is an internal kernel structure, not a stable user-space Application Binary Interface (ABI). Its member order, padding, nesting, configuration-dependent content, and relationships can drift between build and target kernels. A fixed numeric offset can therefore read unrelated bytes. CO-RE is valuable because it makes a supported `pid` member access express the local intent and have the loader select the target offset. It does *not* make every hand-written local declaration correct, guarantee that the target BTF exposes a compatible type, or establish that retaining a task pointer would be safe. Keep the access narrow, copy a scalar promptly through the supported helper, and avoid exporting raw kernel pointers.

The sample illustrates both the value and the boundary. It has a local `task_struct` declaration, a single scalar member read, and a target BTF tracepoint load. That is a far better shape than embedding a raw byte offset in the handler. Yet the checked-in binding uses a manually maintained representation, and the repository has not recorded a successful BTF relocation matrix or verifier log for it. The strongest honest claim today is: *the code is intended to request `task_struct.pid` through Aya's BTF tracepoint path.* It is not evidence that the object has loaded on a particular release, architecture, or service identity.

Tracepoints add another independent contract. Upstream does not make a blanket promise that tracepoints are a stable ABI. A typed BTF tracepoint is less dependent on a raw context offset than `TracePointContext::read_at`, but the named function prototype, its arguments, and the event's semantics remain target facts. Validate `sched_process_fork` and its BTF description on every supported target; do not say that a BTF relocation made the hook permanent. @bpf-design-q-and-a

== Object inspection: establish evidence before attachment <ch15-object-inspection>

Inspection should answer modest, concrete questions. Did the ordinary-user build create the expected object? Does it contain `.BTF` and `.BTF.ext`? Can target BTF be read? Does the target BTF mention the intended tracepoint? What is the post-load verifier result on the disposable VM? No inspection command can replace the last question, but it can make the eventual failure diagnosable.

#terminal-listing(
  "# Run in a disposable worktree on the exact target VM.\nnix develop\n./scripts/generate-target-bindings.sh --install-tool\ncd samples\ncargo xtask build-ebpf --target-btf\ncargo build -p sample-runner\nOBJECT=target/ebpf/samples-ebpf-target-btf\nreadelf -SW \"$OBJECT\" | grep -E '\\.BTF(\\.ext)?'\nreadelf -x .BTF.ext \"$OBJECT\" | sed -n '1,80p'\nsha256sum \"$OBJECT\"\ntest -r /sys/kernel/btf/vmlinux && echo 'target BTF is readable'\nbpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -F 'sched_process_fork' | head -n 5",
  title: "Build and inspect without attaching",
) <lst-core-inspection>

The generator and build run as an ordinary user. The target-BTF mode writes `target/ebpf/samples-ebpf-target-btf` separately from the default object. The `readelf` section listing verifies section presence; its hex dump is a low-level existence check, not proof that the specific access relocated correctly. Preserve the generated manifest and object digest with the eventual load result.

The target-BTF command is read-only. It can fail because the file is missing, unreadable, or `bpftool` is not available under the intended identity; record which condition occurred. The `grep` result is likewise a discovery aid, not a proof that the runner can load. The reliable artifact set for a supported tier is the object hash, build toolchain and Aya versions, section listing, target kernel release and architecture, BTF readability result, selected tier and reason, and the raw verifier/load diagnostic retained for people rather than parsed as a stable product protocol. The verifier log is deliberately diagnostic text whose wording can evolve. @bpf-verifier

== Capability tiers: BTF-present is not the only state <ch15-portability-tiers>

A robust observer makes an explicit decision before it asks the kernel to load a layout-dependent object. #table-ref(<tbl-core-tiers>, title: "capability tiers") presents a minimal model. The current primary sample implements only the first row's object shape and fails if its BTF prerequisite is absent; the other rows are a design that a product must implement with distinct, tested artifacts or a clear inactive state.

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (0.72fr, 1.34fr, 1.56fr, 1.35fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header(
      [*Tier*], [*Required facts*], [*Permitted behavior*], [*Observable decision*],
    ),
    [A — enriched CO-RE], [Readable target BTF; required type/member relocation resolves; selected BTF tracepoint and helper can load and attach under the service identity.], [Read the specifically reviewed kernel scalar and emit bounded audit telemetry.], [Report `core` and record a reason if later declined.],
    [B — baseline eBPF], [Selected event/program/helper contract loads, but no object requires target-BTF structure traversal.], [Emit a smaller fixed record using only the validated context or helper values.], [Report `baseline`; never reuse the failed CO-RE object.],
    [C — user-space observation], [The product has a separately designed, authorized OS-facing data source.], [Offer reduced, documented coverage without pretending to see kernel events.], [Report `userspace` and the coverage boundary.],
    [D — unavailable], [No safe supported observation path.], [Do not attach and do not fabricate health data.], [Report `unavailable` with `no-target-btf`, `event-missing`, `permission-denied`, or another measured reason.],
  ),
  caption: [A capability decision must select an actual artifact and expose the selected tier.],
) <tbl-core-tiers>

A BTF-present check is necessary only for a CO-RE object that requires target BTF; it is not enough. The loader may still be unable to match a type, a needed field may not exist, the BTF tracepoint may be unavailable, the helper may not be allowed for that program type, resource policy may reject the load, or attachment may fail. Conversely, an absent BTF file does not prove that all eBPF is unavailable. A genuinely BTF-free baseline object may still implement a smaller, context-only observation. The baseline must be separately compiled and inspected so it contains no unresolved CO-RE requirement. Aya's tracepoint guidance describes the ordinary load-and-attach flow, but availability remains a fact about the target and its authority context. @aya-book

#portability-note(title: "A fallback is a different contract")[Do not “fall back” by keeping the enriched object and hoping the loader skips its relocations. Select a different object whose source, emitted sections, verifier result, and event schema all support the reduced claim. Export the chosen tier and the downgrade reason once at startup and as a status metric.]

Use `uname -r` and an architecture string as diagnostics, not as capability predicates. Distribution kernels backport or disable facilities independently of their version label. A read-only `bpftool` feature probe can inform an authorized preflight, but the probe must run under conditions comparable to the service. Ultimately, attempt the selected minimal load under the intended identity, preserve the failure category, and stop or choose the designed lower tier. Do not respond to a missing feature by granting broad privileges, disabling kernel safeguards, or retrying indefinitely. @bpf-design-q-and-a

== Safe, reproducible procedure <ch15-procedure>

Run this procedure only in a disposable NixOS VM or equivalent recovery-capable lab. It is audit-oriented: the Chapter 15 program has no denial decision. The repository runner has a conservative effective-user-ID-zero gate, so build as an ordinary user and run only the already-built runner with the narrowly justified lab authority. Do not run Cargo itself through `sudo`.

1. Enter the pinned development environment at the repository root with `nix develop`. Record `uname -r`, `uname -m`, the resolved Rust/Aya toolchain, and whether `/sys/kernel/btf/vmlinux` is readable. Run the inspection listing in #listing-ref(<lst-core-inspection>, title: "the non-attaching inspection sequence"). If BTF is not readable or `sched_process_fork` cannot be found, record `no-target-btf` or `event-missing` and stop. The current sample provides no Tier B object.

2. In a disposable worktree, run `./scripts/generate-target-bindings.sh --install-tool`, then build with `cargo xtask build-ebpf --target-btf` and `cargo build -p sample-runner`. Preserve `vmlinux.rs.manifest`, `target/ebpf/samples-ebpf-target-btf`, its digest, and the `readelf` output. This still validates neither relocation success nor a kernel load.

3. In one terminal, run the reviewed object for a short interval: `sudo ./target/debug/sample-runner run 06-core-process-inspector --object target/ebpf/samples-ebpf-target-btf --target-btf-fixture --duration 10`. In another terminal, create one harmless child process, for example `sh -c 'sleep 0.1 & wait'`. The acknowledgment flag cannot prove that the object matches; it records that you performed the preceding review. Do not use `--enforce`.

4. Preserve the complete loader error if load or attach fails. Classify it conservatively as target BTF/relocation, tracepoint/program type, verifier, permission/policy, or resource failure; do not match an English verifier sentence in automation. A success requires both an attachment message and a relevant event during the interval. Re-run once with no intentional fork/clone workload as the negative control, recognizing that unrelated host activity can still create events in a shared VM.

5. After the interval, let the runner exit. It keeps the loaded `Ebpf` object in process scope and its documented timeout/drop behavior detaches the attachment. Confirm no process remains and retain the selected-tier decision. No pin is created by this workflow, so there is no bpffs cleanup path to normalize.

#security-note(title: "Audit first; enforcement is a later, explicit choice")[This chapter neither installs a denial policy nor treats telemetry as enforcement. In the next chapter's Linux Security Module (LSM) work, audit remains the default. A denial-capable path must be explicit opt-in, constrained to a disposable cgroup and recovery-capable VM, and accompanied by a rollback test. A missing BTF feature is never a reason to broaden authority or enable enforcement.]

== Expected output and interpretation <ch15-expected-output>

#expected-output(title: "What this sample can legitimately show")[On a target where the object builds, target BTF is readable, the BTF tracepoint resolves, the verifier accepts the relocated object, attachment succeeds, and a child is created during the ten-second interval, the runner can print an attachment line followed by one or more records shaped as `event kind=4 ... value=<child pid>`. The exact PID, other metadata, number of records, and ordering are target- and workload-dependent.]

The README's quoted event shape is a useful acceptance cue, not a golden transcript. `kind=4` identifies the repository's process event kind; `value` is the child PID read by the sample-specific program. The runner may display unrelated VM activity, and absence does not isolate whether no fork occurred, attachment failed, the helper fallback produced zero, or the ring buffer dropped a record. The final producer/consumer metrics cover this process's observed transport boundaries, not events before attachment or activity the hook never exposed.

An expected failure is also valuable evidence. Missing `/sys/kernel/btf/vmlinux` should fail before attachment; a target without the required BTF tracepoint should fail load; and a verifier or authority failure should leave no successful attachment. Record the command, object identity, target facts, and full diagnostic, then choose Tier B, C, or D only if an independently implemented path exists. Never change the code or configuration until the error disappears and call the result a portability fix without showing what changed in the target contract.

== Cleanup <ch15-cleanup>

This sample's cleanup is intentionally simple. Allow the bounded runner interval to end or interrupt it, then verify the process has exited. The runner's local object ownership is expected to drop the attachment, and the sample README documents timeout/drop detachment. It does not pin programs, maps, or links under the BPF filesystem (bpffs), so do not invent a shared pin path or remove unrelated kernel objects. If a test is interrupted and you have evidence of a remaining attachment, use the lab's approved BPF inspection procedure to identify it by object and program name before removing anything; do not execute broad detach or filesystem deletion commands.

== Exercises <ch15-exercises>

#exercise(title: "1. Separate evidence from inference")[Without loading the object, run the section inspection in #listing-ref(<lst-core-inspection>, title: "the inspection listing"). Write down which conclusion each line supports and which it cannot support. In particular, explain why `.BTF.ext` presence is weaker than a successful relocation result.]

#exercise(title: "2. Design a genuine baseline")[Specify a Tier B process-observation record that uses no `task_struct` traversal. Name its attach type, every field it can collect, the target-local facts it still requires, and its loss counter. Explain how you would prove the baseline object contains no CO-RE relocation dependency.]

#exercise(title: "3. Make optionality verifier-visible")[Sketch the control-flow requirement—not a hard-coded offset—for an optional kernel member. Identify the relocation-backed existence question, the branch that must make the member access unreachable, and the status reason that user space should emit when the feature is absent.]

#exercise(title: "4. Audit the sample claim")[Read the local `task_struct` binding and the two listings in #section-ref(<ch15-primary-sample>, title: "the primary sample"). List three facts the source supports and three that require a VM test or generated-binding evidence. Include ring-buffer loss reporting in your answer.]

== Chapter summary <ch15-summary>

BTF gives an eBPF object and a running kernel typed descriptions in two separate numbering spaces. CO-RE uses a record in `.BTF.ext` to reconcile an eligible local field, type, or enum question with the target BTF and patch the relevant instruction constant before verification. That process is powerful against layout drift, especially for a narrow scalar access such as `task_struct.pid`, but it does not supply an absent target BTF object, tracepoint, helper, privilege, program type, or semantic guarantee.

The `06-core-process-inspector` specimen makes the boundary concrete. Its source intends a BTF tracepoint access to a child's `task_struct.pid`; its runner explicitly loads with target BTF; and its output, if all environment gates pass, can show a child PID in an audit event. The repository has not yet established generated bindings, emitted-relocation evidence, or a BTF-present/BTF-absent test matrix, so it must not be described as a generally portable monitor. Inspect first, attach only in a disposable lab, preserve diagnostics, and expose a deliberate Tier A, B, C, or D decision.

== Next steps <ch15-next-steps>

Continue to #chapter-ref(<ch-16>, title: "BPF LSM fundamentals"). That chapter applies the same BTF and preflight discipline to a security-hook context, where return values can affect access decisions and an audit-first, explicitly opt-in enforcement boundary becomes essential.
