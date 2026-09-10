#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref

#chapter-opener(part: "03", chapter: "07")

= System Calls, Tasks, and the Virtual File System <ch-07>

A file-opening request looks deceptively direct: a process supplies a pathname, the kernel opens a file, and an observer records what happened. Linux actually crosses several distinct contracts in that interval. A user-space call enters an architecture-specific system-call boundary; a task executes with particular credentials; pathname resolution travels through the Virtual File System (VFS); and a filesystem eventually supplies an object. An extended Berkeley Packet Filter (eBPF) program can observe selected points in this path, but it does not turn internal kernel objects into a durable application interface.

This chapter builds a defensible model for observing that path. It introduces a conditional BPF Type Format (BTF) sample, `06-core-process-inspector`, only as a narrow process-creation enrichment. The sample is *not* a portable VFS observer and does not decode a syscall or reconstruct a pathname. Its limitations are useful: they show exactly where a locally discoverable tracepoint ends and a target-tested kernel-type access begins.

== Prerequisites and learning objectives <sec-07-prerequisites>

Before continuing, readers should be comfortable with the load/attach/lifetime separation for an eBPF program, the distinction between maps and event transport, and the verifier’s requirement that every reachable memory access be justified. A disposable Linux virtual machine (VM), a pinned Rust and Aya toolchain, tracefs access, and an approved privilege arrangement are required for the optional runtime procedure. Do not treat a successful ordinary-user build as authority to attach a program. The repository’s continuous integration checks do not load or attach eBPF objects; runtime claims in this chapter are therefore explicitly environment-gated.

By the end of the chapter, you should be able to:

- distinguish a system-call request, a tracepoint record, a task snapshot, and a resolved VFS object;
- explain process identifier (PID), thread-group identifier (TGID), credentials, and an event-time command name without treating any of them as a permanent identity;
- inspect a tracepoint’s local format before decoding it and state why that format is not a stable Application Binary Interface (ABI);
- describe the difference between BTF and Compile Once – Run Everywhere (CO-RE), including what neither mechanism guarantees; and
- run, or deliberately decline to run, the conditional process inspector with a short observation window and a cleanup plan.

== The mental model: one request, several meanings <sec-07-mental-model>

A system call is an interface request from user space to the kernel. On entry, the kernel receives an architecture-defined register state and a syscall number; a raw syscall event may expose a number and machine-width argument slots. Those slots are not a typed Rust function signature. Their interpretation depends on the selected syscall, the calling convention, and the process ABI, especially for compatibility tasks. A pathname argument is also merely a user pointer at entry: it is neither a resolved VFS object nor proof that the later operation succeeds.

A task is the kernel’s schedulable execution context, represented internally by `task_struct`. It has a PID-like identity within a namespace, a TGID for its thread group, a command name, credentials, memory-management links, scheduling state, and much more. `task_struct` is a kernel implementation structure, not a stable record layout for a monitoring product. Use task-related helpers and event fields when they express the required fact. The eBPF verifier proves constrained bytecode properties such as pointer kinds, bounds, initialized stack state, and allowed calls; it does not prove that a chosen internal field has an enduring operational meaning. #cite(<bpf-verifier>)

The VFS is the abstraction layer that gives many filesystems a common file-operation model. During a pathname operation, the kernel resolves components through directory entries (dentries), often reaches an inode that represents filesystem object metadata, and eventually returns or operates on a `struct file` open-file description. These are related objects, not interchangeable names. A requested string can be relative, can include `..`, can traverse a symbolic link, and can be seen through a mount namespace. A dentry is a cached name-to-object relationship; multiple dentries can identify the same inode through hard links. An inode and device pair can be useful in a carefully stated filesystem-specific identity rule, but it is not a universal pathname or policy identity.

#figure(
  image("../../assets/diagrams/generated/07-syscall-vfs-path.svg", width: 100%),
  caption: [A request moves from a process through syscall entry and pathname resolution to VFS objects and a filesystem. Each box represents a different observation contract: a pathname is a request string, while `file` and inode objects are post-resolution kernel objects. The right-hand eBPF notes are design constraints, not promises that one hook exposes all facts.],
) <fig-07-syscall-vfs-path>

#concept(
  title: [Observe a fact at the layer that owns it],
  [For an audit record, record a bounded request string only where a target-validated event exposes one, pair it with an exit result where useful, and label it as a request. For a process fact, take scalar values at event time. For an object fact, use an interface deliberately designed to expose the resolved object. Never turn a raw kernel pointer, a mutable cgroup path, or a requested pathname into a durable identity by assertion.]
)

#figure(
  table(
    columns: (1.15fr, 1.55fr, 1.7fr, 1.95fr),
    inset: 6pt,
    align: (left, left, left, left),
    stroke: 0.35pt + luma(185),
    table.header(
      [Observation layer], [What it can state], [What it cannot establish], [Defensive use]
    ),
    [Syscall entry],
    [A task requested an operation with a number and ABI-specific argument slots.],
    [That a user pointer resolves, that a later result succeeds, or which final object is opened.],
    [Use aggregate accounting first; bound user-string copies only after validating the event and syscall ABI.],
    [Tracepoint record],
    [The fields and offsets exposed by *this* running kernel’s event format.],
    [A stable ABI across releases, configurations, or architectures.],
    [Capture the local `id` and `format` as a fixture; disable a layout-dependent decoder when they differ.],
    [Task snapshot],
    [Current PID/TGID, user identifier (UID), group identifier (GID), command name, cgroup identifier, and timestamp at the hook.],
    [A permanent principal, future credentials, or a reusable kernel pointer.],
    [Emit fixed-width scalars and say “event-time attribution.”],
    [VFS object],
    [A resolved object relationship at an appropriate kernel interface.],
    [The original spelling of a pathname, all aliases, or portable filesystem semantics.],
    [Use later, narrowly scoped audit/policy interfaces; classify filesystem cases and test rename and hard-link behavior.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Observation contracts along the syscall-to-VFS path. The most useful fact is the one that belongs to the selected layer.],
) <tab-07-observation-contract>

#kernel-detail(
  title: [Pointers are temporal capabilities, not event fields],
  [A `task_struct *`, credential pointer, dentry pointer, or file pointer is meaningful only under the access and lifetime rules at the current hook. Storing such a pointer in a map and dereferencing it later converts a momentary access proof into an invalid lifetime assumption. Export scalars or bounded bytes, not kernel addresses.]
)

== Tracepoint records: discover first, decode second <sec-07-tracepoint-abi>

Static tracepoints are attractive because they are named and discoverable through tracefs. They are often less coupled to private function names than a kprobe, but “static” is not “stable ABI.” Kernel BPF documentation explicitly declines to make tracepoint names and record formats a stable ABI. #cite(<bpf-design-q-and-a>) A target’s `available_events`, event `id`, and `format` file are the decoder contract for that target. They must be checked under the same kernel, namespace visibility, and service identity that will attach the program.

This changes the order of work. First, prove that an event exists and archive its format. Next, decide whether an event field is necessary. A payload-free counter needs no offsets at all. If a field is necessary, decode only its documented local width and offset, and retain the fixture with the build and test result. Finally, describe an absent or changed field as a capability downgrade, not an invitation to guess an offset copied from a tutorial.

A raw `syscalls:sys_enter` event is powerful but sharp. Its six argument slots are `unsigned long` in current kernel event definitions, so their width follows the observed ABI. A narrow collector can key a duration map by `{TGID, PID, syscall number}`, record entry time, remove state at exit, and calculate an elapsed interval. It must nevertheless tolerate missed entry or exit records, map insertion failures, nested operations, task exit, and PID reuse. For a first implementation, an aggregate counter or histogram is easier to make honest than an entry/exit correlator.

A string pointer deserves separate caution. A bounded helper read can fail, truncate, or observe data that changes in user memory. Do not read unbounded command lines, environment blocks, or arbitrary paths in an eBPF program. Do not describe a copied entry pathname as the final VFS path. The separation in #figure-ref(<fig-07-syscall-vfs-path>, title: [the syscall–VFS path]) and #table-ref(<tab-07-observation-contract>, title: [the observation contracts]) is the reason: intent, resolution, and result are different facts.

== Tasks, credentials, and process lifecycle <sec-07-tasks-credentials>

A Linux process is not always one schedulable task. A multithreaded process contains tasks that share a TGID while each task has its own PID-like thread identifier in the relevant namespace. The current-task helper convention packs the TGID in the high 32 bits and the task PID in the low 32 bits. Name both fields in an event schema; avoid an unqualified “PID” when your record actually contains the TGID. Capture a monotonic timestamp and the 16-byte command name at the same event. The command name is useful diagnostic context, not an authorization boundary: it can be changed, truncated, and shared by unrelated workloads.

Credentials are similarly a snapshot, not a simple permanent label. Linux represents credentials with a reference-counted `cred` object. Credential changes use a copy-and-replace model coordinated with Read-Copy Update (RCU), so a task’s current effective identity can differ later. Linux also distinguishes real, effective, and filesystem credential notions. An already open file carries credentials captured from its opener; therefore “the UID running now” is not always the credential context behind a later operation through that file. Treat a UID, GID, capability set, cgroup identifier, and command name as evidence collected at one moment, then document the identity domain your user-space analysis actually uses.

The process lifecycle gives clean observational events without walking task lists. A fork or clone creates a child task; an exec changes the program image; exit ends the task. The primary sample uses `sched_process_fork`, a BTF tracepoint associated with the fork lifecycle, rather than a syscall event. That choice is intentional but narrow: it demonstrates a typed context argument and a guarded structural read. It does *not* tell us which `clone`-family syscall created the child, whether a later `execve` succeeded, or what VFS object that child may access.

#code-listing(
  [The conditional BTF tracepoint program],
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(103, 110).join("\n"),
  language: "rust",
  source-path: [samples/ebpf-programs/src/main.rs, lines 104–110],
) <lst-07-btf-program>

#listing-ref(<lst-07-btf-program>, title: [the eBPF program]) receives `BtfTracePointContext`, treats argument 1 as a child `task_struct` pointer, and attempts to read only `pid`. It then emits a fixed `Event` with kind `PROCESS` and places the child PID in `value`. The base event is collected in the *current* task context: its printed `pid` field is populated from the high half of `bpf_get_current_pid_tgid()` and is therefore the parent task’s TGID, while `tid` is the current parent task identifier. Its `uid`, cgroup identifier, and command name likewise describe the current task at the fork event, not the child. These precise semantics are more useful than calling every field “the process ID.”

The ring buffer is bounded. When reservation fails, the eBPF source increments its `DROPPED` per-central-processing-unit counter, but the present runner does not print that counter. The current event record also lacks an explicit record-version or length field; the consumer accepts it by object size. Thus a printed event proves that this consumer observed one record, not that all forks were reported or that the format is a durable wire protocol. This is an audit observation, not complete process accounting.

== The VFS: names, dentries, inodes, and open files <sec-07-vfs-objects>

The VFS portion of the diagram is deliberately more detailed than the sample. It supplies the mental model needed to avoid a common policy mistake: equating the pathname offered by a system call with the object eventually authorized. Path resolution may start from a task’s current working directory or a directory file descriptor, cross mount points, follow symbolic links where permitted, and select a filesystem-specific inode. The dentry cache represents component relationships used by path walking. A `struct file` represents an open instance; its inode describes the underlying object. Several open files can reference an inode, and several directory entries can do so through hard links.

These distinctions matter even for harmless telemetry. Suppose an `openat2` entry event contains `docs/report`. The string has no self-contained meaning without the caller’s working directory and mount namespace. If the path walk follows a symlink, the final object can be elsewhere. If another task renames an ancestor after observation, later rendering of a path can differ. If a file is hard-linked, the same inode may have a second name. Overlay, network, pseudo, and userspace filesystems add further identity and lifetime distinctions. The correct event label is therefore “requested path bytes, bounded and possibly truncated,” not “opened path.”

VFS path walking also uses different modes, including RCU-walk and reference-walk; some operations cannot sleep while in RCU-walk. That is an implementation constraint behind a practical rule: an audit example should not attempt a general in-kernel pathname reconstruction. The primary sample obeys the spirit of that rule by reading no pathname at all. It emits process lifecycle metadata only. Its README’s generic warning mentions pathname reconstruction and an `--enforce` mode, but neither behavior belongs to the `core_process_inspector` program selected in its `sample.toml`. The runner’s `--enforce` switch is used by later Linux Security Module (LSM) samples, not this process inspector.

#security-note(
  title: [Audit is the default; denial is a separate, opt-in design],
  [Do not block `openat` through a kprobe or infer a file policy from a syscall pathname. If a later chapter introduces a VFS-related LSM decision, begin with audit-only output, preserve the pre-existing LSM decision, and test a narrow rule in a disposable recovery-capable VM. Denial must be an explicit opt-in with a verified object identity, scope, rollback, and independent decision logic; telemetry loss must never decide whether access is allowed. BPF LSM programs are privileged policy mechanisms, not a shortcut around those operational requirements. #cite(<bpf-lsm>)]
)

== BTF and CO-RE: useful adaptation, bounded promise <sec-07-btf-core>

BTF is compact type metadata. A CO-RE-aware toolchain can record eligible type and field accesses in an Executable and Linkable Format (ELF) object, compare them with target BTF at load time, and relocate certain accesses. In the best case, that adapts a field offset when an internal structure layout changes. It cannot create missing BTF, a missing hook, an unavailable helper, an accepted program type, sufficient authority, or unchanged semantics. #cite(<libbpf-core>) “Compile once” is a strategy name, not a fleet-wide compatibility guarantee.

The repository calls the binding file used by this sample “minimal aya-tool-style CO-RE bindings,” but inspection shows hand-maintained filler arrays for portions of `task_struct`, `file`, and `inode`. The process inspector’s target field, `task_struct.pid`, sits after such layout material. This is precisely the kind of access that must not be promoted from a local experiment to a general contract. Before claiming CO-RE portability, generate bindings through the tested target-BTF workflow, inspect the emitted `.BTF.ext` relocation information, and load-test the object against every claimed target. A successful source review or a readable BTF file is not that proof.

#code-listing(
  [The user-space BTF load and attach path],
  read("../../../samples/runner/src/main.rs").split("\n").slice(269, 278).join("\n"),
  language: "rust",
  source-path: [samples/runner/src/main.rs, lines 270–278],
) <lst-07-btf-loader>

#listing-ref(<lst-07-btf-loader>, title: [the loader path]) obtains BTF from `/sys/kernel/btf/vmlinux`, selects the named program, passes both `sched_process_fork` and the BTF object to `load`, then attaches. This is concrete runtime behavior, not a portability fallback. If BTF is unreadable, the operation returns an error. There is no BTF-free variant of this sample and no fallback to a generic tracepoint. That makes the appropriate product behavior clear: report the enrichment as unavailable and fall back to an independently designed, event/helper-only observer if one exists; do not disable relocation or fabricate a structure layout.

The verifier reasoning is deliberately local. The typed context contributes a pointer typed as `task_struct`; the source reads one field using `bpf_probe_read_kernel`, handles a failed read with `unwrap_or(0)`, and emits a fully default-initialized event before setting scalar fields. The verifier still sees the final generated instructions, helper availability, pointer provenance, and every branch. Verification does not certify the hand-maintained binding’s semantic correctness, the BTF tracepoint’s availability, or the Rust source’s claimed CO-RE relocation behavior. The kernel verifier’s acceptance is necessary evidence, but the target load is the decisive check. #cite(<bpf-verifier>)

#verifier-note(
  title: [Two proofs are required],
  [First, the BPF verifier must accept the emitted object: the context argument, helper call, stack initialization, map/event operations, and all exits must satisfy the selected program type. Second, the engineering team must prove the data contract: the target has the intended BTF tracepoint, the binding and relocation evidence describe the target layout, and `value` is documented as a sampled child PID. Neither proof substitutes for the other.]
)

== Safe, reproducible procedure <sec-07-procedure>

This procedure is intentionally short and observation-only. Use it only in a disposable Linux VM where tracing is authorized. Build as an ordinary user. The current runner’s `require_root` check accepts only effective user identifier zero, even though modern kernels can split BPF and performance-monitoring authority into capabilities. That root gate is a conservative limitation of this runner, not a statement that every tracepoint attachment universally requires root. Capability, LSM, container, mount, and kernel-policy decisions remain target-specific. #cite(<capabilities>)

First record the running environment and inspect the exact local event. The commands below do not attach anything. They accept either usual tracefs mount location, print the event identifier and format only if readable, and fail rather than inventing an event layout.

#terminal-listing(
  title: [Read-only preflight for the selected BTF tracepoint],
  "cd samples\ncargo run -p sample-runner -- lab-check\nuname -r\ntracefs=/sys/kernel/tracing\nif [ ! -d $tracefs/events ]; then tracefs=/sys/kernel/debug/tracing; fi\ntest -r /sys/kernel/btf/vmlinux\ntest -r $tracefs/events/sched/sched_process_fork/id\ntest -r $tracefs/events/sched/sched_process_fork/format\ncat $tracefs/events/sched/sched_process_fork/id\ncat $tracefs/events/sched/sched_process_fork/format",
) <lst-07-preflight>

Preserve the displayed kernel release, architecture, `id`, and `format` alongside the test notes. This sample uses a BTF tracepoint rather than offset-decoding that format, but the fixture still confirms the lifecycle event you intend to observe. A failed test means the feature is unavailable in this environment. Stop there; do not change kernel tuning, grant broad `CAP_SYS_ADMIN`, lower tracing restrictions, or replace the event with an unreviewed probe.

If the preflight succeeds and the pinned toolchain including `bpf-linker` is available, build the eBPF object and user-space runner as the ordinary user. The workspace pins Aya 0.14.0, aya-ebpf 0.2.1, and Rust 1.98.1 in its current configuration. Run the already built, narrowly selected loader in the VM only after reviewing the command. This avoids the sample README’s convenient `sudo cargo run` form, which would run Cargo and build scripts as root.

#terminal-listing(
  title: [Bounded process-observation run],
  "cd samples\ncargo xtask check\ncargo xtask build-ebpf\ncargo build -p sample-runner\nsudo ./target/debug/sample-runner run 06-core-process-inspector --duration 10",
) <lst-07-run>

While the ten-second attachment is active, create a harmless child process in another terminal in the same VM, for example `true` or `sh -c 'true'`. The sample observes fork lifecycle activity, so a workload with no fork or clone activity is a valid negative control and may produce no process event. Do not attach this collector to a production host merely to obtain output. The runner caps any requested duration at 60 seconds, and its normal return drops the owned eBPF object. The source makes no bpffs pinning call; nevertheless, verify detach in the target test record rather than assuming a process exit repairs arbitrary external attachments.

== Expected output and interpretation <sec-07-expected-output>

#expected-output(
  title: [What a successful conditional run reports],
  [After a successful load and attach, the runner prints `attached 06-core-process-inspector; observing for 10s (drop detaches)`. For an observed fork, its event printer emits a line beginning `event kind=4` and includes `pid=`, `tid=`, `uid=`, `cgroup=`, `action=`, `value=`, `dev=`, `ino=`, and `comm=`. For this sample, `value` is the attempted read of the child PID; the other task-attribution fields come from the current task at the event. Numeric values vary by target and workload. No event during the negative control is expected; no event after a child workload is not proof that no fork happened because attachment, BTF, tracepoint visibility, ring-buffer loss, or decode conditions may have failed.]
)

The runner formats `dev=0` and `ino=0` for this process event because the base event is default-initialized and this program does not touch VFS identity fields. It prints `action=0` because this is audit-style observation with no decision path. It does not print a dropped-event total. These defaults are not evidence about file access, enforcement, or exact event completeness. A test report should state the observed child workload, the elapsed attachment interval, whether at least one kind-4 record arrived, and the limitations above.

== Portability, cleanup, and exercises <sec-07-portability>

#portability-note(
  title: [Feature gate the enrichment, not the truth],
  [The process inspector requires a readable `/sys/kernel/btf/vmlinux`, a usable `sched_process_fork` BTF tracepoint, an accepted BTF tracepoint program type, compatible Aya behavior, permitted attachment authority, and a successful target load. A kernel version alone does not establish those facts. On an unsupported target, emit a clear “BTF process enrichment unavailable” result and retain only a separately tested lower-capability collector, if any. Do not reinterpret raw syscall slots as a substitute for a typed task pointer.]
)

Cleanup is simple by design: wait for the bounded run to finish, then confirm the runner has returned and no process remains. Because the sample does not request pins, it should not leave a bpffs object as part of its intended lifecycle. Do not add pins “temporarily” to make an observation survive its owner; persistence introduces ownership, schema, upgrade, reconciliation, and rollback obligations that this sample does not implement.

#exercise(
  title: [Record an evidence fixture],
  [In a disposable VM, run only #listing-ref(<lst-07-preflight>, title: [the read-only preflight]). Save the kernel release, architecture, tracefs mount selected, event `id`, complete `format`, BTF readability result, and the exact effective identity. Then write a one-paragraph conclusion: whether this machine is eligible for the BTF enrichment and what fact caused any downgrade. Do not attach a program for this exercise.]
)

#exercise(
  title: [Design a truthful file-audit event],
  [On paper, specify a fixed-width event that distinguishes: bounded request-path bytes, syscall outcome, event-time task attribution, and an optional resolved-object identity. For each field, identify its hook source, lifetime, truncation or failure behavior, and whether it is a request, result, or object fact. Explain why neither a raw pointer nor a single pathname is your durable identity.]
)

#exercise(
  title: [Audit the sample claim],
  [Compare #listing-ref(<lst-07-btf-program>, title: [the program]) with #listing-ref(<lst-07-btf-loader>, title: [the loader]). Identify the three independent conditions that must hold before a child PID is meaningful: typed context availability, a successful guarded kernel read, and a consumer-visible event. Then identify the additional evidence needed before describing the hand-maintained binding as portable CO-RE.]
)

== Chapter summary and next steps <sec-07-summary>

A syscall invocation, a tracepoint record, a task snapshot, and a VFS object each answer a different question. Syscall entry exposes intent under an ABI; task helpers and event fields give time-bounded attribution; VFS resolution gives object relationships whose names and identities are richer than a user string. Tracepoints should be discovered and fixture-checked locally, not presented as a stable ABI. BTF and CO-RE can adapt eligible type access but cannot replace a target feature probe, authority check, relocation inspection, or semantic test.

The repository’s `06-core-process-inspector` demonstrates only a conditional BTF tracepoint read of the child `task_struct.pid` during `sched_process_fork`, followed by a bounded ring-buffer event. Its current hand-maintained structure binding and unreported loss counter make it a teaching case for cautious enrichment, not a baseline portable collector. Keep its runtime scope audit-only, time-bounded, and disposable.

Next, move from lifecycle observation to cautious measurement in #chapter-ref(<ch-08>, title: [Scheduler and Page-Fault Measurements]). There, the same discipline applies: choose locally verified scheduler and exception events, describe metrics as observed events rather than hidden kernel state, and make every missing or unmatched record visible in the result.
