#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, kernel-detail, portability-note, security-note, verifier-note
#import "../../components/code.typ": code-file, code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, section-ref, table-ref
#import "../../components/terms.typ": acronym

#chapter-opener(part: "VI", chapter: "17")
= The Linux Security Module Framework <ch-17>

The Linux Security Module (LSM) framework is where a Linux kernel asks a security question about a kernel object before proceeding with a sensitive operation. This chapter introduces the framework as a dispatch system rather than as a pathname firewall. It then uses the audit-only `12-lsm-file-audit` sample to make one narrow question observable: *has a process opened this particular resolved file object?* The answer is deliberately informative, reversible, and bounded in time. An extended Berkeley Packet Filter (eBPF) program can join that dispatch path only when the booted kernel, its type metadata, active LSM list, loader authority, and selected hook all agree. #cite(<bpf-lsm>)

The safety boundary is important. The sample is a learning instrument for a disposable virtual machine (VM) or similarly isolated host that you administer. It is not a production audit system, a general file-access monitor, a replacement for discretionary access control, or a complete protected-file policy. In particular, it audits only policy-matched `(device,inode)` opens while its loader owns the attachment. It neither reconstructs pathnames in eBPF nor denies an operation.

== Prerequisites and learning objectives <sec-17-prerequisites>

You need a Linux VM that you can recover by rebooting, an ordinary-user build environment for the repository’s locked Rust workspace, and authorization to run the final attachment step. The runtime exercise additionally needs readable kernel BPF Type Format (BTF) metadata at `/sys/kernel/btf/vmlinux`, a kernel built with BPF LSM support, and an effective LSM list that contains `bpf`. A control group (cgroup) v2 directory is required by this sample’s runner configuration even though sample 12 does not use it to restrict the audit event. The runner also has a conservative effective-user-ID-zero gate; that is an implementation limit of this repository, not proof that every BPF operation universally requires UID 0. Linux capabilities and local security policy remain part of the operation-specific deployment contract. #cite(<capabilities>)

After completing the chapter, you should be able to:

- distinguish ordinary LSM ordering from a chain of BPF LSM programs and from cgroup LSM attachment;
- explain why the synthetic prior-result argument must be preserved before local policy is evaluated;
- state precisely what `file_open` does and, equally importantly, what it does not cover;
- run the audit sample without enabling denial, interpret its conditional output, and remove its disposable resources; and
- formulate a narrow threat model and a feature probe that must succeed before an audit design becomes an enforcement proposal.

#concept(title: "A security hook asks about an object, not a string")[
The Virtual File System (VFS) resolves a pathname into kernel objects. At `file_open`, the relevant object is a `struct file` associated with an inode, not the spelling originally supplied by a process. A pathname can vary with a process root, mount namespace, symbolic link, bind mount, rename, or hard link. For this reason, this chapter treats a pathname as setup input and operator context, while the sample matches a device-and-inode pair.
]

== From security question to hook dispatch <sec-17-dispatch>

The LSM framework is a set of hooks placed in security-relevant kernel paths. A subsystem such as the VFS invokes the framework; configured security modules then receive the hook’s arguments and return values according to that hook’s contract. The framework is not itself a policy engine. It provides the coordination point at which built-in or loaded modules—such as a mandatory access control (MAC) module and the `bpf` LSM component—may participate. BPF LSM is therefore additive: it does not erase a decision made by a conventional LSM or bypass normal discretionary access checks. #cite(<bpf-lsm>)

For an integer-valued hook, the current generic model begins with that hook’s default return value and stops at the first module result that differs from the default. The active order is observable on a running machine in `/sys/kernel/security/lsm`; it is a boot-and-distribution property that must be recorded with a deployment, not guessed from a source tree. If an earlier ordinary LSM returns a denial, later checks for that hook may not run. BPF LSM cannot observe, undo, or audit a check that never reaches the BPF LSM component. This is a valuable limitation: layering is not a vote in which a later program can overrule an earlier denial. #cite(<bpf-lsm>)

There are three different mechanisms often compressed into the word “stacking.” They have different inputs and return semantics, summarized in #table-ref(<tab-17-stacking>, title: "three forms of stacking"). Keeping them separate prevents a particularly dangerous mistake: transferring the ordinary BPF LSM errno convention to cgroup LSM code.

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (1.25fr, 1.5fr, 2.45fr),
    inset: 6pt,
    align: (left, left, left),
    table.header(
      [*Mechanism*], [*Where it composes*], [*Engineering consequence*],
    ),
    [Ordinary LSM ordering],
    [The framework’s configured module sequence],
    [A non-default result can short-circuit a later module. Treat the observed active list and order as deployment input.],
    [BPF LSM program chain],
    [Several BPF programs attached to one BPF LSM hook],
    [Each program receives the preceding BPF result as a synthetic final argument. Preserve a nonzero result before evaluating a local rule.],
    [Cgroup LSM],
    [Effective programs for a workload cgroup],
    [This is a separate attachment type with boolean-grant aggregation and cgroup run-context semantics. It is not global errno-style LSM code plus a cgroup-ID test.],
  ),
  caption: [Three mechanisms called “stacking,” with different control-flow contracts. The first two matter directly to sample 12; the third is an advanced, separately tested feature.],
) <tab-17-stacking>

An ordinary BPF LSM authorization program attaches to a BTF-described hook. BTF is compact type metadata that lets the loader identify the hook and lets a compatible object express eligible type accesses; Compile Once – Run Everywhere (CO-RE) relocations can adapt certain BTF-described field accesses, but cannot manufacture a missing hook, an active `bpf` LSM, permission, or security semantics. #cite(<bpf-lsm>) #cite(<libbpf-core>) For a normal integer authorization hook, the return convention is narrow: return `0` to permit, or a negative error number (errno), such as `-EACCES` for “permission denied,” to deny. A positive arbitrary value is not a portable substitute for a decision. Verify exceptional hooks against their declaration and the target verifier. #cite(<bpf-lsm>)

The BPF chain adds one detail absent from the native hook signature. The hook declaration supplies its native arguments; BPF LSM adds a trailing integer containing the previous BPF program’s result, or zero for the first BPF program. For `file_open(struct file *file)`, the file pointer is argument zero and the prior BPF result is argument one. The first operation in a defensive program is thus conceptually simple: if `ret != 0`, return `ret`. That rule preserves an earlier BPF-chain denial rather than accidentally replacing it with permission. #cite(<bpf-lsm>)

#kernel-detail(title: "Dispatch order bounds observation")[
The prior result is *not* a record of every LSM’s verdict. It represents the earlier BPF program in the BPF chain. By contrast, a prior ordinary LSM denial can prevent BPF LSM execution altogether. Therefore, a BPF event stream must not be described as a complete log of all file-open authorization decisions on the host.
]

== What `file_open` means <sec-17-file-open>

`file_open` is an integer LSM hook whose native argument is a resolved `struct file *`. In the VFS open path, it is a useful point to ask whether the current task may open that file object. This makes the hook a good teaching boundary: it connects a concrete kernel object, a fixed return contract, a map lookup, and an observable attachment lifecycle. It does *not* mean “protect this textual path forever.” It also does not promise to gate every subsequent read, write, memory mapping, execution route, descriptor transfer, or file-related operation relevant to an asset. A real requirement must enumerate the operations that matter and select additional hooks where appropriate. #cite(<bpf-lsm>)

The requested figure shows the narrow sequence. The VFS reaches the hook with a file and inode. The normal LSM chain may stop the operation before BPF LSM is reached. If BPF LSM runs, a program can inspect its permitted context, consult bounded policy state, emit best-effort telemetry, and return an authorization result. Sample 12 takes only the audit branch: it reports a matched object and returns zero.

#figure(
  image("../../assets/diagrams/generated/17-lsm-file-open.svg", width: 100%),
  caption: [A `file_open` decision sequence. The sample follows the “no match / audit” branch; `-EACCES` is shown only as an explicit opt-in policy concept, not as behavior of sample 12.],
) <fig-17-file-open-sequence>

As #figure-ref(<fig-17-file-open-sequence>, title: "the file-open sequence") emphasizes, policy identity should be about the resolved object. An inode number is meaningful within a filesystem, not as a host-wide identifier. The audit sample combines a device value with the inode number; its user-space setup obtains those values using metadata for `--protect`, and its eBPF side reads `f_inode`, then `i_ino`, then the superblock’s `s_dev`. It is not a pathname matcher. A hard link on the same filesystem normally reaches the same inode, so an object-based rule can observe the alternate name. A rename normally changes the name, not the inode. These are desirable properties only if the policy protects the object rather than a directory entry.

The qualification matters for unusual filesystems. Overlay filesystems, Filesystem in Userspace (FUSE), network filesystems, pseudo-filesystems such as procfs, and anonymous or in-memory filesystems can have device, inode, and generation behavior that needs an explicit filesystem-class policy. The sample has none. Its checked-in `vmlinux.rs` is explicitly a quarantined manual fixture, not generated target evidence. The LSM programs are excluded from the default object until target bindings, relocation inspection, and runtime evidence exist.

== The audit sample, exactly as implemented <sec-17-sample>

The two canonical sample files in #listing-ref(<lst-17-audit-readme>, title: "the audit sample README") and #listing-ref(<lst-17-audit-manifest>, title: "the sample manifest") identify the named lab and its `lsm_file_audit` program. The focused source ranges below are read directly from their canonical repository files. The sample’s central code is imported unchanged in #listing-ref(<lst-17-audit-program>, title: "the BPF audit decision path"). Notice its intentionally narrow decisions. It first reads the prior BPF LSM return from `ctx.arg(1)` and immediately propagates nonzero. It next obtains the `file` argument from `ctx.arg(0)`, constructs a `FileIdentity` only if all pointer and field reads succeed, and looks up that identity in `POLICY`. An absent identity or absent map entry returns zero with no event. A matching key creates an event carrying the device and inode. For the `lsm_file_audit` entry point, `may_deny` is `false`, so `event.action` is zero and the function returns zero even if configuration says enforcement is enabled.

#code-file(
  "../../samples/12-lsm-file-audit/README.md",
  title: "Canonical instructions for the audit-only sample",
  language: "markdown",
  source-path: "samples/12-lsm-file-audit/README.md",
) <lst-17-audit-readme>

#code-file(
  "../../samples/12-lsm-file-audit/sample.toml",
  title: "Canonical sample manifest",
  language: "toml",
  source-path: "samples/12-lsm-file-audit/sample.toml",
) <lst-17-audit-manifest>

#code-listing(
  "Sample 12 BPF decision path: preserve, match, audit, allow",
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(237, 283).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs:238–283",
) <lst-17-audit-program>

The global maps explain both the promise and the limitation. `POLICY` is a hash map from `FileIdentity` to a one-byte membership value. `CONFIG` contains `enforce`, `policy_generation`, and a cgroup identifier. `EVENTS` is a ring buffer, and `DROPPED` is a per-CPU array. When reservation fails, the program increments `DROPPED` and keeps its already selected return value. Telemetry pressure therefore never changes authorization. #cite(<bpf-ringbuf>)

The runner exposes producer reservation loss and consumer parse rejection, and the record carries schema version, length, kind, reason, flags, and policy generation. It rejects unknown or malformed records before decoding. This remains application-managed same-host telemetry, not a complete Linux Audit trail: no event can still mean no match, no hook invocation, no attachment, producer loss, or a window boundary.

The corresponding user-space implementation is in #listing-ref(<lst-17-runner-setup>, title: "the loader setup and attachment"). `configure_policy` obtains the protected identity using `fs::metadata`, obtains the requested cgroup directory’s inode as a cgroup identifier, inserts the protected key, and writes configuration with `enforce: false` for sample 12. `attach_lsm` reads BTF from the system filesystem, loads the program at `file_open`, and attaches it. The owner remains alive during the bounded observation period; when the `Ebpf` owner leaves scope, the sample describes the attachment as detached. It performs no bpffs pinning, no persistent policy installation, and no automatic restart.

#code-listing(
  "Sample runner BTF attachment and audit policy setup",
  read("../../../samples/runner/src/main.rs").split("\n").slice(313, 363).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs:314–363",
) <lst-17-runner-setup>

The dispatcher adds an important guard that the README alone can obscure: `12-lsm-file-audit --enforce` fails with `sample 12 is audit-only` before configuration or attachment. The runner nevertheless requires `--protect` and `--cgroup` for this sample because it calls the common policy configuration function. The cgroup value is recorded in configuration, but cannot make sample 12 deny and does not gate whether sample 12 emits for a matching protected object. Do not infer a workload-scoped enforcement property from the presence of that argument.

#security-note(title: "Audit is the default; denial is not a test shortcut")[
Sample 12 contains no denial-capable route. A neighboring enforcement sample is a separate exercise and must remain explicit opt-in in a disposable VM and disposable cgroup, with one disposable path and a rehearsed rollback. Never “test” enforcement by changing this audit sample, by applying a broad rule, or by granting a general shell extra authority. Build as an ordinary user; authorize only the reviewed loader binary for the narrowly justified attachment step.
]

== Safe, reproducible audit procedure <sec-17-procedure>

Begin with a read-only feature inventory. These commands intentionally report unsupported or unavailable prerequisites rather than attempting to change boot parameters, capabilities, memory limits, or LSM order. The `lab-check` subcommand tests for BTF and the literal `bpf` name in securityfs, but it does not prove `CONFIG_BPF_LSM=y`, hook availability, helper eligibility, or a successful attachment. Record the full effective LSM list before proceeding.

#terminal-listing("cd /home/ubuntu/learn-eBPF-00/samples\n./target/debug/sample-runner lab-check\nuname -r\nuname -m\ntest -r /sys/kernel/btf/vmlinux && echo BTF-readable || echo BTF-unavailable\ntest -r /sys/kernel/security/lsm && cat /sys/kernel/security/lsm || echo securityfs-unavailable", title: "Read-only preflight for the audit exercise") <lst-17-preflight>

Build ordinary user-space and default artifacts as an ordinary user. The default eBPF object intentionally omits LSM programs; a runnable LSM exercise additionally requires a separately generated, reviewed target-BTF object. A build failure is evidence about the environment, not a reason to run Cargo under `sudo`.

#terminal-listing("cd /home/ubuntu/learn-eBPF-00\nnix develop\n# This atomically replaces the quarantined fixture in this disposable worktree.\n./scripts/generate-target-bindings.sh --install-tool\ncd samples\ncargo xtask build-ebpf --target-btf\ncargo build -p sample-runner\nreadelf -SW target/ebpf/samples-ebpf-target-btf | grep -E '\\.BTF(\\.ext)?'\nsha256sum target/ebpf/samples-ebpf-target-btf", title: "Generate, build, and inspect before privileged attachment") <lst-17-build>

Only in the disposable VM, create a directory and regular file below the reserved `/tmp/learn-ebpf-` prefix, then create an empty cgroup v2 directory if permitted. Sample 12 cannot deny, but the common configuration records the cgroup and nonzero generation. Supply only a target-generated, relocation-inspected object and acknowledge that fixture explicitly.

#terminal-listing("sudo mkdir -p /tmp/learn-ebpf-demo\nsudo sh -c 'printf %s\\n demo > /tmp/learn-ebpf-demo/protected'\nsudo mkdir -p /sys/fs/cgroup/learn-ebpf-demo\ncd /home/ubuntu/learn-eBPF-00/samples\nTARGET_OBJECT=target/ebpf/samples-ebpf-target-btf\ntest -r \"$TARGET_OBJECT\"\nsudo ./target/debug/sample-runner run 12-lsm-file-audit --object \"$TARGET_OBJECT\" --target-btf-fixture --policy-generation 1 --protect /tmp/learn-ebpf-demo/protected --cgroup /sys/fs/cgroup/learn-ebpf-demo --duration 10", title: "Audit-only demonstration with one disposable file") <lst-17-run>

While the runner is observing, use a second terminal to open the exact disposable file, for example `cat /tmp/learn-ebpf-demo/protected`. The runner configured the map and attached before it printed its `attached ...; observing ...` line, so perform the open after that line appears. An unrelated regular file is a negative control: it should not match the `POLICY` entry and therefore should not create this sample’s file event. Likewise, an `--enforce` flag is a negative control for sample 12: it should fail rather than convert auditing into denial.

== Expected output and how to reason about it <sec-17-output>

The exact process identifiers, device number, inode number, command name, kernel release, and ordering are environment-dependent. Do not copy a transcript as though it were an assertion about your machine. The sample supports the following output *shape* after a successful attachment and a matching open:

#expected-output(title: "Conditional audit result")[
The runner first prints a policy line with `mode=AUDIT generation=1`, then an attachment line. A matching open can produce a validated `kind=10` record with `action=0`, `reason=1`, and `generation=1`; the open remains allowed. Final transport metrics report producer and consumer loss boundaries. Exact identifiers and counts remain target-dependent.
]

The verifier reasoning is separate from runtime success. A verifier-approved program establishes that the kernel accepted the object under this target’s program, attach, helper, and pointer-safety rules; it does not prove the business policy is complete. In #listing-ref(<lst-17-audit-program>, title: "the BPF path"), the null checks after the `file`, `inode`, and superblock reads prevent a dereference after a known-null branch. A failed helper-mediated read becomes `None` through `ok()?`, and an absent policy lookup also returns zero. The event is initialized by `base` before the device and inode fields are assigned. The ring-buffer helper path has one successful reservation followed by one submit; its failure branch updates a bounded per-CPU loss counter. These are the kinds of control-flow and initialization facts the verifier tracks. #cite(<bpf-verifier>)

#verifier-note(title: "Accepted bytecode is not a complete audit proof")[
The sample’s pointer branches and reservation lifecycle are necessary verifier obligations. They do not establish that the hand-maintained structural bindings match every target, that `(device,inode)` is sufficient on every filesystem, that emitted records are lossless, or that the program sees every relevant file operation. Keep verifier logs with the object hash and target facts, then test the stated security coverage independently.
]

If attachment fails, preserve the full error and classify it honestly: BTF unavailable, inactive `bpf` LSM, unsupported or disabled BPF LSM, insufficient authority, verifier rejection, missing object, or another loader error. The repository’s runner calls `Btf::from_sys_fs()` and therefore produces a BTF-specific failure before the LSM load if that file is unavailable. It requires effective UID 0 before loading any selected sample. It does not independently inspect `CONFIG_BPF_LSM`, retain verifier logs, or confirm that `bpf` was in the effective LSM list immediately before loading. Those checks belong in a deployment preflight, not in an assumption about a nominal kernel version.

== Portability, telemetry, and threat model <sec-17-portability-threat-model>

BPF LSM should be treated as a capability tier rather than a simple minimum-version claim. A kernel with an old-enough version number can still lack BTF, `CONFIG_BPF_LSM`, an active `bpf` LSM, a requested hook, a permitted helper, required authority, or compatible architecture and lockdown policy. BTF and CO-RE mitigate eligible layout differences; they do not make a hand-maintained binding, a hook contract, or filesystem semantics portable by declaration. The feature probe is therefore part of the safety case. #cite(<bpf-lsm>) #cite(<libbpf-core>)

#portability-note(title: "Treat unsupported as a valid result")[
For this sample, an unreadable `/sys/kernel/btf/vmlinux`, a missing `bpf` entry in `/sys/kernel/security/lsm`, a failed load, or a failed attach means “audit feature unavailable on this target.” Do not append an ad hoc `lsm=` kernel parameter, remove another LSM, grant a broadly privileged interactive shell, pin objects, or silently attach a different hook to force a result. Make the feature inactive and retain the diagnosis.
]

The threat model must say who and what is protected. A narrow future policy could defend one service workload from accidental or unauthorized opens of a small, inventoried set of high-value regular-file objects. It could make an alternate hard link or rename visible through object identity, provided the filesystem identity rules were tested. It could not claim to defend against a host administrator who can change BPF state or LSM boot configuration, a kernel compromise, a privileged actor that replaces the loader or link, or filesystem behavior outside its explicit identity classes. It also cannot become a complete data-use control simply because it sees `file_open`.

Telemetry belongs outside the decision. If an event buffer is full, authorization remains the already selected decision; the runner exports that producer loss separately from parse rejection. The record now has fixed framing, reason, and selected generation, but a production successor still needs an object-class result, inactive-generation validation, atomic selection, link-health monitoring, durable export rules, and practiced rollback. Persistence is not automatically safe merely because a map can be pinned. #cite(<bpf-map>)

The sample’s cgroup detail needs similar restraint. It records the current cgroup identifier in an event and stores the supplied cgroup directory’s inode in configuration. Neither action turns a cgroup path into a durable container identity or turns sample 12 into cgroup-scoped enforcement. Cgroup v2 is a hierarchy whose membership and delegation must be checked at the target. A later cgroup LSM design must use its distinct return and hierarchy semantics and test migration; it must not reuse this ordinary LSM program’s errno reasoning. #cite(<cgroups-v2>)

== Cleanup, exercises, and summary <sec-17-summary>

When the bounded runner exits, the owned eBPF object leaves scope and the sample’s attachment is described as detached. Verify that the runner has stopped before cleanup. Then remove only the resources created for this exercise. The cgroup directory must be empty; if a shell or process was moved into it for an unrelated test, move or stop that process first. Do not remove host cgroups, alter the global LSM order, or delete files outside the disposable prefix.

#terminal-listing("sudo rmdir /sys/fs/cgroup/learn-ebpf-demo 2>/dev/null || true\nsudo rm -rf /tmp/learn-ebpf-demo", title: "Cleanup for the disposable audit exercise") <lst-17-cleanup>

For a first exercise, run the sample twice: once without opening the protected file and once with a single `cat` while the runner is attached. Record which condition produced `kind=10` and why the no-event case cannot distinguish all failure modes. For a second exercise, create a hard link to the disposable protected file before attachment, open it during the observation window, and compare the printed device and inode to the original. State which property follows from inode identity and which remains filesystem-dependent. For a third, run the read-only preflight on a machine where BTF or `bpf` LSM is unavailable and write a one-sentence downgrade decision instead of attempting configuration changes.

The LSM framework is a kernel security dispatch layer. Its order determines whether BPF LSM runs at all. Within a BPF LSM chain, the prior result is a safety invariant: preserve a nonzero value. `file_open` is an object-level open decision, not a comprehensive asset-protection claim. Sample 12 demonstrates a defensible first move: identify one preconfigured `(device,inode)`, emit best-effort audit telemetry for matching opens, return zero, and let scope exit detach the short-lived attachment. Its value is pedagogical precisely because its limits are explicit.

== Next steps <sec-17-next-steps>

Next, continue to #chapter-ref(<ch-18>, title: "the protected-file policy capstone"). That chapter can build on this audit-first evidence to discuss versioned policy state, complete identity and filesystem-class tests, explicit failure modes, link health, rollback, and a single opt-in denial only inside a recovery-capable disposable environment. Do not advance to enforcement until the preflight, observed LSM order, object identity behavior, event-loss signal, and negative controls in this chapter are understood.
