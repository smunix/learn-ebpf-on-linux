#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, exercise, expected-output
#import "../../components/code.typ": code-file, code-listing, terminal-listing

// Canonical source reader for bounded excerpts. It reads repository files rather than copying them.
#let sample-excerpt(path, first, last, title, source-path) = code-listing(
  title,
  read(path).split("\n").slice(first - 1, last).join("\n"),
  language: "rust",
  source-path: source-path,
)
#import "../../components/crossrefs.typ": section-ref, figure-ref, table-ref, listing-ref, definition-target
#import "../../components/terms.typ": acronym

#chapter-opener(part: "IV", chapter: "12")
= Seccomp, Capabilities, and eBPF <ch-12>

A containerized workload does not cross one “security boundary.” Its kernel requests pass through several controls that answer different questions: credentials answer whether the caller has authority; namespaces choose which instance of some resources the caller sees; secure computing mode (seccomp) limits the system-call interface; control groups (cgroups) scope resources and certain BPF attachments; and Linux Security Modules (LSMs) authorize object operations. An extended Berkeley Packet Filter (eBPF) program participates in only the particular contract defined by its program type and attachment. It is not a replacement for any of the surrounding controls.

This chapter develops an operational model for combining classic Berkeley Packet Filter (cBPF) seccomp filters, Linux capabilities, user namespaces, and eBPF-based observation. It deliberately begins with the repository’s read-only preflight and ends with an audit-only, disposable-virtual-machine procedure. The goal is not to grant a process “enough privilege to make BPF work.” The goal is to state the smallest authority for each component, prove what the target host actually provides, and preserve a recovery path.

== Prerequisites and learning objectives <sec-ch12-prerequisites>

Before continuing, be comfortable with the eBPF load/verify/attach lifecycle, tracepoint programs, and the difference between a BPF map and an event transport. You should also have completed the cgroup-connect audit and container-attribution labs conceptually: their event fields are useful evidence, but neither establishes a container’s permanent identity. A disposable Linux virtual machine (VM), a normal-user Rust build environment, and permission to inspect the host are sufficient for the first half of this chapter. An audit-only BPF LSM trial has additional kernel and administrative prerequisites discussed later.

After this chapter, you should be able to:

- distinguish cBPF used by seccomp from eBPF programs loaded through the BPF subsystem;
- name the effective, permitted, inheritable, bounding, and ambient capability sets and explain why they are not a universal BPF recipe;
- explain why user-namespace root is not host-wide BPF authority;
- predict how seccomp stacking and LSM ordering can limit what an audit program observes;
- interpret the repository’s feature matrix without mistaking it for a successful attachment test; and
- design a loader, policy writer, and telemetry consumer with separate, minimal authority.

#concept(title: "Start with separate questions")[A capability asks whether a thread may perform a privileged operation in the relevant user namespace. Seccomp asks whether that process may invoke a system-call interface. An LSM asks whether an object operation is permitted at a particular hook. A cgroup asks which current hierarchical domain the task belongs to. An eBPF program observes or acts only where its program and attachment contract allow. Passing one check never proves the answer to the others.]

== One request, several decisions <sec-ch12-pipeline>

#definition-target("def-ch12-least-authority", "Least authority")[Give each component only the permissions, namespace access, file descriptors, and system calls it needs for its defined job, for no longer than needed. In this chapter, that means separating a privileged object loader or policy writer from a consumer that merely reads approved telemetry.]

The pipeline in #figure-ref(<fig-ch12-security-pipeline>, title: "security-decision pipeline") is a reasoning aid, not a promise of one universal call graph. Seccomp filters a system call near syscall entry. A filesystem open may subsequently pass through pathname resolution, discretionary access checks, filesystem work, and one or more LSM hooks. A cgroup socket-address program is instead selected by its cgroup attachment and its networking hook. The order of concrete checks depends on the kernel path, the active LSM configuration, and the selected program type. Do not make a security claim from a diagram alone; identify the requested operation and test that operation on the target.

#figure(
  image("../../assets/diagrams/generated/12-security-decision-pipeline.svg", width: 100%),
  caption: [A security decision is composed from distinct control layers. The precise call path and active LSM ordering are target facts, so the figure is a mental model rather than a universal trace.],
) <fig-ch12-security-pipeline>

#kernel-detail(title: "The important distinction: cBPF is not eBPF")[A seccomp filter is a classic BPF program evaluated against syscall metadata such as the system-call number, architecture, and arguments. It has no eBPF map application programming interface (API), helper calls, arbitrary kernel-memory dereferences, or attachable eBPF program type. In particular, seccomp cannot replace an eBPF LSM policy, and a verifier-accepted eBPF object cannot widen a seccomp-denied syscall surface. The seccomp interface intentionally prevents filter pointer dereference, avoiding a time-of-check-to-time-of-use (TOCTOU) class in this layer. @seccomp]

The following table keeps the layers separate. “Typical evidence” is intentionally evidence, not a capability grant: an administrator’s successful tool invocation does not prove that the production service identity has the same access.

#figure(
  table(
    columns: (1.20fr, 1.55fr, 1.74fr, 1.55fr),
    inset: 5pt,
    stroke: 0.35pt + rgb("#B8CDD2"),
    table.header(
      [*Layer*], [*Primary question*], [*What it constrains*], [*Typical target evidence*],
    ),
    [Capabilities], [May this thread perform a privileged operation?], [Authority at a kernel permission check in a relevant user namespace], [Effective capability set; operation-specific load/attach result],
    [User namespace], [Which credentials and capabilities are meaningful here?], [The scope in which credentials and many capability checks apply], [Namespace handle and host-side inspection of mappings],
    [Seccomp], [May this process issue this syscall?], [A process’s syscall interface, with stacked filter results], [Filter install result; declared allowlist; integration test],
    [cgroup v2], [Which hierarchy and attached-policy domain contains this task now?], [Resource distribution and cgroup-scoped BPF attachment selection], [Mounted/delegated hierarchy, current membership, attachment state],
    [LSM], [May this hook-specific object operation proceed?], [Mandatory access-control decisions at configured hooks], [Active LSM list; hook/object trial; BPF LSM preflight],
    [eBPF program], [What may this accepted program do at its hook?], [Verifier-checked program-type and helper contract], [Object hash, verifier result, attach result, lifecycle evidence],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Control layers and the evidence needed before relying on them.],
) <tab-ch12-controls>

== Capabilities: narrow authority, not a “root bit” <sec-ch12-capabilities>

Linux capabilities split traditional superuser authority into per-thread bits. The *effective* set participates in permission checks; the *permitted* set bounds bits that may become effective; the *inheritable* set participates in `execve`; the *bounding* set limits what can be gained across `execve`; and the *ambient* set can survive a nonprivileged `execve` only while the bit remains both permitted and inheritable. These are separate sets because a process’s authority must survive, change, or be constrained across program execution in deliberately different ways. @capabilities

`CAP_BPF`, introduced in Linux 5.8, separated some privileged BPF operations from the historically broad `CAP_SYS_ADMIN`; it is vocabulary, not a deployment recipe. Program type, performance or network authority, BPF settings, an LSM, lockdown, and the target kernel can still reject an operation. Conversely, the runner’s effective-user-ID-zero gate is its conservative implementation limitation, not proof that every kernel action requires UID 0. Test the precise load and attach under the production identity. @capabilities

The consequence is architectural. Build eBPF objects as an ordinary user. Run a small reviewed loader only with the authority needed to create, load, and attach the reviewed object; give a policy writer only its required map operations; and give an event consumer neither a loading path nor a writable policy-map file descriptor. Drop loader privileges when its lifecycle permits. A formatter or JavaScript Object Notation (JSON) parser bug must not become authority to load arbitrary BPF.

The shared sample types illustrate a small but important default. `EnforcementConfig::default()` sets `enforce`, `policy_generation`, and `cgroup_id` to zero; the unit test asserts the non-enforcing state. Event records separately carry an explicit schema version, record length, kind, flags, reason, generation, and reserved-zero fields. That same-host ABI does not make the configuration a deployment protocol, but it makes both default disposition and telemetry compatibility reviewable.

#sample-excerpt(
  "../../../samples/common/src/lib.rs", 54, 104,
  "Shared policy scope defaults", "samples/common/src/lib.rs, lines 21–36",
) <lst-ch12-policy-default>

A capability design also needs negative requirements. Do not “solve” a failed load by lowering `perf_event_paranoid`, disabling `unprivileged_bpf_disabled`, granting `CAP_SYS_ADMIN`, or adding file capabilities to Cargo or a shell. Those changes are broad, persistent in effect, and obscure which operation actually required authority. Preserve the failure message, inspect the target’s policy, and either narrow the requested operation or mark the feature unavailable.

=== User namespaces change the meaning of “root” <sec-ch12-user-namespaces>

A user namespace maps user and group identities and defines the scope of capability checks for namespaced resources. A process can be user identifier (UID) 0 and possess a full capability set inside a new user namespace while possessing no capabilities in its parent user namespace. Authority acquired inside the child namespace does not automatically authorize operations over non-namespaced, host-wide resources. Therefore, “root in a container” and “host root” are not interchangeable descriptions of eBPF authority. @capabilities

This is one reason to treat a container as a collection of controls rather than an identity. A PID is meaningful in a PID namespace; a mount namespace changes pathname views; a cgroup namespace virtualizes cgroup paths; and a cgroup ID describes a task’s current place in the host cgroup graph. The previous container-attribution sample emits a host PID and current cgroup ID at an execution tracepoint. Its README correctly says that user-space/runtime metadata must resolve a human container name; it does not claim a container name is in the event. See #listing-ref(<lst-ch12-container-attribution>, title: "current cgroup observation"). The cgroup version-2 hierarchy and its delegation rules must be inspected separately from namespace visibility. @cgroups-v2

#sample-excerpt(
  "../../../samples/ebpf-programs/src/main.rs", 187, 193,
  "Prior-lab cgroup observation at exec", "samples/ebpf-programs/src/main.rs, lines 187–193",
) <lst-ch12-container-attribution>

== Seccomp: reduce syscall surface deliberately <sec-ch12-seccomp>

Seccomp’s filter mode applies a cBPF decision to syscall metadata. The program receives a `seccomp_data` record, not arbitrary process memory. It can compare a syscall number, architecture, and scalar argument values, but it cannot inspect a path buffer by dereferencing a pointer. That limitation is a security property, not a missing eBPF convenience: a filter cannot safely turn pathname-pointer inspection into an authorization mechanism. Seccomp reduces the kernel interfaces exposed to a process; it does not provide a full information-flow sandbox, authenticate a caller to a remote service, or decide whether a particular file object should be opened. @seccomp

The first rule for a portable filter is to check the architecture field before interpreting a syscall number. The same number can have a different meaning under another application binary interface (ABI) or compatibility calling convention. The second rule is to derive an allowlist from observed, tested behavior. A loader that opens an ELF object, reads BPF Type Format (BTF) metadata, issues BPF syscalls, talks to a Unix-domain socket, and exits has a different syscall budget from a long-running event consumer. Applying one process’s list to the other is either too broad or breaks it.

Installing `SECCOMP_SET_MODE_FILTER` requires `no_new_privs` or `CAP_SYS_ADMIN` in the caller’s user namespace. Filters are inherited over permitted `fork`/`clone` and preserved across permitted `execve`; multithreaded synchronization with `SECCOMP_FILTER_FLAG_TSYNC` can fail for incompatible filter trees. Initialize dependencies, reduce authority, install the reviewed filter at a known point, and avoid later excluded syscalls. @seccomp

Several filters can apply. The highest-precedence action controls; on a tie, the most recently installed filter supplies data. An existing container filter may therefore deny a syscall that an application filter permits. Log the installation boundary and test the final process image instead of depending on installation order. @seccomp

#security-note(title: "Do not turn seccomp user notification into a general authorization server")[`SECCOMP_RET_USER_NOTIF` introduces a request/response protocol, cancellation cases, visibility limits across PID namespaces, and TOCTOU risk if a supervisor makes a decision from caller-controlled memory. It is not a substitute for a hook-specific LSM policy. This chapter uses no user-notification policy and does not authorize a broad deny filter. @seccomp]

Seccomp complements eBPF operationally. A loader’s seccomp profile can prevent it from spawning shells, opening unexpected networking paths, or changing its runtime behavior after a controlled setup phase. An unprivileged consumer can receive already-approved events through a deliberately passed file descriptor or a narrowly permissioned Unix socket while its seccomp profile excludes BPF-management and filesystem-mutation syscalls it does not require. Neither profile makes the eBPF object safe; the verifier and the program’s hook semantics remain independent proof obligations.

== The repository’s evidence: preflight, cgroup audit, and LSM audit <sec-ch12-repository-evidence>

#code-file(
  "../../samples/00-lab-check/sample.toml",
  title: "Primary sample declaration",
  language: "toml",
  source-path: "samples/00-lab-check/sample.toml",
) <lst-ch12-primary-metadata>

The primary sample, `00-lab-check`, declares `programs = "none"`. Its runner command is read-only: it reads procfs, sysfs, and filesystem paths and prints a matrix. It neither calls `Ebpf::load_file` nor attaches anything. Accordingly, it has no verifier result and no eBPF lifecycle to clean up. The actual implementation is in the shared runner, shown in #listing-ref(<lst-ch12-lab-check>, title: "read-only feature matrix").

#sample-excerpt(
  "../../../samples/runner/src/main.rs", 92, 132,
  "Read-only lab feature matrix", "samples/runner/src/main.rs, lines 92–132",
) <lst-ch12-lab-check>

Read the rows literally. “Kernel BTF” means that `/sys/kernel/btf/vmlinux` is a file. “BPF LSM active” means that securityfs was readable and its comma-separated list contained exactly `bpf`. “cgroup v2” means only that `/proc/filesystems` mentions `cgroup2`; the check does *not* prove that the intended hierarchy is mounted, delegated, writable, or appropriate for an attachment. “bpffs” and “tracefs” are directory checks. “effective root” tests `geteuid() == 0`, not individual capability sets. The final sentence accurately labels attachment as conditional, but it must not be read as a successful verifier/load/attach test.

The `10-cgroup-connect-audit` prior lab is an audit observer with the `connect4` cgroup socket-address attachment. It reads Internet Protocol version 4 (IPv4) address and port fields, emits a `ConnectEvent` if ring reservation succeeds, returns `1`, and attaches in `Single` mode to the provided cgroup. It supports scoped destination telemetry—not allow/deny policy, a universal container label, IPv6, or unverified byte-order semantics.

#code-file(
  "../../samples/12-lsm-file-audit/sample.toml",
  title: "Audit sample declaration",
  language: "toml",
  source-path: "samples/12-lsm-file-audit/sample.toml",
) <lst-ch12-audit-metadata>

The later BPF LSM audit path makes the ordering lesson concrete. It first reads the synthetic preceding BPF-LSM return. If nonzero, it returns that value unchanged. Otherwise, the audit variant calls the common function with `may_deny` false, emits best-effort telemetry only for a configured `(device, inode)` identity, and returns zero. Exact predicate failures, null-pointer reads, and missing policy leave the operation allowed in this sample. This is environment-gated behavior: it can be attempted only when the target provides compatible BTF, `CONFIG_BPF_LSM=y`, an active `bpf` LSM, a supported `file_open` hook, and sufficient loader authority. @bpf-lsm

#sample-excerpt(
  "../../../samples/ebpf-programs/src/main.rs", 217, 251,
  "Audit-first file-open decision and preservation of prior BPF-LSM result", "samples/ebpf-programs/src/main.rs, lines 217–251",
) <lst-ch12-lsm-decision>

== LSM ordering, audit coverage, and return contracts <sec-ch12-lsm-ordering>

The LSM framework can compose multiple security modules. `/sys/kernel/security/lsm` exposes the active, comma-separated modules in the order their checks are made; that order is a booted-host fact. An integer-returning hook begins from its default result and a non-default result from an earlier LSM can end that dispatcher path. A later BPF LSM program therefore may not observe an operation already denied by an earlier module. It cannot reverse that denial. @bpf-lsm

There are two distinct ordering questions. First, where does `bpf` appear relative to other active LSMs? Record the actual list rather than copying a distribution recipe. Second, what happens among BPF programs at one BPF-LSM attachment? The BPF LSM context carries the previous BPF program’s return value; an ordinary authorization program must preserve a nonzero prior value rather than accidentally returning zero. For ordinary integer authorization hooks, zero permits and a documented negative errno denies; special hook contracts must be checked individually. @bpf-lsm

This explains a hard limit on audit claims. An audit-only BPF LSM can report calls that reach it. It cannot demonstrate that it saw every attempted file access on a host with other LSMs or a seccomp filter that denied an earlier syscall. Its ring buffer is also bounded: reservation can fail, and the repository increments `DROPPED` on a failed reservation but the runner currently does not display that counter. Treat emitted records as application audit telemetry, not as complete Linux Audit subsystem records. A lost telemetry event must not silently change a decision already made.

#verifier-note(title: "What the verifier proves—and what it does not")[For the `file_open` sample, the verifier must establish that each reachable path returns an initialized `i32`, that nullable `file`, inode, superblock, and map lookup results are checked before use, and that the fixed map key/value accesses match their declarations. It also enforces the program type’s allowed helper and context rules. Acceptance does not prove a usable BPF LSM configuration, correct device/inode identity across every filesystem class, complete audit coverage, correct LSM ordering, or that a user-space consumer kept up. Preserve load logs and test the hook on the booted target. @bpf-verifier]

== A safe, reproducible procedure <sec-ch12-procedure>

Use a disposable VM for every attachment trial. Build as an ordinary user; do not run Cargo as root. First, build and run the attachment-free preflight from the repository’s `samples` directory:

#terminal-listing(title: "Build normally and run the read-only preflight", "cd /home/ubuntu/learn-eBPF-00/samples\ncargo xtask build-ebpf\ncargo build -p sample-runner\ntarget/debug/sample-runner lab-check") <lst-ch12-preflight-command>

The first two build commands require the repository’s pinned toolchain and BPF build dependencies. A build failure is a setup result, not a reason to run Cargo with elevated privilege. The last command remains safe to run as an unprivileged user. Record the kernel release, all matrix rows, architecture, and the complete active-LSM list if readable:

#terminal-listing(title: "Record target facts without changing policy", "uname -r\nuname -m\ncat /sys/kernel/security/lsm 2>/dev/null || true\nfindmnt -t cgroup2,bpf,tracefs\nls -l /sys/kernel/btf/vmlinux 2>/dev/null || true") <lst-ch12-target-facts>

Only if the preflight shows a readable BTF file and active `bpf` LSM, and only in a VM that can be restored, create a dedicated disposable file and cgroup leaf. The next commands prepare an *audit-only* observation. They neither use `--enforce` nor modify a pre-existing workload cgroup.

#terminal-listing(title: "Prepare disposable audit resources", "sudo install -d -m 0700 /tmp/learn-ebpf-demo\nsudo sh -c 'printf audit-only > /tmp/learn-ebpf-demo/protected'\nsudo mkdir /sys/fs/cgroup/learn-ebpf-demo") <lst-ch12-audit-setup>

In terminal A, place only the short-lived loader in the new leaf and run the audit sample. `exec` makes the shell process become the runner; the runner holds the attachment only for the bounded duration and its drop path detaches it. The root requirement here is the current runner implementation’s guard and the target’s actual policy; it is not a statement that UID 0 is the minimal possible kernel credential.

#terminal-listing(title: "Terminal A: run the LSM sample in audit mode", "cd /home/ubuntu/learn-eBPF-00\nsudo sh -c 'echo $$ > /sys/fs/cgroup/learn-ebpf-demo/cgroup.procs; exec samples/target/debug/sample-runner run 12-lsm-file-audit --protect /tmp/learn-ebpf-demo/protected --cgroup /sys/fs/cgroup/learn-ebpf-demo --duration 30'") <lst-ch12-audit-run>

While terminal A observes, terminal B joins a short-lived test shell to the same leaf and opens the file. This is an access test, not a denial test; `cat` should still succeed.

#terminal-listing(title: "Terminal B: generate one scoped audit observation", "sudo sh -c 'echo $$ > /sys/fs/cgroup/learn-ebpf-demo/cgroup.procs; cat /tmp/learn-ebpf-demo/protected'") <lst-ch12-audit-trigger>

=== Expected output and interpretation <sec-ch12-expected-output>

#expected-output(title: "Evidence, not a fabricated pass")[`lab-check` always begins with `learn-eBPF lab feature matrix (read-only)`, prints seven labelled `supported` or `unsupported` rows, and ends with its attachment-conditional result sentence. The individual statuses are environment-gated and must be recorded rather than predicted. In a compatible VM, the audit runner prints its configured `policy device=... inode=... cgroup=... mode=AUDIT` line, then `attached 12-lsm-file-audit; observing for 30s (drop detaches)`. A successful matching open can produce an `event kind=10` line with `action=0`; the repository code does not guarantee delivery if the ring buffer is full. The file read should print `audit-only` rather than permission denied.]

If the target lacks BTF, lacks `bpf` in its active LSM list, has no compatible hook, or the loader lacks authority, stop at the clear failure and keep the result as a capability-profile fact. Do not alter the boot LSM list, grant blanket privileges, or retry against a non-disposable host simply to obtain output. If the audit event does not appear, check cgroup membership, the exact file identity, and ring-buffer health before inferring that the hook did not run.

=== Denial remains an explicit, separate opt-in <sec-ch12-denial-boundary>

The next sample, `13-lsm-file-enforce`, uses the same shared decision routine but permits `-EACCES` only when *all* of these conditions hold: the user supplied `--enforce`; the currently opened object matches the configured `(device, inode)`; and the task’s current cgroup ID equals the configured dedicated cgroup. Missing map state and failed identity reads allow in the reviewed code. This is a narrow learning guard, not a complete protected-file product: `file_open` does not cover every later access or execution path, and pseudo, overlay, Filesystem in Userspace (FUSE), network, and other filesystem classes require explicit policy treatment.

Do not add `--enforce` to the audit procedure. A denial trial belongs only after audit records, cgroup scope, cleanup, rollback, and the exact target behavior have been reviewed in a disposable recovery-capable VM. Never point it at a host configuration file, an existing production cgroup, or a broad path class. The safe default throughout this chapter is observe and report; enforcement is explicitly opt-in and narrowly scoped.

=== Cleanup <sec-ch12-cleanup>

Allow terminal A’s bounded runner to exit before removing resources. Then delete only the disposable objects created above. Both removal attempts are intentionally limited to the chapter’s names:

#terminal-listing(title: "Detach first, then remove disposable state", "sudo rm -f /tmp/learn-ebpf-demo/protected\nsudo rmdir /tmp/learn-ebpf-demo\nsudo rmdir /sys/fs/cgroup/learn-ebpf-demo") <lst-ch12-cleanup>

If the cgroup removal reports that it is busy, wait for the shell or runner placed in the leaf to exit; do not move unrelated processes merely to make cleanup succeed. This procedure does not pin BPF maps or links, so it leaves no intended bpffs state. Still verify that the runner ended normally before declaring the trial complete.

== Portability and deployment limits <sec-ch12-portability>

The documented introduction of `CAP_BPF` in Linux 5.8, BPF LSM support in the general Linux 5.7 era, and individual seccomp action/flag histories are orientation facts, not sufficient version gates. Distribution kernels backport features, omit configuration, and impose policy. BPF LSM additionally depends on BTF, kernel configuration, the active boot LSM list, exact hook eligibility, and object-specific verifier acceptance. Seccomp actions and flags should be probed before use. Cgroup v2 existence must be distinguished from a mounted, delegated target subtree. @capabilities @bpf-lsm @seccomp @cgroups-v2

The sample code itself adds further local limits. The runner rejects `run` when its effective UID is not zero, even though its error text mentions equivalent `CAP_BPF`/`CAP_PERFMON` authority. It has an IPv4-only cgroup-connect observer. It reads a cgroup ID by statting the supplied cgroup path, so the ID is host- and lifecycle-scoped rather than a permanent container identity. The shared event ABI is fixed-layout, in-host data; `repr(C)` and `Pod` do not make it a versioned cross-machine format. Finally, its ring-buffer loss counter is not presented by the current consumer. These are reasons to qualify a lab result, not defects a reader should hide with additional privilege.

== Exercises <sec-ch12-exercises>

#exercise(title: "Explain a failed preflight")[Run `lab-check` without elevated privilege. For each unsupported row, identify exactly what the code tested and one important fact it did *not* test. Explain why “effective root unsupported” does not alone answer whether a least-authority loader could work on a different target.]

#exercise(title: "Design two syscall budgets")[Without implementing a filter, list the expected categories of syscall for (1) an object loader that terminates after passing a read-only event interface and (2) a long-running event consumer. Mark which dependencies must be initialized before a filter is installed. Explain why `seccomp_data.arch` must be checked before a syscall number.]

#exercise(title: "Audit completeness argument")[Assume another LSM precedes `bpf` and denies one `file_open`. State whether the BPF LSM audit sample necessarily emits an event for that denial, why or why not, and what independent evidence would be required before making a complete-audit claim.]

#exercise(title: "Least-authority service split")[Sketch three processes—loader, policy writer, and consumer—and assign each its file descriptors, capability needs, seccomp budget, and cleanup responsibility. Identify one authority that must not be shared from the loader to the consumer.]

== Chapter summary <sec-ch12-summary>

Seccomp, capabilities, user namespaces, cgroups, LSMs, and eBPF are complementary controls. A cBPF seccomp filter reduces syscall surface; it is not eBPF policy. Capability names and UID 0 do not prove a BPF action will succeed, and user namespaces make “root” scope-sensitive. LSM order constrains authorization and later audit visibility; BPF-LSM programs preserve preceding BPF decisions.

`00-lab-check` records limited environment facts without claiming attachment success. The prior labs provide scoped telemetry, not permanent container identity. The LSM audit sample demonstrates a narrow identity/cgroup predicate and previous-result preservation, but its runtime is boot-kernel-gated and telemetry bounded. Preflight, build normally, audit in a disposable VM, capture evidence, clean up, and only then review whether a narrow opt-in denial is justified.

== Next steps <sec-ch12-next-steps>

No subsequent chapter source is present in this repository at authoring time, so this chapter intentionally does not create a dangling clickable chapter reference. In the planned sequence, proceed to the next chapter on control-plane state, pins, tail calls, and upgrades before attempting any durable policy deployment: the map schema, ownership, activation boundary, rollback window, and attachment lifecycle are part of the security design.

#bibliography("../../references.yml", style: "ieee")
