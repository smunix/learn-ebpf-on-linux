#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, definition-target, figure-ref, listing-ref, section-ref, table-ref
// Import concise excerpts directly from canonical repository files.
// The short manifest below uses the shared `code-file` helper unchanged.
#let source-excerpt(path, title: none, language: "text", lines: none) = {
  let text = read(path)
  let selected = if lines == none { text } else {
    text.split("\n").slice(lines.first() - 1, lines.last()).join("\n")
  }
  code-listing(title, selected, language: language, source-path: path)
}


#chapter-opener(part: 4, chapter: 11)
= Namespaces, Cgroups, and Container Identity <ch-11>

A container is not a small virtual machine and it is not a single kernel object. It is a runtime-managed collection of Linux tasks to which several independent isolation and control mechanisms may have been applied. A task can have a private view of process identifiers, filesystems, and network devices while being placed in a host-managed resource hierarchy. It can also be UID 0 in its own user namespace without being privileged over the host. An eBPF program that observes one event must therefore be precise about which of these facts it has observed.

This chapter builds a durable attribution model: record an event-time kernel key, retain host and boot context, and join it to time-bounded runtime metadata. The companion is the audit-only `11-container-attribution` sample. It observes an execution tracepoint and emits a numeric cgroup identifier. It does *not* discover a Docker, containerd, or Kubernetes name, and its successful attachment remains environment-gated rather than a repository-wide promise.

== Prerequisites <ch11-sec-prerequisites>

Before proceeding, be comfortable with processes and threads, the distinction between kernel and user space, Rust's ownership model, and the basic eBPF lifecycle of load, attach, observe, and detach. The practical exercise assumes the repository's supported NixOS `x86_64-linux` development environment, a disposable virtual machine (VM), a readable tracefs event directory, and a cgroup version 2 (cgroup v2) mount. It also requires that the exact target authorizes the tracepoint program and its helpers. Build source as an ordinary user; invoke only the reviewed loader binary with the narrowly justified authority in the disposable VM. Do not run the exercise on a production host.

== Learning objectives <ch11-sec-objectives>

After this chapter, you should be able to distinguish a namespace's *view* from a cgroup's *control scope*; explain why a host process identifier (PID), a pathname, or a runtime label alone cannot establish container identity; and describe the roles of PID, mount, network, user, and cgroup namespaces. You should be able to read a cgroup v2 hierarchy without confusing a mutable path with a kernel identity, construct an event-time cgroup attribution record, and identify the missing control-plane data needed to name a workload. Finally, you should be able to run the companion observer safely, interpret its limited output, and clean up without pins or persistent policy.

== The mental model: one task, several domains <ch11-sec-mental-model>

A Linux task has multiple identities because different kernel subsystems answer different questions. A PID names a process in a PID namespace; a pathname is resolved through a mount namespace; network addresses are interpreted through a network namespace; credentials are scoped by a user namespace; and a cgroup locates the task in a resource and policy hierarchy. None is automatically a workload name.

#definition-target(
  "def-container-attribution",
  [Container attribution],
  [the association of an event-time cgroup identifier with time-bounded, host-side workload lifecycle metadata. Namespace inode evidence may explain isolation context, but it does not replace the cgroup join.],
)

This definition deliberately says *event-time*. If a supervisor moves a process after it executes, a later current-cgroup lookup can tell a different, yet individually correct, story. Similarly, a runtime can remove a workload and reuse a path or label. An attribution store must preserve when its runtime mapping was observed and the interval for which that mapping was valid.

#concept(
  title: [Isolation is plural, identity is scoped],
  [Treat a container as a set of related observations, not a value to reverse-engineer in an eBPF fast path. For a host-side observer, a current cgroup identifier is a useful kernel join key. A workload name, image digest, pod identifier, and owner are control-plane facts with their own lifecycle. A PID or a pathname is supplementary diagnostic context, not the universal key.],
)

#figure(
  image("../../assets/diagrams/generated/11-container-identity.svg", width: 100%),
  caption: [Container isolation layers converge on a host-observed attribution event. The available generated asset shows namespace views, cgroup v2 scope, and the distinct host task context.],
) <fig-container-isolation>

#figure-ref(<fig-container-isolation>, title: [container isolation and attribution]) is a useful corrective to a common diagrammatic mistake: drawing a container boundary around everything and calling the result an identity boundary. The kernel can report the task and its cgroup at a hook. The naming relationship to a runtime workload must be maintained outside that hook.

== Namespace views: five questions, not one boundary <sec-namespaces>

A namespace gives a task a view of a resource. It changes what the task can see or name; by itself it does not allocate a CPU share, impose a memory maximum, or guarantee a security policy. Linux exposes namespace handles beneath `/proc/<pid>/ns`. From a sufficiently privileged host observer, the device and inode pair of such a handle can establish that two observed tasks share that namespace. That pair is evidence about a selected namespace, not a container name.

=== PID namespace: whose PID is this? <sec-pid-namespace>

A PID namespace presents a process-numbering universe. A process can have one PID as seen from the host's initial namespace and another as seen from a nested namespace. The first process in a new namespace conventionally appears as PID 1 there, but the host still has a host PID for the same kernel task. Parent-child visibility follows the namespace nesting rules: a parent namespace can observe descendants, while a child cannot enumerate arbitrary ancestors.

This matters when joining an event to logs. The `pid` printed by the companion runner is intended as a host PID, and the record also carries a thread identifier (TID). Neither tells you what a process calls itself inside a container. Store the identity domain alongside the number: for example, `host_pid`, rather than merely `pid`. If an incident report contains a PID from `ps` executed inside a container, resolve it through a host observation made at the same time; never equate integers from unknown PID namespaces.

=== Mount namespace: paths are views <sec-mount-namespace>

A mount namespace determines the mount table through which a pathname is traversed. Two tasks can use the same underlying filesystem object but see it at different paths, or one can see a mount that the other cannot. Chroot-like directory roots, bind mounts, overlay filesystems, and container root filesystems therefore make a path valuable explanation but weak durable identity. This chapter does not reconstruct paths in eBPF, and the companion program does not read its tracepoint context or filesystem data.

The same caution applies to cgroup files. A cgroup namespace can virtualize the paths presented in `/proc/<pid>/cgroup` and `/proc/<pid>/mountinfo`; `/` inside that namespace can denote a host subtree rather than the cgroup v2 root. A path collected inside the workload is consequently not an authoritative host identity. Collect the host-side path and ancestry as time-bounded labels after the event, if an operator needs them.

=== Network namespace: a separate network stack <sec-network-namespace>

A network namespace provides an isolated set of network interfaces, addresses, routes, firewall state, and related networking resources. A container can have a private virtual Ethernet interface, share the host network namespace, or join another workload's network namespace. Thus an address such as `127.0.0.1`, an interface name such as `eth0`, or a socket's local address is meaningful only with its network-namespace context. Network namespace membership says nothing by itself about the workload's CPU or memory control scope.

=== User namespace: root has a domain <sec-user-namespace>

A user namespace maps user identifiers (UIDs) and group identifiers and gives capabilities a namespace-relative meaning. A task that is UID 0 inside a user namespace can have capabilities over resources owned by that namespace while lacking the corresponding authority in the parent or initial user namespace. “Container root” is therefore not a deployment authorization answer for host-wide eBPF operations. Linux capabilities split traditional superuser authority into per-thread privilege bits, but the needed authority remains operation-, program-type-, kernel-policy-, and namespace-dependent.#cite(<capabilities>)

For a loader, test the actual service identity rather than inferring permission from UID 0 or from one capability name. The repository runner is deliberately more conservative than the kernel model: its `require_root` function rejects any effective user ID other than zero, even though its error text mentions equivalent BPF and performance-monitoring capabilities. That source-level gate is an implementation limitation, not evidence that every tracepoint deployment requires host root.

=== Cgroup namespace: a cgroup path is still a view <sec-cgroup-namespace>

A cgroup namespace virtualizes the cgroup hierarchy presentation for member tasks. It should not be confused with cgroup v2 itself. The former changes what paths a task sees; the latter is the unified hierarchical mechanism for resource control and cgroup-attached policy. A cgroup namespace may make a host subtree look like `/`, which is exactly why an in-container cgroup path cannot be promoted to a host-wide container identifier.

== Cgroup v2: hierarchy, scope, and runtime placement <sec-cgroup-v2>

Cgroup v2 places tasks in one unified tree. Controllers such as CPU, memory, and I/O operate according to the hierarchy's rules; a parent enables a domain controller for children, and children cannot use it unless that top-down enablement exists. A parent also cannot disable a controller while descendants still use it.#cite(<cgroups-v2>) These rules matter operationally because an agent must attach or delegate at the scope it actually intends, rather than at a guessed runtime path.

A related rule is the no-internal-process constraint for ordinary domain-controller subtrees. A non-root domain cgroup that distributes a domain resource to children should not itself contain processes; processes normally live in leaf cgroups. Threaded subtrees have distinct rules and are not an introductory shortcut around the hierarchy. Delegation is similarly narrow: an administrator grants a controlled subtree and selected cgroup interface files, not indiscriminate write access to the host cgroup filesystem.#cite(<cgroups-v2>)

A runtime commonly creates cgroups, configures namespaces, and launches workload and helper processes; the details are runtime- and configuration-specific. One logical workload may use multiple cgroups, and systemd units also use cgroups. Thus an identifier can describe a service scope rather than an Open Container Initiative (OCI) container. The reliable conclusion is modest: the task was in *this cgroup* at the event; runtime naming is a host control-plane question.

#figure(
  kind: "table",
  supplement: [Table],
  caption: [Identity domains for host-side attribution. Each row answers a different question and should be stored with its scope and observation time.],
  table(
    columns: (1.25fr, 1.35fr, 1.55fr, 1.55fr),
    inset: 5pt,
    stroke: 0.4pt + rgb("#B8CDD2"),
    table.header([*Observation*], [*Answers*], [*Useful for*], [*Insufficient by itself because*]),
    [`host PID` / `TID`], [Which host task or thread emitted the event?], [Correlating host logs and `/proc` observations], [PID namespaces and reuse make a bare number ambiguous over time.],
    [`cgroup_id: u64`], [Which cgroup contained the task at the hook?], [Fast event key; policy/resource scope], [Tasks migrate; the value is not a global runtime name.],
    [Host cgroup path and ancestry], [How did the host currently label that hierarchy?], [Operator diagnostics and runtime reconciliation], [Paths can be renamed and namespace-virtualized.],
    [Namespace `(st_dev, st_ino)` pair], [Which selected isolation view did a host observer see?], [Explaining PID, mount, user, or network context], [It names a namespace handle, not a workload.],
    [Runtime workload UID and labels], [Which workload did the control plane associate with the cgroup?], [Human-meaningful reports and ownership], [Metadata can be stale, reused, or unavailable.],
  ),
) <tbl-identity-domains>

The consequence of #table-ref(<tbl-identity-domains>, title: [identity domains]) is a two-plane design. The eBPF data plane should obtain only small kernel facts that are available at the hook. A host reconciler should observe cgroup lifecycle, resolve runtime metadata, and retain an interval such as `[observed_from, observed_until)`. Queries then join an event using its event time, host identifier, boot identifier, and cgroup ID. If no mapping covers the event time, report `unattributed` or `ambiguous`; do not silently attach the event to the cgroup's present-day occupant.

== The companion observer: what it actually records <sec-companion>

The manifest in #listing-ref(<lst-container-manifest>, title: [the sample manifest]) binds this exercise to the shared `container_attribution` program and the `sample-runner`. It does not describe a runtime integration layer.

#source-excerpt(
  "../../../samples/11-container-attribution/sample.toml",
  title: [Manifest selecting the Chapter 11 program],
  language: "toml",
) <lst-container-manifest>

The program is a tracepoint program. The runner attaches it to the `syscalls/sys_enter_execve` static tracepoint; this is an execution-attempt observation point, not a container lifecycle callback. The selected function ignores the tracepoint context, constructs a base event, and sets `value` to the current cgroup identifier.

#source-excerpt(
  "../../../samples/ebpf-programs/src/main.rs",
  title: [Canonical `container_attribution` eBPF program],
  language: "rust",
  lines: (193, 202),
) <lst-container-program>

The shared event constructor is the other half of the record contract. It obtains a nanosecond timestamp, current cgroup ID, PID/TID pair, UID, and command name; it uses a default-initialized `Event` for the remaining fields. The program's `value` therefore duplicates `cgroup_id` for this sample. This redundancy may aid a narrow classroom check, but it is not a substitute for a versioned attribution schema.

#source-excerpt(
  "../../../samples/ebpf-programs/src/main.rs",
  title: [Shared base-event construction and bounded ring-buffer submission],
  language: "rust",
  lines: (72, 105),
) <lst-event-base>

The user-space runner loads the named `TracePoint`, then attaches it to the fixed category and event shown below. The attachment has no `--cgroup` argument: it observes executions system-wide and reports each triggering task's current cgroup. This is why the exercise can contrast an execution in a dedicated test cgroup with one outside it.

#source-excerpt(
  "../../../samples/runner/src/main.rs",
  title: [Canonical runner attachment for the sample],
  language: "rust",
  lines: (605, 610),
) <lst-container-attach>

Do not over-read the event. The record has no host identifier, boot identifier, runtime workload UID, namespace inode pairs, cgroup path, controller state, or reconciliation interval. It does carry a schema version, record length, kind, flags, and reserved-zero fields, and the runner validates them with byte-wise native-endian reads before formatting. It remains an in-host teaching record, not a durable cross-host protocol. The runner also reports producer reservation loss and consumer parse rejection, but bounded transport still means a missing event is not proof that no execution occurred.#cite(<bpf-map>)#cite(<bpf-ringbuf>)

== Event-time attribution procedure <sec-attribution-procedure>

An honest host-side attribution pipeline has four steps. First, at the hook, emit `{timestamp_ns, cgroup_id, host_pid, tid, uid, comm, kind}` and any separately defined schema and generation values. Second, an authorized host reconciler records cgroup creation, removal, host path, ancestry, and selected namespace handle pairs, then associates that cgroup with runtime metadata and an observation interval. Third, a query joins the event to a mapping only if the host and boot contexts match and the event time lies inside that interval. Finally, it makes uncertainty explicit: missing runtime metadata, unavailable `/proc` namespace handles, migration races, and ring-buffer loss are recorded as states rather than hidden by a best-effort name.

Namespace evidence is optional and question-driven. PID pairs explain different process numbers; mount pairs explain divergent paths; network pairs contextualize interfaces; and user pairs explain why apparent root may lack host authority. A reconciler can collect selected evidence at lifecycle boundaries or on an investigation path rather than on every event.

#kernel-detail(
  title: [A cgroup identifier is a scoped kernel key],
  [The helper used by #listing-ref(<lst-container-program>, title: [the eBPF program]) is evaluated for the current task at the tracepoint. The result is appropriate for keyed attribution and cgroup-scoped policy only after you specify host and lifecycle scope. It is not an immutable, cross-boot, cross-host, or orchestration-independent container ID. If a task migrates, later events correctly carry a different key.],
)

== Safe, reproducible observation in a disposable VM <ch11-sec-safe-procedure>

The following is a bounded observation procedure, not a production deployment recipe. It deliberately avoids pins, cgroup-attached enforcement, host tuning, and runtime-specific path parsing. Use two terminals in a disposable NixOS VM whose cgroup v2 mount is `/sys/fs/cgroup` and writable by the administrator. Stop if any preflight fails; do not lower kernel security settings or grant broad capabilities to make the sample run.

In the first terminal, enter the pinned development shell, build as your ordinary user, and inspect the actual tracepoint and cgroup v2 mount. The format is inspected because tracepoints are target-local interfaces, even though this program deliberately does not decode any fields.

#terminal-listing(
  title: [Terminal A — build and read-only preflight],
  "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\ncd samples\ncargo xtask build-ebpf\ncargo build -p sample-runner\n\nTRACEFS=/sys/kernel/tracing\n[ -d \"$TRACEFS/events\" ] || TRACEFS=/sys/kernel/debug/tracing\ntest -r \"$TRACEFS/events/syscalls/sys_enter_execve/id\"\ncat \"$TRACEFS/events/syscalls/sys_enter_execve/id\"\nsed -n '1,12p' \"$TRACEFS/events/syscalls/sys_enter_execve/format\"\nfindmnt -t cgroup2",
)

If those checks succeed, start only the already-built loader binary for a short interval. The runner caps `--duration` at 60 seconds. Its source currently requires effective UID 0 before attempting attachment, so this step uses `sudo` for the binary only—not for Cargo or the build scripts.

#terminal-listing(
  title: [Terminal A — bounded audit-only observation],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\nsudo ./target/debug/sample-runner run 11-container-attribution --duration 10",
)

While that command is observing, use the second terminal to create one disposable leaf cgroup, display its numeric directory inode through the runner's `cgroup-id` command, then execute `/bin/true` from that leaf. The `exec` replaces the temporary shell, producing a predictable `execve` trigger. This changes cgroup placement only in the disposable VM and creates no policy; do not adapt it to a managed production hierarchy.

#terminal-listing(
  title: [Terminal B — trigger one execution from a disposable cgroup],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\nsudo mkdir /sys/fs/cgroup/learn-ebpf-attribution\nsudo ./target/debug/sample-runner cgroup-id /sys/fs/cgroup/learn-ebpf-attribution\nsudo sh -c 'printf \"%s\\n\" \"$$\" > /sys/fs/cgroup/learn-ebpf-attribution/cgroup.procs; exec /bin/true'",
)

The last command exits promptly. An execution launched outside the test cgroup is a useful negative control: it should have a different cgroup number, but it does not prove that either event has a runtime container name. Keep any captured output with the VM's kernel release, build revision, object hash, and the preflight results if you intend to call the exercise tested on that target.

== Expected output and its limits <ch11-sec-expected-output>

#expected-output(
  title: [What success looks like],
  [On a target where the object loads and attaches, the runner first prints `attached 11-container-attribution; observing for 10s (drop detaches)`. An execution during that interval can then produce a line in the shape `event kind=9 pid=<host-pid> tid=<host-tid> uid=<uid> cgroup=<numeric-id> action=0 value=<numeric-id> dev=0 ino=0 comm=true`. Angle-bracketed values are target-dependent, and unrelated executions may appear because the hook is system-wide. Compare `cgroup` and `value` with the numeric ID printed for the disposable cgroup; do not expect a container name.],
)

The output is evidence only of a conditional run paired with successful load and attachment on the stated host. It does not prove complete auditing, a stable record ABI, correct runtime correlation, or portability. Repository continuous integration does not load or attach these programs. Treat source review, compilation, verifier acceptance, attachment, and semantic attribution as separate facts.

== Verifier reasoning <ch11-sec-verifier-reasoning>

The small body of #listing-ref(<lst-container-program>, title: [the attribution program]) is deliberately easier to reason about than a context-decoding tracepoint. It does not read a tracepoint field or calculate a raw offset, so it needs no target-specific layout proof for `sys_enter_execve`. It passes no task or kernel pointer to the helper. The function returns a defined zero on its only path, as required by its tracepoint program contract.

The safety proof continues in the shared helpers. `base` constructs an `Event` with named fields and a default for all remaining fields, avoiding intentionally uninitialized record bytes. `emit` checks whether ring-buffer reservation succeeded before writing the event; on success, it submits exactly that reservation, and on failure it attempts to increment the per-CPU drop counter. The `DROPPED` pointer itself is tested with `if let Some` before the unsafe write. These are local program invariants, not a promise that any helper is available to every tracepoint program on every target. The verifier must accept the emitted object under the target's program type, helper allowlist, configuration, and authority; verifier acceptance also does not prove the user-space decoding or attribution model semantically correct.#cite(<bpf-verifier>)

#verifier-note(
  title: [No context decoding is an intentional portability choice],
  [The hook name and its availability still require a target check. What this sample avoids is a hard-coded tracepoint field offset. If a later version reads syscall arguments or task structures, it needs a local format or BTF proof, a compatible object variant, and a separate verifier and Rust-safety review.],
)

== Portability and enforcement boundaries <ch11-sec-portability>

This sample is environment-gated by accessible `syscalls/sys_enter_execve`, a usable cgroup v2 hierarchy, successful object verification and load, adequate BPF/performance-tracing authority, and the runner's effective-UID gate. A cgroup v2 filesystem in `/proc/filesystems` is weaker evidence than a mounted, accessible hierarchy at the intended scope. An absent namespace handle may reflect permissions rather than absence of isolation.

#portability-note(
  title: [Feature probe, then downgrade honestly],
  [Kernel release numbers alone are not support contracts. Record the booted kernel, architecture, tracefs path, cgroup v2 mount, effective service identity, object build identity, and actual error or success. If attachment is denied, the tracepoint is unavailable, or cgroup v2 cannot be inspected, report attribution unavailable for this sample. Do not substitute another hook, change `perf_event_paranoid`, disable unprivileged-BPF restrictions, or add broad `CAP_SYS_ADMIN` merely to obtain output.],
)

The sample has no enforcement branch for `11-container-attribution`: it attaches the tracepoint regardless of the CLI's generic `--enforce` flag and returns zero from the eBPF program. It neither permits nor denies the observed execution. This is the correct scope for an attribution lesson. In later policy work, audit is the default; any denial must be explicit opt-in, restricted to a disposable cgroup and recovery-capable VM, and evaluated independently of telemetry delivery. Secure computing mode (seccomp) may reduce a process's system-call surface, but it is complementary to namespaces, capabilities, Linux Security Modules, and application design rather than a replacement for them.#cite(<seccomp>)

== Cleanup <ch11-sec-cleanup>

Allow Terminal A's fixed-duration command to return normally. The runner states that dropping its owned objects detaches, and this sample creates no bpffs pin. Do not rely on an interrupted interactive run as a cleanup test; prefer the short duration, then verify that the command exited. After the `/bin/true` trigger has exited, remove the disposable leaf cgroup:

#terminal-listing(
  title: [Remove the disposable cgroup after the trigger exits],
  "sudo rmdir /sys/fs/cgroup/learn-ebpf-attribution",
)

If removal reports that the cgroup is busy, inspect membership in the disposable VM before retrying; do not remove a parent cgroup or move unrelated workloads. Capture any load/attach failure and leave the host configuration unchanged. There are no maps, links, or pins for the reader to manually delete in the normal bounded path.

== Exercises <ch11-sec-exercises>

#exercise(
  title: [Compare identity domains],
  [Run the bounded observer once with the `/bin/true` trigger in the disposable cgroup and once outside it. Record the host PID, command, and cgroup number. Which fields change? Which fields are absent that would be needed to state a runtime workload name? Write a proposed control-plane table with host ID, boot ID, cgroup ID, observed-from, observed-until, and workload UID.],
)

#exercise(
  title: [Inspect views without asserting identity],
  [For an authorized test process, compare `readlink /proc/<host-pid>/ns/pid`, `mnt`, `net`, `user`, and `cgroup` with those of a host process. Explain what equality or inequality of the handles establishes. Then explain why neither result proves that the process is, or is not, a particular runtime container.],
)

#exercise(
  title: [Design a migration-aware join],
  [Sketch records for a task observed in cgroup A at time T1, moved to cgroup B at T2, and executed again at T3. Define the interval logic that joins the first execution to A and the second to B. Include an explicit outcome for a missing interval and a counter for unmatched events. Do not solve this by looking up only the current cgroup path.],
)

== Chapter summary <ch11-sec-summary>

Namespaces and cgroups answer distinct questions. PID, mount, network, user, and cgroup namespaces define views and scoped privileges; cgroup v2 supplies a hierarchical resource and policy scope. A container runtime composes these mechanisms but does not turn them into one durable kernel identifier. Host PID/TID, cgroup ID, namespace inode evidence, host cgroup path, and runtime labels each have a valid but limited identity domain.

The companion program is intentionally narrow: at `sys_enter_execve`, it emits a fixed in-host event containing the current cgroup ID and related task fields. Its cgroup ID is a strong event-time join key for a host's live hierarchy, not a container name. Correct attribution requires host and boot context plus a time-bounded control-plane mapping. Its output, verifier acceptance, and attachment are all target-specific evidence, while ring-buffer loss and the unversioned record format constrain what the output can prove.

== Next steps <ch11-sec-next-steps>

Continue with #chapter-ref(<ch-12>, title: [Seccomp, Capabilities, and eBPF]). It distinguishes execution filtering, privilege decomposition, observation, and LSM policy so that cgroup attribution is not mistaken for authority or isolation by itself.

#bibliography("../../references.yml")
