#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": chapter-ref, section-ref, figure-ref, table-ref, listing-ref, definition-target
#import "../../components/terms.typ": acronym

#chapter-opener(part: "VI", chapter: "18")
= From Audit to Enforcement <ch-18>

A file-opening rule becomes a security control only when its scope, identity, decision, evidence, and removal path agree. This chapter finishes the protected-file capstone by moving from an observation that is useful for learning to an operational design that can be reviewed and reversed. The current repository samples are deliberately small. They demonstrate an audit-first decision path for a single file identity and a dedicated cgroup; they are not evidence of a production-ready policy service. Treat every attachment in this chapter as *environment-gated* until it has loaded, attached, and detached successfully on the booted target kernel.

== Prerequisites <ch18-sec-prerequisites>

You should have completed the earlier work on maps, fixed event records, control groups (cgroups), verifier reasoning, and Berkeley Packet Filter (BPF) Linux Security Module (LSM) fundamentals. In particular, be comfortable separating an extended Berkeley Packet Filter (eBPF) program from its user-space loader, reading a BPF map lookup as a fallible operation, and describing an LSM hook’s return contract. Use an authorized, recovery-capable virtual machine (VM) with a disposable cgroup v2 subtree. Do not use a developer workstation, a production service cgroup, a real credential store, or a protected system path.

The two primary samples are `13-lsm-file-enforce` and `14-sentinel-capstone`. Both currently share the same underlying file-open implementation and runner. Their readme files state that they are audit-only by default and that denial requires an explicit `--enforce` flag, a matching protected `(device,inode)` identity, and a matching dedicated cgroup identifier. Their runtime behavior remains conditional on target BTF, active BPF LSM support, cgroup v2, sufficient authority, and successful verification and attachment.

== Learning objectives <ch18-sec-objectives>

After this chapter, you should be able to explain why a pathname is diagnostic context rather than a robust primary authorization key; construct the limits of a device-and-inode policy; distinguish a global BPF LSM program with a cgroup predicate from a cgroup-LSM attachment; and name the conditions under which the sample can return `-EACCES`. You should also be able to design an audit-first rollout, treat ring-buffer loss independently from authorization, outline a two-generation policy update, and perform a narrow rollback drill without leaving BPF objects pinned or a broad denial policy attached.

== The mental model: a decision at an object boundary <ch18-sec-mental-model>

The Linux Virtual File System (VFS) resolves a request into a `struct file` before the `file_open` LSM hook sees it. This is a much more useful decision point than a string typed by an application: the rule can be about the resolved file object, not the spelling that happened to find it. For an ordinary integer-returning BPF LSM authorization hook, zero permits and a negative errno denies; a prior nonzero result from an earlier BPF LSM program must be returned unchanged. The BPF LSM documentation describes this chained return result and the program-type-specific authorization model. #cite(<bpf-lsm>)

#definition-target("def-authorization-contract", "Authorization contract")[For this capstone, authorization is a small function of a prior BPF-LSM result, a resolved file identity, a policy-map match, an explicit operating mode, and the current task’s cgroup ID. Telemetry records the result; it does not decide the result.]

A narrowly stated goal is therefore: *while a program is attached, deny the act of opening one disposable regular-file object only when the current task is in one dedicated cgroup and the operator has explicitly enabled enforcement.* This statement is intentionally smaller than “protect this path” or “protect this file forever.” `file_open` gates the resolved file open; it does not alone cover every possible later read, memory mapping, execution, descriptor inheritance, mount-topology change, or other filesystem access path. Choosing a hook is a coverage analysis, not an opportunity to claim blanket protection.

The scope has three independent gates. First, the resolved object must match a policy entry. Second, the actor must match the configured cgroup. Third, the operator must turn on enforcement. In audit mode, the same matching identity produces an event but the hook returns zero. In enforcement mode, the same match returns `-EACCES` (the conventional “permission denied” errno) only if all gates pass. This is a useful learning pattern because a missing rule, a failed identity read, or a missing configuration does not suddenly deny unrelated system activity.

#concept(title: "Audit and enforcement must share the predicate")[An audit run is meaningful only if it evaluates the same file identity, workload scope, mode switch, and reason taxonomy that enforcement will use. Merely logging a pathname in one program and denying an inode in another does not validate a future deny rule.]

Figure #figure-ref(<fig-capstone-architecture>, title: "the audit-to-operations feedback loop") separates the kernel data plane from the user-space control plane. It is an intended capstone architecture, not a claim that sample 14 already supplies each service component. The shipped sample has one `POLICY` hash map, one `CONFIG` array entry, one ring buffer, and an in-process consumer. It has no active-generation selector, persistent manifest, or reconciliation service.

#figure(
  image("../../assets/diagrams/generated/18-capstone-architecture.svg", width: 100%),
  caption: [Capstone architecture: resolve a protected object in user space, populate policy state, make the `file_open` decision in BPF LSM, and feed auditable rationale and health information back to an operator.]
) <fig-capstone-architecture>

== What the current samples actually implement <sec-current-samples>

Sample 13 maps to the `lsm_file_enforce` BPF program; sample 14 maps to `sentinel_file_open`. Both call the same `file_decision` function with denial enabled. The runner opens target BTF from `/sys/kernel/btf/vmlinux`, loads the selected program on `file_open`, and attaches it as an ordinary, global LSM program. The program is *not* attached with Aya’s `LsmCgroup` facility and it does not use an `#[lsm_cgroup]` section. Its cgroup scope is a predicate inside a globally attached hook.

That distinction matters. Cgroup LSM is a separate attachment model with cgroup hierarchy and boolean-grant aggregation semantics, rather than the familiar errno-style logic of an ordinary BPF-LSM MAC hook. Returning zero because “zero allows” in a global hook can be wrong in cgroup LSM. The current sample wisely does not pretend to demonstrate that advanced attachment type. Kernel documentation treats cgroup v2 as a hierarchy with its own lifecycle and delegation constraints; do not call a path in that hierarchy a stable container identity. #cite(<cgroups-v2>)

The BPF-side implementation is shown verbatim in #listing-ref(<lst-file-decision>, title: "the shared file decision path"). It preserves a prior BPF verdict, reads `f_inode`, obtains `i_ino` and `i_sb->s_dev`, consults the `POLICY` map, reads `CONFIG`, emits an `Event`, and returns either zero or `-EACCES`. Each pointer and map lookup is expressed as an `Option`; a failure before a policy match returns zero. The policy value itself is a byte (`u8`): its content is not consulted after a successful presence test.

#code-listing(
  "Shared BPF LSM identity extraction and decision path",
  read("../../../samples/ebpf-programs/src/main.rs").split("\n").slice(194, 252).join("\n"),
  language: "rust",
  source-path: "samples/ebpf-programs/src/main.rs"
) <lst-file-decision>

On the user-space side, `configure_policy` obtains the protected path’s `st_dev` and `st_ino` through `MetadataExt`, obtains the cgroup path’s inode number, inserts a `FileIdentity` into `POLICY`, and writes `EnforcementConfig` into element zero of `CONFIG`. The runner rejects `--enforce` unless the lexical protected path begins under `/tmp/learn-ebpf-`. This is a valuable safety rail, but it is not a replacement for a filesystem inventory or a rollback plan. The runner also enforces an effective user identifier (UID) of zero before every `run` operation. Its diagnostic mentions equivalent BPF/performance-monitoring capabilities, but its code checks only `geteuid() == 0`; do not represent the implementation as a least-capability deployment.

#code-listing(
  "Runner policy configuration and explicit enforcement gate",
  read("../../../samples/runner/src/main.rs").split("\n").slice(182, 215).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-runner-config>

The runner prints the selected `device`, `inode`, cgroup ID, and mode; retains the `Ebpf` owner while consuming events for at most 60 seconds; and then returns, allowing its in-memory maps and attachment state to be dropped. It creates no bpffs pin by default. `action=1` in a printed event means that the BPF program selected its denial action; `action=0` is an audit or out-of-scope outcome. The following is the exact dispatch and bounded observation loop, not pseudocode. It also reveals an operational limitation: the consumer accepts an event as an `Event` solely when the byte length equals `size_of::<Event>()`.

#code-listing(
  "Sample 13 and 14 dispatch with bounded event consumption",
  read("../../../samples/runner/src/main.rs").split("\n").slice(320, 386).join("\n"),
  language: "rust",
  source-path: "samples/runner/src/main.rs"
) <lst-runner-lifecycle>

== Device plus inode: strong against names, bounded by filesystem semantics <sec-identity>

An inode number identifies an object only within a filesystem. Pairing it with a filesystem discriminator is therefore the minimum conceptual shape for this kind of policy. The samples use the superblock device field, widened to `u64`, plus `i_ino`; user space inserts a key from `st_dev` and `st_ino`. This is an *in-session, target-specific identity assumption*, not a durable global file name. The source binding used for `file`, `inode`, and `super_block` is a small hand-maintained structural binding with a comment directing regeneration on a BTF-enabled build host. It must be generated, relocated, and tested against the target before the field reads should be trusted as portable. BPF Type Format (BTF) and Compile Once – Run Everywhere (CO-RE) relocation help adapt eligible type access, but neither makes a filesystem’s meaning uniform. #cite(<libbpf-core>)

#figure(
  table(
    columns: (1.1fr, 1.45fr, 1.55fr),
    inset: 6pt,
  stroke: 0.45pt + rgb("#B8CDD2"),
  table.header(
    [*Case*], [*What device + inode represents*], [*Capstone disposition*],
  ),
  [Hard link], [Another directory entry for the same inode on one filesystem.], [The same key should match, so a protected object remains protected through the alternate name. Test this in audit mode before relying on it.],
  [Rename], [A new pathname for the same inode within a filesystem.], [The same key should match after the rename. A path-prefix policy would express a different and harder requirement.],
  [New regular file], [Usually a distinct inode, even in the same directory.], [It should not match the old rule. Inode reuse after deletion is a lifecycle concern; this sample does not include inode generation.],
    [Overlay, FUSE, network, pseudo, or anonymous filesystem], [The observed `s_dev` and inode semantics can be layered, synthetic, remote, or unsuitable for the intended asset.], [The current code does not classify these cases. Treat them as unsupported until a target-specific policy class and tests exist.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Identity cases and required interpretation for device-and-inode policy keys.]
) <tab-identity-cases>

#table-ref(<tab-identity-cases>, title: "Identity cases and required interpretation") describes why hard links and renames are a feature of object identity rather than an edge case. A hard link should lead to the same inode, so an inode-keyed rule naturally covers it. A rename typically changes a directory entry but not the inode, so the rule continues to apply. By contrast, a requirement such as “allow this object only through this one directory entry” is not solved by this key. It would require careful dentry, mount, namespace, and race analysis; do not conceal that distinct requirement under a path-prefix map.

Overlay filesystems deserve particular restraint. A visible pathname can refer to an upper layer, lower layer, or merged view whose device and inode interpretation does not match the policy author’s mental model. Filesystem in Userspace (FUSE), Network File System (NFS), `procfs`, `sysfs`, and in-memory filesystems pose related questions. The sample does not check mode bits, filesystem type, regular-file class, or inode generation. It consequently cannot emit `IDENTITY_UNSUPPORTED`, distinguish an identity-read failure from a policy miss, or safely support a broad family of filesystems. The correct response is not to add a broad deny; it is to keep those identities out of scope until audit data and a specific policy class justify them.

#kernel-detail(title: "Paths remain valuable—but as evidence")[Path resolution depends on a task’s root, current directory, mount namespace, symbolic links, and mount topology. A resolved path can help an operator diagnose an event in user space, but it should not be silently promoted to the BPF-side authorization identity. The sample intentionally never reconstructs a full pathname in eBPF.]

== Fail open deliberately, not accidentally <sec-fail-open>

“Fail open” is sometimes used as shorthand for “ignore errors.” That is not a design. It should name a condition, its bounded scope, its selected disposition, its evidence, its owner, and its rollback action. In the samples, several conditions allow: a nonmatching object, a missing policy entry, a null or unreadable file/inode/superblock pointer, a missing `CONFIG` entry (via a default configuration), and any absent `--enforce` flag. An earlier nonzero BPF-LSM return is different: it is preserved rather than converted to allow. These rules make the sample availability-first and prevent accidental broad denial during a learning exercise.

A ring buffer is also not an authorization oracle. The BPF helper reserves space for a fixed `Event`; if reservation fails, `emit` increments the per-CPU `DROPPED` counter and returns. The caller then returns the decision it already made. A ring buffer is bounded; a reservation can fail rather than block, and successful reservations have strict submit-or-discard obligations. #cite(<bpf-ringbuf>) #cite(<bpf-verifier>) The sample follows the reservation ownership rule, but the runner never reads or reports `DROPPED`. Thus a quiet terminal does *not* prove that no matching opens occurred.

#security-note(title: "Never couple visibility to permission")[For an audit-first system, an unavailable event transport must not convert a would-have-been denial into allow, nor an allow into denial. Preserve the decision, increment a measurable loss counter, and alert from an independent health path. In this repository, the counter exists but is not surfaced; treat telemetry completeness as unproven.]

Table #table-ref(<tab-failure-contract>, title: "Failure contract for the sample and a mature successor") distinguishes the current source from the behavior a real protected scope needs. A mature policy may deliberately fail closed for a narrow secret-store object during an identity or policy-generation failure, but only after its inventory, recovery route, and rollback have been demonstrated. That is a threat-model decision, not a default consequence of a null map lookup.

#figure(
  table(
    columns: (1.25fr, 1.35fr, 1.5fr),
    inset: 6pt,
    stroke: 0.45pt + rgb("#B8CDD2"),
    table.header([*Condition*], [*Current sample result*], [*Operational requirement before narrow denial*]),
    [Prior BPF-LSM result is nonzero], [Return it unchanged; no local override.], [Record stacked-policy context where it can be observed without exposing secrets.],
    [Identity cannot be read], [Return zero and emit no reason-specific event.], [Declare a filesystem/object-class disposition and emit a stable reason code.],
    [No `POLICY` map match], [Return zero and emit no event.], [Separate intentional out-of-scope from protected-scope `MISSING_RULE`.],
    [Configuration absent], [Default configuration makes scope false and returns zero.], [Keep a last-known-good generation active; never expose a half-built policy.],
    [Ring buffer full], [Increment `DROPPED`; return the decision already chosen.], [Export and alert on producer loss, consumer parse errors, and queue/forwarder loss separately.],
    [Loader exits], [No pin is created; the owned attachment is expected to be dropped with the process.], [Monitor link health and practice emergency detach and recovery.],
  ),
  kind: "table",
  supplement: [Table],
  caption: [Failure dispositions: the current availability-first sample versus an operable narrow enforcement service.]
) <tab-failure-contract>

== Policy generations: state is a release <sec-generations>

The map in the repository is intentionally simple: `HashMap<FileIdentity, u8>` plus a one-element `Array<EnforcementConfig>`. The configuration carries one nonzero `policy_generation`, and decision events copy it for attribution, but there is no pair of independently staged generations, active-generation selector, migration marker, or policy value metadata. Sample 14 is not yet a two-generation control plane. Do not infer rollout safety from the sample name.

A production-shaped successor should compile approved inventory in user space and populate an inactive generation before any selector changes. One practical arrangement is an outer one-element selector map, a map-of-maps or equivalent indirection to immutable generation maps, and an explicit manifest. The manifest records an Application Binary Interface (ABI) schema version, map type and key/value sizes, object hash/build identifier, hook name, intended cgroup scope, filesystem classes, policy generation, creation time, and owning service. A BPF map is a shared kernel data structure whose lifetime is governed by references such as file descriptors, programs, attachments, and optional pins; it is not automatically compatible merely because a name can be reopened. #cite(<bpf-map>)

The rollout sequence is: validate policy input and capacity; build generation *N+1* off-path; test representative lookups and schema metadata; atomically select *N+1*; watch both decision telemetry and health metrics; retain *N* through a defined rollback window; then retire it deliberately. Every decision event should carry the selected generation. This prevents an update loop from exposing a partially populated active map and lets an operator identify the exact policy state that produced a later decision.

If BPF filesystem (bpffs) pins are introduced, pin only root-owned, schema- and generation-named objects. A pin retains a reference; it does not authenticate a policy, provide an upgrade protocol, or guarantee desired enforcement after reboot. Startup reconciliation should refuse a map whose schema, hook, owner, or target cgroup differs from the manifest. The current samples create no pins, which keeps a classroom rollback simple: process exit drops the temporary state. #cite(<bpf-map>)

== Telemetry as evidence and health signal <sec-telemetry>

The shared `Event` contains a validated header with schema version, record length, and kind; fixed-width identity and action fields; flags and reserved-zero fields; a decision reason; and `policy_generation`. The consumer performs byte-wise native-endian decoding and rejects unknown schema, kind, length, flags, or reserved values. This is useful in-host diagnostic context, but its `repr(C)` and native-endian layout remain a same-host ABI convenience rather than a durable serialization protocol.

A decision-complete next-generation record should use fixed-width fields and explicit reserved bytes, carry `schema_version`, `record_kind`, `record_length`, monotonic timestamp, file key, cgroup/workload selector, generation, mode, disposition, errno, reason code, and a loss/health indication. Decode a durable record byte-wise with a stated byte order if it can leave the machine. Keep paths, command-line arguments, credentials, file contents, and raw kernel pointers out of the hot-path record unless a reviewed retention and privacy model specifically allows them. Ring-buffer output is application security telemetry; it is not automatically a Linux Audit subsystem record.

The operational dashboard needs more than allowed and denied counts. Export attachment/link health, policy-generation readiness, policy-map update failures, BPF-side ring reservation failures, user-space parser failures, consumer queue drops, no-policy matches within protected scope, unsupported-identity events, and the currently selected operating tier. Absence of an event is ambiguous until each loss boundary is measured. This is the same observability discipline that makes audit safe enough to inform enforcement.

== Verifier reasoning on the enforcement path <ch18-sec-verifier-reasoning>

The code in #listing-ref(<lst-file-decision>, title: "the BPF decision listing") is small because security hot paths must make proof obligations visible. `identity_from_file` checks the file pointer before dereference, reads the inode pointer, checks it, reads the inode number and superblock pointer, checks it, and then reads the device. A map lookup is used only after `Option` construction proves it exists. The current code uses `bpf_probe_read_kernel` rather than pretending a raw kernel address is a Rust reference. The verifier tracks nullable map values and pointers, initialized stack state, helper call contracts, and tracked ring-buffer reservations; acceptance is necessary but does not prove the application’s filesystem semantics or Rust ABI assumptions. #cite(<bpf-verifier>)

#verifier-note(title: "Two independent proofs remain necessary")[The verifier can establish that reachable BPF paths use legal pointer and helper states. Rust and operations still need their own argument: the BTF-derived fields correspond to the booted kernel; `s_dev` corresponds to the user-space device identity on the approved filesystem; the record layout is understood by the receiver; and the policy’s scope matches the threat model.]

The cgroup comparison is also precise but limited. The BPF program obtains the current cgroup ID at hook time, while the runner treats the cgroup directory’s inode as its configured ID. This relationship must be tested on the actual cgroup v2 target. It attributes the current task at the hook; it does not establish a durable application, container, or tenant identity. Cgroup migration, descendants, maintenance processes, and a workload intentionally moved outside the target subtree all require explicit acceptance tests.

== Safe, reproducible audit-first procedure <ch18-sec-procedure>

Perform this procedure only in a disposable VM that you administer. It uses sample 14 because it exposes the intended audit-to-enforce narrative, but sample 13 uses the same underlying safeguards. First build as an ordinary user. Do not run Cargo or build scripts under `sudo`; the present runner’s UID-zero gate applies only to the separate, already-built loader invocation. Commands assume the repository is at `/home/ubuntu/learn-ebpf-on-linux`.

#terminal-listing(title: "Build and collect non-attaching preflight evidence", "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\n# Use only a disposable worktree on the exact target VM.\n./scripts/generate-target-bindings.sh --install-tool\ncd samples\ncargo xtask build-ebpf --target-btf\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check\nreadelf -SW target/ebpf/samples-ebpf-target-btf | grep -E '\\.BTF(\\.ext)?'\nsha256sum target/ebpf/samples-ebpf-target-btf\n\n# Record the two identities the runner will insert into its temporary maps.\nsudo install -d -m 0755 /tmp/learn-ebpf-demo\nsudo sh -c 'printf \"disposable demo only\\n\" > /tmp/learn-ebpf-demo/protected'\nsudo mkdir -p /sys/fs/cgroup/learn-ebpf-demo\n./target/debug/sample-runner identity /tmp/learn-ebpf-demo/protected\n./target/debug/sample-runner cgroup-id /sys/fs/cgroup/learn-ebpf-demo")

The `lab-check` result is an inventory, not a load test. It checks for a BTF file, the literal `bpf` member in the runtime LSM list, cgroup2 in `/proc/filesystems`, bpffs and tracefs directories, and effective root status. It does not establish that the cgroup is mounted or delegated at the requested path, that `CONFIG_BPF_LSM` is enabled, that the selected hook and helper set are accepted, or that the intended production identity has authority. A missing prerequisite is a stop condition. Do not relax kernel hardening, change global BPF sysctls, grant Cargo file capabilities, or add broad `CAP_SYS_ADMIN` simply to force this exercise to run. Linux capabilities are operation- and policy-dependent; validate the actual deployment authority. #cite(<capabilities>)

In terminal A, attach in audit mode by omitting `--enforce`. The loader is the only command run with elevated authority. In terminal B, put only the disposable test shell into the disposable cgroup and exercise the protected object, a hard link, and a rename. Keep the audit session short.

#terminal-listing(title: "Audit first, then test alternate names in the demo cgroup", "# Terminal A: use the generated and reviewed object from the preflight.\ncd /home/ubuntu/learn-ebpf-on-linux/samples\nTARGET_OBJECT=target/ebpf/samples-ebpf-target-btf\ntest -r \"$TARGET_OBJECT\"\nsudo ./target/debug/sample-runner run 14-sentinel-capstone \\\n  --object \"$TARGET_OBJECT\" --target-btf-fixture \\\n  --policy-generation 1 \\\n  --protect /tmp/learn-ebpf-demo/protected \\\n  --cgroup /sys/fs/cgroup/learn-ebpf-demo \\\n  --duration 30\n\n# Terminal B: execute only disposable access attempts in the dedicated cgroup.\nsudo sh -c '\n  echo $$ > /sys/fs/cgroup/learn-ebpf-demo/cgroup.procs\n  cat /tmp/learn-ebpf-demo/protected\n  ln /tmp/learn-ebpf-demo/protected /tmp/learn-ebpf-demo/alternate\n  cat /tmp/learn-ebpf-demo/alternate\n  mv /tmp/learn-ebpf-demo/alternate /tmp/learn-ebpf-demo/renamed\n  cat /tmp/learn-ebpf-demo/renamed\n'")

Only after audit events show expected `(device,inode)` values and `action=0`, run a separate, short enforcement window with the same disposable resources and append `--enforce`. A matching open from the demo cgroup should fail with permission denied; an open outside that cgroup and an open of a different inode are the required negative controls. Do not continue if policy hits, missing events, file classes, or cgroup membership are unexplained.

#expected-output(title: "What the unmodified runner can and cannot show")[On an environment that successfully loads the reviewed target-BTF object and attaches, the runner prints `policy ... mode=AUDIT|ENFORCE generation=<n>`, an attachment line, validated event lines carrying `reason` and `generation`, and final transport-health counters including `producer_reserve_dropped` and `consumer_parse_rejected`. In audit mode a match uses the audit reason and remains allowed; in enforcement mode only a matching in-cgroup open is intended to return `-EACCES`. Exact identifiers, counts, and attach success are target-dependent.]

The immediate rollback is to let the bounded process finish or interrupt the loader, confirm it exits, and then retry the disposable read. Because neither sample creates a pin, its stated lifecycle is that dropping the owned object detaches the temporary attachment. Still, treat the retry as evidence, not an assumption. Remove only the test resources after no loader remains attached.

#terminal-listing(title: "Cleanup and simple rollback verification", "# After the loader has exited, this access should no longer be governed by the demo attachment.\ncat /tmp/learn-ebpf-demo/protected\n\nsudo rmdir /sys/fs/cgroup/learn-ebpf-demo\nsudo rm -rf /tmp/learn-ebpf-demo")

If `rmdir` reports that the cgroup is busy, move or terminate only the test shell/processes that were placed in that subtree, then repeat the removal. Never solve a cleanup failure by deleting an arbitrary cgroup hierarchy. For a mature service, emergency detach, link-health alerting, restart behavior, reboot behavior, and any bpffs pin removal must be tested and documented separately.

== Portability and operational caveats <ch18-sec-portability>

This sample requires more than a version string. Its LSM loader requires readable target BTF; its program depends on the `bpf` LSM being active; its structural field reads depend on the target BTF/binding workflow; and its attachment requires authority that the runner narrows to UID 0. The repository readmes mention Linux 5.7+ or 5.8+ as guidance, but no kernel version alone establishes `CONFIG_BPF_LSM`, LSM order, hook availability, verifier acceptance, helper availability, lockdown state, architecture support, cgroup setup, or compatible Aya behavior. Aya provides the Rust loader surface, but the target kernel decides whether the particular program is acceptable. #cite(<aya-book>) #cite(<bpf-lsm>)

The current repository’s reviewed harness does not load or attach these samples, so this chapter cannot claim a successful runtime result for them. Preserve the booted kernel release and architecture, BTF availability, active LSM list and order, cgroup mount and target identity, exact Cargo lock/toolchain, eBPF object hash, loader authority, verifier log, sample command, load/attach result, event evidence, detach result, and rollback result for every supported environment. A target that lacks one prerequisite should report an unavailable enforcement tier and remain audit-only or inactive according to the declared product policy; it must not silently substitute a different hook or a broader privilege.

== Exercises <ch18-sec-exercises>

#exercise(title: "Prove name independence without enforcement")[In audit mode, create a hard link and then rename that hard link in the disposable directory. Record the user-space `identity` output before and after each operation and compare it with event `dev` and `ino` fields. Explain why identical results support an object identity claim but do not prove overlay filesystem semantics.]

#exercise(title: "Write a failure contract")[For one named regular file on one named local filesystem, write a five-column table: condition, protected scope, chosen allow/deny result, emitted reason code, and rollback owner. Include identity read failure, missing rule, telemetry full, cgroup migration, and loader exit. Distinguish reasons the sample emits from states that still require external health evidence.]

#exercise(title: "Design, do not implement, generation N+1")[Sketch an outer active-generation selector, two immutable inner maps, and a manifest checker. State the exact moment at which the selector may change, how events retain their generation, and how long the prior generation remains available. Do not modify the current global map in place while it is enforcing.]

== Chapter summary <ch18-sec-summary>

A defensible file-opening policy begins with a resolved kernel object and ends with a practiced rollback. The repository samples use a global BPF LSM `file_open` hook, a device-plus-inode map key, a current-task cgroup predicate, and an explicit enforcement bit. They preserve earlier BPF-LSM denials; they fail open on identity and policy-state failures; and they keep telemetry loss independent of authorization. Hard links and renames are correctly understood as alternate names for the same inode, while overlay and nonstandard filesystems remain unclassified and therefore unsafe for a broad claim.

The operational work begins where the sample ends: target-tested BTF bindings, a narrow privilege boundary, two independently staged policy generations, link and lifecycle health, durable export semantics, and a documented emergency detach. The sample now supplies versioned same-host records, reason/generation attribution, and visible producer/consumer loss; those are necessary but not sufficient for a service. Audit remains the default because it is where object inventory, false-positive rate, and failure behavior become observable.

== Next steps <ch18-sec-next-steps>

Before treating the capstone as a service, revisit #section-ref(<sec-generations>, title: "policy generations") and #section-ref(<ch18-sec-portability>, title: "portability and operational caveats"), then turn the acceptance criteria into a kernel/configuration/architecture test matrix. Continue with #chapter-ref(<ch-19>, title: "custom map iterators and real-time ring-buffer telemetry") to build the loss-aware event and state planes that an audit-to-enforcement system needs for diagnosis and recovery.
