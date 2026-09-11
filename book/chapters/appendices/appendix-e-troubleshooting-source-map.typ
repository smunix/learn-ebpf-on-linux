// Appendix E is self-contained so book/main.typ remains the only global style owner.
#import "../../components/callouts.typ": concept, kernel-detail, portability-note, security-note, verifier-note, expected-output
#import "../../components/code.typ": terminal-listing
#import "../../components/terms.typ": glossary-term

= Appendix E: Troubleshooting and Source Map <appendix-e>

Troubleshooting an eBPF experiment is not a search for a command that makes an error disappear. It identifies which contract is absent: the object, booted kernel interface, hook, loader identity, verifier proof, or ownership and cleanup path. A build can succeed while attachment is unavailable; a readable BTF file can coexist with a missing tracepoint; and a read-only audit is not evidence that an eBPF object loaded. The repository's continuous-integration checks and NixOS VM test deliberately stop before repository-object attachment.

The safe response is *audit first, attach last*. Preserve the error, target facts, and object identity before changing source or configuration. Do not disable `unprivileged_bpf_disabled`, lower `perf_event_paranoid`, grant a general shell `CAP_SYS_ADMIN`, or run Cargo under `sudo`. A feature is usable only when its object, booted target, program and attachment type, and loader identity agree. #cite(<capabilities>)

#security-note(title: [Stop conditions are valid results])[A failed preflight, denied load, unavailable BTF object, missing tracepoint, or verifier rejection is a measured compatibility boundary. Record it and select a deliberately implemented lower tier only when one exists. Do not substitute another hook, guess a context offset, broaden authority, or start an LSM enforcement experiment as a repair. Kernel-facing work belongs in a disposable, recovery-capable VM or another explicitly approved non-production target.]

== Begin with a non-attaching evidence record

Run the following commands from the repository root before a loader is considered. They are either source checks or read-only observations. They do not load or attach a repository program. The strict BTF/LSM command is intentionally included only for an exercise that actually requires both facilities; a failure there does not invalidate a BTF-free tracepoint design.

#terminal-listing(
  title: [Audit-first repository and target record],
  "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\njust check\njust kernel-audit\n./scripts/smoke-tests.sh --audit\n\n# Use this stricter gate only for BTF- and BPF-LSM-dependent work.\n./scripts/check-kernel.sh --require-btf --require-bpf-lsm\n\n# Record the current shell, not an imagined service identity.\nuname -m\nuname -r\nid\ngrep -E '^Cap(Prm|Eff|Bnd|Amb):' /proc/$$/status\nfindmnt -t tracefs\nfindmnt -t bpf\nfindmnt -t cgroup2"
)

`just kernel-audit` and `./scripts/check-kernel.sh` report unreadable kernel configuration as `UNKNOWN`; they do not infer it is disabled. The optional smoke-harness feature probe remains read-only but is capability-gated and cannot prove that this object will load.

#terminal-listing(
  title: [Optional acknowledged feature probe],
  "cd /home/ubuntu/learn-ebpf-on-linux\n./scripts/smoke-tests.sh --probe --allow-privileged"
)

The table orders diagnosis because a missing object, unavailable target interface, or pre-loader UID gate can fail before the verifier evaluates bytecode.

#figure(
  table(
    columns: (1.2fr, 1.75fr, 2.15fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header([*Observed symptom*], [*Evidence to collect first*], [*Safe disposition*]),
    [Build/toolchain stops], [`rust-toolchain.toml`, `Cargo.lock`, exact Cargo/linker error, compiler target, and object path.], [Do not compile under `sudo` or substitute a floating toolchain. Restore the pinned development environment or record the build tier as unavailable.],
    [BTF path absent or unreadable], [`test -r /sys/kernel/btf/vmlinux`, target release, mount namespace, and selected object's BTF requirement.], [Decline CO-RE/BTF-tracepoint/LSM work. Use only a separately built and tested BTF-free object, or report the feature unavailable.],
    [Event absent or tracefs unreadable], [Tracefs mount, event `id`, complete `format`, category/event name, and service namespace.], [Do not attach a nearby event and do not copy offsets. Keep a payload-free design only if its own selected event exists.],
    [Permission or policy error], [Actual EUID, effective capabilities, namespace, lockdown/LSM context, command, and full loader error.], [Keep the requested authority narrow; the current runner's EUID-zero gate is a runner limitation, not a universal kernel rule.],
    [Verifier rejection], [Object SHA-256, program/attach type, target facts, full raw diagnostic, and first rejected instruction/state.], [Repair the missing proof or choose a lower tier. Never suppress the verifier or match its English wording in automation.],
    [Unexpected remaining state], [Whether the bounded loader exited, the known owner, explicit pin path if one was created, and an authorized inventory.], [Inspect only the project's own object; detach or unpin only after ownership is established. Leave unfamiliar state for its owner or incident process.],
  ),
  caption: [Symptom triage begins with evidence that distinguishes absence, denial, and proof failure.]
) <tab:troubleshooting-triage>

== BTF is absent: reduce the contract, not the safeguards

#glossary-term("btf") is compact type metadata; Compile Once—Run Everywhere (CO-RE) uses compatible local and target metadata to relocate eligible type accesses. It cannot supply a BTF file, create a hook, enable an LSM, grant authority, or make a hand-maintained kernel structure semantically correct. #cite(<libbpf-core>) A failed BTF check is therefore decisive for this repository's type-aware `06-core-process-inspector` and BPF-LSM paths, whose runner reads target BTF from sysfs. It is *not* decisive for every tracepoint observation.

Distinguish absence from lack of access without changing state:

#terminal-listing(
  title: [Read-only BTF diagnosis],
  "if test -r /sys/kernel/btf/vmlinux; then\n  stat -c '%n %s bytes' /sys/kernel/btf/vmlinux\n  bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head -n 1\nelse\n  printf '%s\\n' 'target BTF is absent or unreadable'\nfi"
)

If the file is absent or unreadable, preserve that outcome with `uname -r`, architecture, and service identity. Do not present `.btf(None)`-style loader changes, copied structure definitions, or silently disabled relocation as a fallback. Select either an independently built BTF-free program needing no target type traversal, such as the conceptual scheduler counter, or a named unavailable tier. The checked-in `01-tracepoint-hello` is a different, event-producing sample.

#portability-note(title: [A fallback must be a distinct artifact])[A BTF-free path must have its own source, emitted object, schema, feature checks, and test evidence. Reusing an enriched object after its BTF relocation fails is not a lower capability tier. The correct startup status names the selected tier and a reason such as `no-target-btf`, rather than emitting invented telemetry.]

== A tracepoint is missing or its format cannot be read

A static tracepoint is discoverable through tracefs, but its name and record layout are not a blanket stable ABI. The local `id` and `format` are the target's decoder contract. #cite(<bpf-design-q-and-a>) The runner checks both usual tracefs roots and refuses attachment when the selected format is absent or unreadable. That can mean an absent event, hidden tracefs, or denied access; record which path was visible.

#terminal-listing(
  title: [Discover and archive the selected scheduler event without attaching],
  "set -eu\nfound=0\nfor tracefs in /sys/kernel/tracing /sys/kernel/debug/tracing; do\n  event=\"$tracefs/events/sched/sched_switch\"\n  if test -r \"$event/id\" && test -r \"$event/format\"; then\n    printf 'tracefs=%s\\n' \"$tracefs\"\n    printf 'event=sched/sched_switch\\n'\n    printf 'id='; cat \"$event/id\"\n    sha256sum \"$event/format\"\n    sed -n '1,160p' \"$event/format\"\n    found=1\n    break\n  fi\ndone\n[ \"$found\" -eq 1 ] || printf '%s\\n' 'sched/sched_switch is unavailable or unreadable'"
)

Use the analogous category and event for the selected sample: `sched/sched_switch` for `01-tracepoint-hello`, `syscalls/sys_enter_openat` for samples 02 and 04, `sched/sched_process_exec` for sample 03, and `exceptions/page_fault_user` for sample 08. A readable format is not permission to hard-code its offsets. For a payload-free counter, preserve the fixture but read no context bytes. For a decoder, validate every required field's name, width, offset, alignment, and meaning against the saved target fixture. If the event is unavailable, report `event-missing` or `tracefs-inaccessible`; do not substitute a kprobe, raw tracepoint, or a semantically different event merely to keep a dashboard nonempty.

== Permission denied is an operational diagnosis

The runner currently rejects every `run` subcommand unless its effective UID is zero, while `lab-check`, `identity`, and `cgroup-id` remain read-only. This is a conservative implementation gate, not a claim that UID 0 is the kernel's sole authorization model. Depending on the operation and target, BPF and performance-monitoring capability checks, namespace rules, perf policy, lockdown, and an LSM can all matter. #cite(<capabilities>) A successful interactive administrator run also does not establish the authority of a later service unit.

Build as an ordinary user, then run only the reviewed loader in the disposable VM. Do not use `sudo cargo run`, which elevates dependency resolution and build scripts. This command exposes the runner's read-only target view and EUID limitation:

#terminal-listing(
  title: [Runner preflight without attachment],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\ncargo xtask check\ncargo xtask build-ebpf\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check"
)

If the loader fails before an Aya operation with the runner's EUID message, record `runner-euid-gate`, not a failed `CAP_BPF` or `CAP_PERFMON` trial. After an authorized kernel or policy denial, retain the error, capability context, object hash, target release, and command. Decline the feature if a narrow authorization design is unavailable.

== A verifier rejection is a missing proof, not a privilege request

The verifier evaluates emitted bytecode under the program type, helper allow-list, configuration, and target policy. Its output describes an incoming abstract state, not a durable source-language error format. #cite(<bpf-verifier>) Classify a failure as a proof failure only after eliminating missing object, BTF/relocation, hook, authority, and resource causes. Then preserve the raw log and identify the *first* rejected instruction, incoming state, and violated invariant.

#figure(
  table(
    columns: (1.18fr, 1.75fr, 2.17fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header([*Diagnostic family*], [*Likely missing fact*], [*Source-level repair direction*]),
    [`map_value_or_null`], [A map lookup was used before a path-dominating null check.], [Branch immediately; return or take a safe fallback in the null arm, and dereference only in the non-null arm.],
    [Packet or context bounds], [The verifier cannot prove room for the complete access on this path.], [Use the same checked offset, prove the full width before the access, and keep the guard adjacent to it. Revalidate after a packet-changing helper.],
    [Indirect stack read], [A helper-visible range includes unwritten bytes or padding.], [Initialize the complete key/record before passing it, and reduce stack use rather than assuming a named-field write covers padding.],
    [Unreadable register/helper mismatch], [A caller-saved register was reused, provenance was lost, or the helper is ineligible.], [Preserve/reconstruct state across calls and check the helper contract for this program type; do not cast a scalar into a pointer.],
    [Unreleased reference or complexity], [A tracked resource reaches an exit, or loop/path exploration is not tractable.], [Put acquire/use/release beside one another on all exits; add a small explicit loop bound and simplify branch structure.],
  ),
  caption: [Verifier symptoms translated into proof obligations. Message wording is diagnostic, not a parser API.]
) <tab:verifier-diagnosis>

The quarantined `05-verifier-lab/rejected` fixture dereferences packet data without proving `data + 2 <= data_end`. It is outside the normal workspace and only for an explicit disposable-VM diagnosis. The adjacent fixture has a better bounds proof, but the repository claims no passing result on an arbitrary target. Build and inspect both as an ordinary user; an explicit `bpftool` load is separately authorized.

#verifier-note(title: [Keep the negative control quarantined])[Do not attach the rejected fixture to an interface. Do not replace a load failure with an invented “expected” log line. Record the target, toolchain, object hashes, command status, and complete raw output; then repair one violated invariant at a time. The verifier field guide in Appendix C gives the detailed state-reading method.]

== Detach and recovery: verify ownership before removal

The ordinary runner bounds observation to 60 seconds, keeps its `Ebpf` owner in scope, and creates no bpffs pin. Its documentation describes normal return or drop as detaching the temporary attachment. Let a bounded observation end, confirm the loader exited, save the result, and verify the workload is no longer governed by the test. A reboot or VM snapshot restore is recovery, not lifecycle-cleanup evidence.

#security-note(title: [Never perform broad BPF cleanup])[Do not delete arbitrary entries below `/sys/fs/bpf`, kill unrelated BPF programs, remove a host cgroup hierarchy, or detach a network program whose owner is unknown. A bpffs pathname retains a reference; it does not identify a safe owner or schema. For an interrupted test, inspect only a known project-owned path in an approved administrative view, establish its program/object identity, and follow the documented rollback for that one test.]

The verifier appendix's optional corrected-fixture load is this book's explicit pin path. Only if that exact fixture loaded successfully should its narrow cleanup check be used:

#terminal-listing(
  title: [Remove only the explicitly named optional verifier-fixture pin],
  "sudo bpftool prog show pinned /sys/fs/bpf/learn-ebpf-bounded-xdp\nsudo rm -f /sys/fs/bpf/learn-ebpf-bounded-xdp\nsudo bpftool prog show pinned /sys/fs/bpf/learn-ebpf-bounded-xdp"
)

The final query should report this named pin absent. Do not run it for a rejected load, a normal runner sample that made no pin, or as generic host cleanup. For BPF-LSM exercises, stop the loader, verify the disposable read works, and remove only the test resources. A busy cgroup means a test process remains; move or stop only that process.

== Chapter and sample source map

The map routes readers to canonical source and chapter. “Conditional” means the directory and manifest exist but the repository claims no successful load/attach/detach result for every target. The selected runner branch and eBPF source remain the implementation record.

#figure(
  table(
    columns: (1.3fr, 1.65fr, 2.15fr),
    inset: 4.5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header([*Sample directory*], [*Primary chapter(s)*], [*Current role and troubleshooting boundary*]),
    [`00-lab-check`], [Chapters 2 and 16], [Read-only Tier 0 preflight; no eBPF program, load, attachment, or cleanup action.],
    [`01-tracepoint-hello`], [Chapter 3], [Conditional `sched/sched_switch` ring-buffer lifecycle; it is not the proposed payload-free scheduler counter.],
    [`02-syscall-counter`], [Chapter 7], [Conditional `syscalls/sys_enter_openat` per-CPU keyed counting; verify the local event and capacity/error contract.],
    [`03-exec-ringbuf`], [Chapter 6], [Conditional fixed-record transport at `sched/sched_process_exec`; interpret producer loss separately from observed records.],
    [`04-map-patterns`], [Chapters 4 and 13], [Conditional map inventory on `sys_enter_openat`; do not call its shared-array increment exact or assume all declared maps participate.],
    [`05-verifier-lab`], [Chapter 14 and Appendix C], [Quarantined rejected/corrected XDP proof fixtures; explicit load diagnosis only, never default attachment.],
    [`06-core-process-inspector`], [Chapters 7 and 15], [Target-BTF-gated process enrichment; checked-in structural bindings and relocation matrix require target evidence.],
    [`07-scheduler-latency`], [Chapter 8], [Quarantined by the runner pending a generated and tested tracepoint-format fixture; do not assume offsets.],
  ),
  caption: [Source map, Part I: preflight through BTF and verifier work.]
) <tab:source-map-one>

#figure(
  table(
    columns: (1.3fr, 1.65fr, 2.15fr),
    inset: 4.5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header([*Sample directory*], [*Primary chapter(s)*], [*Current role and troubleshooting boundary*]),
    [`08-page-fault-profiler`], [Chapter 9], [Conditional user-fault aggregate; the runner attaches only the user event, so event availability and metric scope matter.],
    [`09-xdp-packet-counter`], [Chapter 10], [Conditional XDP `Skb`-mode observer for an explicitly supplied disposable interface; parser failure must remain `XDP_PASS`.],
    [`10-cgroup-connect-audit`], [Chapter 11], [Conditional IPv4 connect audit attached to one cgroup; prove cgroup-v2 mount, delegation, scope, and endpoint representation.],
    [`11-container-attribution`], [Chapter 11], [Conditional exec-time cgroup attribution; a cgroup ID is a join key, not a durable container name.],
    [`12-lsm-file-audit`], [Chapter 17], [BTF/active-BPF-LSM-gated audit-only `file_open` specimen; `--enforce` is deliberately rejected.],
    [`13-lsm-file-enforce`], [Chapter 18], [Recovery-VM-only explicit opt-in denial specimen for one disposable identity and cgroup; do not treat it as a general policy service.],
    [`14-sentinel-capstone`], [Chapter 18], [Audit-default capstone direction with the same current basic decision path; no claim of a completed production control plane.],
  ),
  caption: [Source map, Part II: kernel observation through security-policy experiments.]
) <tab:source-map-two>

== Glossary guidance for incident notes

Use glossary terms narrowly in issue, lab, and support records. Precise names keep an authorization problem from being misreported as a verifier failure or a lifecycle reference as policy state.

#figure(
  table(
    columns: (1.28fr, 1.7fr, 2.05fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header([*Glossary term*], [*Use it for*], [*Do not use it to imply*]),
    [#glossary-term("btf")], [Target-readable type metadata and the precondition for selected type-aware paths.], [A universal eBPF capability or an authorization grant.],
    [#glossary-term("core")], [Loader-time adaptation of eligible BTF-described type accesses.], [An existing hook, unchanged semantics, or a BTF-free fallback.],
    [#glossary-term("bpffs")], [The filesystem through which a pin can retain a map, program, or link.], [That a familiar path is safe to delete or schema-compatible.],
    [#glossary-term("map")], [Kernel-resident state with an explicit value, concurrency, capacity, loss, and owner contract.], [A transaction across several updates or an exact global count merely because it stores a counter.],
    [#glossary-term("lsm")], [A security-hook framework and, here, a privileged BPF policy attachment tier.], [A pathname firewall, a complete audit stream, or permission to test broad denial.],
    [#glossary-term("xdp")], [An ingress packet hook with explicit action semantics.], [A harmless tracing attachment or a reason to use `XDP_ABORTED` for malformed traffic.],
  ),
  caption: [Glossary terms that make diagnostic records comparable across targets.]
) <tab:glossary-guidance>

#expected-output(title: [A finished troubleshooting record])[Record the repository revision, `Cargo.lock` and toolchain, object SHA-256, `uname -r`, architecture, mounts and BTF/tracefs facts, program and attachment type, loader identity, full error or verifier log, selected tier, and cleanup result. Say “unavailable” when that is the evidence; never borrow a passing claim from another kernel or privilege context.]

Name the symptom, gather the smallest evidence that distinguishes its cause, make no broad environmental change, choose a genuinely supported lower tier only when one exists, and close the lifecycle deliberately. That makes an eBPF failure actionable without turning a laboratory workaround into a security regression.
