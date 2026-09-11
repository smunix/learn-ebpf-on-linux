// Appendix B is self-contained so it can be included from book/main.typ.
#import "../../components/callouts.typ": concept, kernel-detail, portability-note, security-note, expected-output
#import "../../components/code.typ": terminal-listing
#import "../../components/crossrefs.typ": table-ref

= Appendix B: Command Reference <appendix-b>

This reference is a command map for the repository, not a shortcut around the
kernel contract. A command can parse a script, evaluate a flake, build an ELF
object, inspect a trace event, ask `bpftool` about the running kernel, load an
object, or attach it; those are different operations with different authority
and cleanup consequences. In particular, a green local check or package build
is not evidence that a repository object verified, loaded, or attached on the
booted target. Run all kernel-facing commands only in a disposable,
recovery-capable NixOS virtual machine (VM) or an explicitly approved
non-production host. Record the booted kernel, architecture, lockfiles, object
hash, loader identity, and unedited diagnostics beside any later runtime
result. Flakes make the development inputs reviewable; they do not make the
running kernel or its policy identical to the declared configuration.
#cite(<nixos-flakes>)

#security-note(title: [The default is inspection, not attachment])[The command
surface deliberately starts with read-only checks. Do not lower
`kernel.unprivileged_bpf_disabled`, lower `perf_event_paranoid`, grant a general
shell `CAP_SYS_ADMIN`, add file capabilities to Cargo, set an unlimited memory
limit, or mount a filesystem merely to turn an unavailable result into a pass.
Build as an ordinary user. If an approved experiment needs a privileged loader,
run only the reviewed loader binary after preflight, for a short bounded
interval, and retain its error if it refuses. Linux BPF authority remains
operation-, program-, namespace-, and policy-dependent; UID 0 is not a complete
authority description. #cite(<capabilities>)]

== Working boundary and command classes

Unless shown otherwise, begin in `/home/ubuntu/learn-ebpf-on-linux`. The flake exposes
only `x86_64-linux`; treat an evaluation failure on another architecture as an
explicit support boundary. `nix develop` provides the repository's Rust,
Clang/LLVM, `bpftool`, BPF linker, `just`, Typst, and validation tools. The
sample workspace adds a pinned nightly declaration for its eBPF build and pins
Aya 0.14.0, `aya-ebpf` 0.2.1, and the rest of its Cargo graph. Use those checked
inputs rather than substituting floating documentation or a different compiler
and calling the resulting object equivalent. #cite(<aya-book>)

#terminal-listing(
  title: [Enter the pinned shell and identify the target],
  "cd /home/ubuntu/learn-ebpf-on-linux\nnix develop\nuname -m\nuname -r\ngit rev-parse HEAD\nsha256sum flake.lock samples/Cargo.lock samples/rust-toolchain.toml"
)

These commands collect evidence only; retain their output with a runtime
attempt.
#table-ref(<tab:command-classes>, title: [command classes]) distinguishes the
safe foundation from controlled runtime work.

#figure(
  table(
    columns: (1.25fr, 2.15fr, 2.2fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header(
      [*Class*], [*Representative command*], [*Meaning and boundary*],
    ),
    [Foundation], [`nix develop`; `just check`], [Enters the pinned shell, parses scripts/snippets, checks local links, and evaluates flake outputs. It does not build a VM or attach eBPF.],
    [Package or document build], [`just book`; `just samples`], [Builds the Typst package or copies the sample source package. Neither command executes a loader.],
    [Read-only target audit], [`just kernel-audit`; `just smoke`], [Reads exposed kernel facts. An unavailable file or feature is an observation, not a repair request.],
    [Authorized probe], [`./scripts/smoke-tests.sh --probe --allow-privileged`], [Runs a time-bounded `bpftool feature probe kernel`; it may be denied by the target authority but still loads no repository object.],
    [Controlled loader], [`./target/debug/sample-runner run ...`], [Can load and attach the selected object. Use only after the earlier evidence is recorded, on a disposable target, under an approved identity.],
  ),
  caption: [Command classes are lifecycle boundaries, not merely convenient aliases.],
) <tab:command-classes>

The repository's `just` recipes are the stable project interface. They should
be preferred to a remembered expansion because their no-attachment scope is
part of the documented behavior.

#figure(
  table(
    columns: (1.3fr, 2.1fr, 2.2fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header(
      [*Command*], [*Exact action*], [*Use and interpretation*],
    ),
    [`just check`], [Runs shell syntax, offline local-link and snippet checks, then `nix flake check --no-build`.], [Required ordinary-user foundation gate. It validates repository text and flake evaluation, not a BPF program.],
    [`just book`], [Runs `nix build .#book`.], [Builds the current book package only.],
    [`just samples`], [Runs `nix build .#samples`.], [Packages source only; it is not a privileged runtime test.],
    [`just kernel-audit`], [Runs `./scripts/check-kernel.sh`.], [Reports architecture, BTF, readable kernel configuration, and runtime LSM information without changing state.],
    [`just smoke`], [Runs `./scripts/smoke-tests.sh --audit`.], [Repeats the audit-only prerequisite path and performs no object load or attachment.],
    [`just vm-test`], [Builds `.#checks.x86_64-linux.vm-test`.], [Runs the isolated NixOS audit VM test. It audits BTF and active `bpf` LSM state; it does not attach a repository program.],
    [`just diagrams-check`], [Renders a temporary comparison through the diagram script.], [Checks diagram freshness without writing generated files.],
  ),
  caption: [Current project tasks and their deliberately limited claims.],
) <tab:just-reference>

For direct flake use, `nix build .#book` and `nix build .#samples` are the
corresponding package commands, and `nix flake check --no-build` is the
foundation evaluation step. `nix fmt` formats Nix files through the flake
formatter. None is an instruction to switch NixOS generations, enable the lab
module, or reboot a host. The opt-in module requests an isolated-lab kernel and
LSM configuration, but the effective kernel and LSM list must be observed after
boot. A declared `CONFIG_BPF_LSM` alone does not establish an active BPF LSM or
a usable hook. #cite(<bpf-lsm>)

== Read-only kernel, tracefs, and bpftool inspection

Start target diagnosis with the repository scripts. The permissive audit prints
`UNKNOWN` when kernel configuration text or securityfs is unreadable; its strict
options turn only genuinely required prerequisites into a nonzero result. That
difference is important: an unknown configuration source should be documented
separately from a discovered disabled option. A BTF or BPF-LSM requirement is
appropriate for a selected BTF-aware or LSM object, not for a generic
foundation check.

#terminal-listing(
  title: [Audit the running target without changing it],
  "cd /home/ubuntu/learn-ebpf-on-linux\njust kernel-audit\n./scripts/check-kernel.sh --require-btf --require-bpf-lsm\n./scripts/smoke-tests.sh --audit"
)

The strict `check-kernel.sh` invocation may fail on a target that lacks readable
`/sys/kernel/btf/vmlinux`, a readable configuration source, or an active `bpf`
entry in `/sys/kernel/security/lsm`. That is a correct gate for BPF LSM work;
it is not evidence that the host should be retuned. A payload-free tracepoint
counter can be a separate BTF-free tier when its own event and authority checks
succeed. CO-RE adapts eligible BTF-described layout accesses, but it cannot
create BTF, an event, a helper, a privilege, or unchanged semantics.
#cite(<libbpf-core>)

Tracefs is the source of record for the local static event identifier and
record layout. The following command finds either conventional tracefs location
without mounting tracefs, enabling an event, or decoding the context. It prints
an explicit unavailable result rather than falling through to a tutorial offset.

#terminal-listing(
  title: [Inspect and preserve the selected tracepoint contract],
  "set -eu\nfound=0\nfor tracefs in /sys/kernel/tracing /sys/kernel/debug/tracing; do\n  event=\"$tracefs/events/sched/sched_switch\"\n  if [ -r \"$event/id\" ] && [ -r \"$event/format\" ]; then\n    printf 'tracefs=%s\\n' \"$tracefs\"\n    printf 'event=sched/sched_switch\\n'\n    printf 'id='; cat \"$event/id\"\n    sha256sum \"$event/format\"\n    sed -n '1,160p' \"$event/format\"\n    found=1\n    break\n  fi\ndone\n[ \"$found\" -eq 1 ] || printf '%s\\n' 'sched/sched_switch is unavailable or unreadable'"
)

Save the unabridged `format` text, its digest, the chosen tracefs path, event
ID, `uname -r`, and architecture with any test result. The format is a decoder
contract for that target, not a portable ABI promise. An initial counter that
only counts occurrence should still archive the format but must not turn it into
hard-coded field offsets. #cite(<bpf-design-q-and-a>)

This read-only mount inventory distinguishes tracefs, bpffs, and cgroup v2;
a listed type does not establish a delegated scope.

#terminal-listing(
  title: [Inspect relevant mounts without mounting anything],
  "findmnt -t bpf\nfindmnt -t tracefs\nfindmnt -t cgroup2\nfindmnt -T /sys/fs/bpf\nfindmnt -T /sys/kernel/tracing"
)

`bpftool` is a kernel-inspection tool, not an authorization bypass. The smoke
harness uses a 30-second bound and demands a deliberate acknowledgement before
its potentially privileged feature probe. It remains read-only with respect to
repository objects.

#terminal-listing(
  title: [Capability-gated bpftool probes],
  "cd /home/ubuntu/learn-ebpf-on-linux\nbpftool version\n./scripts/smoke-tests.sh --probe --allow-privileged\nbpftool btf dump file /sys/kernel/btf/vmlinux format raw | sed -n '1,20p'"
)

Run the final BTF-dump pipeline only when the BTF file is readable. A probe that
fails can reflect missing authority as well as an unavailable facility; record
which command, identity, and error occurred. Do not substitute `full` probing
as a routine diagnostic, and do not treat a successful administrator probe as a
service-identity result. For post-experiment inspection, `bpftool prog show`,
`bpftool map show`, and `bpftool link show` are read-only listings, but their
visibility can also be policy-dependent. A feature report does not discharge the
verifier's object-, program-type-, and helper-specific proof obligation.
#cite(<bpf-verifier>)

== Cargo xtask and the attachment-free sample path

The sample workspace's `xtask` command has three subcommands. `check` runs
`cargo fmt --all -- --check` and `cargo check --workspace --exclude
samples-ebpf`; `build-ebpf` creates `target/ebpf` and asks `aya-build` to build
the `samples-ebpf` package using `nightly-2026-07-15`; and `run` dispatches to
the shared sample runner. A host Cargo that cannot satisfy the workspace or its
pinned nightly is a toolchain mismatch, not a reason to use `sudo` or edit the
lockfile.

#terminal-listing(
  title: [Build and audit as an ordinary user],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\ncargo xtask check\ncargo xtask build-ebpf\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check"
)

The first three commands can write ordinary workspace build artifacts under
`samples/target`; they do not themselves attach a repository program. The last
command is specifically attachment-free: it reads the release, BTF-file state,
runtime LSM list, mount namespace, selected tracepoint-format accessibility,
effective UID, and effective-capability text. Its own final message says that
successful verification, attachment, observation, and detach remain separate
tests. Use it as the runner-facing preflight, not as a verdict that a future
loader will succeed.

#expected-output(title: [Avoid fabricated passing transcripts])[The project
contains no CI claim that a sample has loaded or attached. Therefore this
appendix intentionally gives no fixed `PASS`, event count, verifier acceptance,
or LSM decision transcript. The useful output is the target's actual audit
report, build error, loader error, or bounded observation record, retained with
its environment identity.]

== Controlled loader invocations and cleanup

A `cargo xtask run` command dispatches to the same runner but it can load and
attach an object. Do not make `sudo cargo run` the standard procedure: it moves
Cargo dependency resolution and build scripts into the privileged boundary. The
current runner conservatively refuses attachment unless its effective UID is
zero. That is a limitation of this runner, not proof that all Linux BPF
operations require UID 0. Build first as the ordinary user, then invoke only
the already-built binary under separately approved authority.

For the smallest current tracepoint lifecycle, first collect the `sched/sched_switch`
fixture above, build the object and runner with the preceding listing, and use a
fresh disposable VM. This is an audit-only observation command with an explicit
10-second bound; it is not a pre-approved result for every target.

#terminal-listing(
  title: [Conditional bounded tracepoint observation in a disposable VM],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\nsudo ./target/debug/sample-runner run 01-tracepoint-hello --duration 10"
)

The runner checks tracefs readability before this attachment, loads the object
from `target/ebpf/samples-ebpf` unless `--object` is supplied, attaches its
selected tracepoint, caps every requested duration at 60 seconds, reads its
per-CPU count, and keeps the owner alive throughout observation. The result is
conditional on the booted target, selected hook, object, and authority. State
only that the selected target accepted and observed the object if the recorded
run actually reaches that result. Do not turn a zero count into a failure or a
positive count into a fleet-wide claim; the counter is a non-atomic aggregate
snapshot. Per-CPU map aggregation and object lifetime remain separate map and
lifecycle contracts. #cite(<bpf-map>)

Other runner subcommands have additional gates and are not substitutes for this
baseline. XDP requires `--iface` and attaches in `XdpMode::Skb`; use only an
isolated disposable interface after a separate parser/action and detach review.
Cgroup-connect observation requires `--cgroup` and uses single attachment
mode; prove the mounted and delegated cgroup-v2 scope rather than naming a
container path. Samples 06 and 12--14 are deliberately quarantined by the
current runner until a target-generated and tested object is supplied with
`--target-btf-fixture`. An `--enforce` flag is not a general safety switch: the
runner restricts enforceable paths to `/tmp/learn-ebpf-*`, requires a nonzero
policy generation, and combines a file `(device,inode)` identity with a cgroup
ID, but these safeguards do not replace BPF-LSM preflight, recovery, or a
practiced rollback. Do not treat a generic sample README command as proof that
a quarantined BTF/LSM path is ready. BPF LSM remains an opt-in, audit-first
facility with hook-specific return and authority contracts. #cite(<bpf-lsm>)

#security-note(title: [Do not begin policy work from this command reference])[No
denial-capable invocation is a default exercise here. Before any BPF LSM
experiment, establish readable target BTF, BPF-LSM build evidence where
available, active `bpf` in the runtime LSM list, the exact hook and object,
loader authority, a disposable protected object and cgroup, audit-only
behavior, independent decision telemetry, link ownership, and recovery. A
missing record, full transport, failed map lookup, or unavailable feature must
not silently broaden scope or choose a security decision.]

For the tracepoint command above, ordinary normal completion drops the owned
`Ebpf` object and its attachment lifetime. The runner uses no bpffs pin path;
do not create one “temporarily” while diagnosing it. Immediately after the
bounded process exits, inspect the relevant state with the same authorization
context, then preserve the result.

#terminal-listing(
  title: [Post-run read-only lifecycle check],
  "bpftool link show\nbpftool prog show\nbpftool map show\nfindmnt -T /sys/fs/bpf"
)

These listings do not prove that no BPF object exists elsewhere on a shared
host; they are a check against the experiment's declared ownership. If an
unplanned attachment or pin appears, stop and identify its recorded owner
before removing anything. Do not delete arbitrary entries under `/sys/fs/bpf`,
detach an unknown program, or use reboot as evidence of correct cleanup. A pin,
an attachment, or another file descriptor can keep a BPF object alive after a
loader exits; pinning is persistence, not cleanup.

Local build artifacts have a different lifecycle and can be removed without
touching kernel state:

#terminal-listing(
  title: [Remove only local Cargo build artifacts],
  "cd /home/ubuntu/learn-ebpf-on-linux/samples\ncargo clean"
)

If an isolated XDP experiment created the documented disposable veth named
`veth-ebpf0`, remove that interface only after the loader has stopped and only
when it is known to be the interface created for that experiment:

#terminal-listing(
  title: [Optional cleanup for the documented disposable veth],
  "sudo ip link del veth-ebpf0 2>/dev/null || true"
)

Do not generalize this cleanup command to an interface chosen by another owner.
Likewise, remove a test file or cgroup only when it was created by the recorded
experiment and is empty or otherwise safely retired. A cgroup path is an
attachment scope and can be virtualized or moved; it is not a durable container
identity. #cite(<cgroups-v2>)

== Diagnostic decisions that preserve the safety boundary

The fastest safe diagnosis changes one variable at a time. #table-ref(<tab:command-diagnostics>,
title: [diagnostic decisions]) maps common observations to a bounded next step.
It deliberately contains no command that weakens a system-wide control.

#figure(
  table(
    columns: (1.45fr, 2.1fr, 2.0fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.4pt + luma(170),
    table.header(
      [*Observation*], [*Interpret it as*], [*Safe next action*],
    ),
    [`nix develop` or `just` is absent], [The pinned tool environment is not active or the host lacks the expected Nix setup.], [Record the host boundary; enter the supported development shell instead of installing an unpinned replacement.],
    [`cargo xtask` reports a Rust, edition, nightly, or `bpf-linker` failure], [A local toolchain/build dependency mismatch.], [Keep the error and compare `rust-toolchain.toml`, `Cargo.lock`, and the development-shell tools. Do not build under `sudo`.],
    [Tracefs event is missing or unreadable], [The selected hook contract is unavailable in this target namespace.], [Record the attempted path and stop or select a separately designed tier; never copy offsets or silently attach another event.],
    [BTF or active `bpf` LSM is absent], [A BTF/LSM precondition is not established.], [Keep BTF-free audit work separate; leave CO-RE enrichment or BPF LSM inactive.],
    [`bpftool` probe or loader is denied], [Authority or policy may be insufficient; a feature probe is not decisive alone.], [Record effective identity, capabilities, namespace/policy context, and exact error. Do not broaden privilege automatically.],
    [Runner rejects a sample as quarantined], [The object/fixture contract has intentionally not been proved.], [Do not add `--target-btf-fixture` casually. Generate and validate the required target-specific evidence or keep the sample unavailable.],
    [A loader/verifier error occurs], [It may be an object, relocation, resource, authority, or verifier-proof failure.], [Preserve the complete error and object identity, classify the first failure, make one reviewed change, then repeat the same bounded trial.],
  ),
  caption: [Diagnostics should refine the observed contract, not enlarge the experiment.],
) <tab:command-diagnostics>

#concept(title: [The operational rule])[A good command sequence is evidence
first, object second: enter the pinned shell; run ordinary checks; audit the
booted kernel and selected tracepoint; inspect only relevant mounts and, when
approved, run a bounded feature probe; build as an ordinary user; load one
reviewed audit-only object under the intended authority in a disposable VM; then
confirm its declared lifecycle ended. When any condition is absent, report the
named unavailable or downgrade state. That is a completed diagnostic outcome,
not an invitation to guess, escalate, or enforce.]

#bibliography("../../references.yml", style: "ieee")
