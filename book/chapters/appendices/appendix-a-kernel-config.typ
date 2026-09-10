// This appendix is intentionally self-contained so it can be included from the
// book entry point without acquiring a second global style owner.
#import "../../components/callouts.typ": concept, kernel-detail, portability-note, security-note, expected-output
#import "../../components/code.typ": terminal-listing
#import "../../components/terms.typ": acronym, glossary-term

= Appendix A: Kernel and NixOS Configuration <appendix-a>

This appendix establishes an observable, reversible laboratory contract for the
repository. Its purpose is not to declare a machine “eBPF-ready” from a version
number or a Nix expression. Instead, it separates three facts that are often
collapsed: what the kernel was *built* with, what the currently booted kernel
*exposes*, and what a particular loader is authorized to do. A NixOS
configuration can request a kernel and an LSM order reproducibly; it cannot make
the booted kernel, mount namespace, LSM policy, or service identity satisfy that
request without a reboot and on-target evidence.

The supported repository surface is `x86_64-linux`. The flake pins `nixpkgs` and
`rust-overlay` in `flake.lock`, exposes an eBPF lab NixOS module, and supplies a
development shell containing Rust, Clang/LLVM, `bpftool`, `bpf-linker`, `pahole`,
`just`, Typst, and validation tools. Flakes provide the reproducibility mechanism;
the lockfile revision is therefore evidence worth recording with a test result,
not a substitute for it. @nixos-flakes The commands in this appendix use the
repository as checked out at `/home/ubuntu/learn-eBPF-00`; run them from that
directory unless a command shows another path.

#security-note(
  title: "Use an isolated, recovery-capable target",
  [The repository’s non-privileged checks and its VM audit do not load or attach
  an eBPF program. A later loader, tracing exercise, or BPF LSM experiment is
  privileged operational code even after verifier acceptance. Build as an
  ordinary user, then test only the reviewed loader in a disposable NixOS VM or
  similarly recoverable host. Do not weaken `kernel.unprivileged_bpf_disabled`,
  grant `CAP_SYS_ADMIN` indiscriminately, add file capabilities to Cargo or a
  shell, or treat a development workstation as the lab.])

== Exact flake entry points

Start by entering the pinned tool environment and exercising only the bounded,
non-privileged foundation checks. `just` is supplied by the development shell;
`nix flake check --no-build` evaluates flake outputs but deliberately does not
build the VM test. These commands compile neither an eBPF program for attachment
nor activate a NixOS generation.

#terminal-listing(
  title: "Pinned development environment and foundation checks",
  "cd /home/ubuntu/learn-eBPF-00\nnix develop\njust check"
)

The following table is the authoritative command map in the current `justfile`
and README. Each command is exact; its stated safety scope matters more than its
name. In particular, a successful package build, parser check, or VM audit is not
evidence that a repository object has verified, loaded, or attached.

#figure(
  table(
    columns: (2.5fr, 3.0fr, 2.7fr),
    inset: 6pt,
    align: (left, left, left),
    stroke: 0.45pt + luma(170),
    table.header(
      [*Command*], [*What it does*], [*Boundary and interpretation*],
    ),
    [`nix develop`], [Enters the pinned development shell.], [Does not change kernel state. Use it before `just` targets.],
    [`just check`], [Parses shell and documentation snippets, checks local links, and evaluates flake outputs.], [No build of the VM and no eBPF attachment.],
    [`just book`], [Runs `nix build .#book` to build the current Typst book package.], [A documentation build, not a kernel test.],
    [`just samples`], [Runs `nix build .#samples` to package the source tree.], [Does not run a loader.],
    [`just kernel-audit`], [Runs the read-only kernel audit.], [Reports observed prerequisites and unknowns; it does not repair them.],
    [`just smoke`], [Runs `./scripts/smoke-tests.sh --audit`.], [Read-only audit mode; no attachment.],
    [`just vm-test`], [Runs `nix build .#checks.x86_64-linux.vm-test`.], [Builds and runs the isolated NixOS audit test; no repository eBPF object is attached.],
  ),
  caption: [Current flake and `just` commands, with their deliberately limited test scope.],
) <tab:flake-commands>

For a direct flake interface, use `nix build .#book` and `nix build .#samples`.
The flake has only `x86_64-linux` outputs; an evaluation or assertion failure on
another architecture is a compatibility boundary, not a reason to force a host
configuration. The development shell exports `BPF_CLANG=clang`, `BPFTOOL=bpftool`,
and `RUST_BACKTRACE=1`, which makes the expected tool names explicit without
altering kernel policy.

== The opt-in NixOS lab module

The flake exports `nixosModules.default` and `nixosModules.ebpf-lab`, both
pointing to `nix/nixos-ebpf-lab.nix`. The module is intentionally inert until
`services.learn-ebpf-lab.enable = true;` is set. A NixOS host configuration that
has the repository module available can import it and enable the service option
as follows. The import path is deliberately local in this example: replace it
with the appropriate pinned flake-module reference when composing a separate
system configuration.

#terminal-listing(
  title: "Minimal opt-in module use",
  "{\n  imports = [ /home/ubuntu/learn-eBPF-00/nix/nixos-ebpf-lab.nix ];\n  services.learn-ebpf-lab.enable = true;\n}"
)

When enabled, the module defaults `boot.kernelPackages` to
`pkgs.linuxPackages_latest` and requests the following kernel configuration
symbols through a named kernel patch with `patch = null` and
`structuredExtraConfig`: `BPF`, `BPF_SYSCALL`, `BPF_JIT`, `BPF_EVENTS`,
`KPROBES`, `SECURITY`, `SECURITYFS`, `DEBUG_INFO`, `DEBUG_INFO_BTF`,
`DEBUG_INFO_BTF_MODULES`, and `BPF_LSM`. It also keeps
`kernel.unprivileged_bpf_disabled = 1`, installs `bpftools`, `pahole`, `clang`,
and `llvm`, and sets `security.lsm` from the `lsmOrder` option. The default
order is exactly:

#terminal-listing(
  title: "The module’s default LSM order",
  "landlock,lockdown,yama,integrity,apparmor,bpf"
)

The module exposes `lsmOrder` as a comma-separated string and applies
`lib.splitString "," cfg.lsmOrder` to `security.lsm`. This preserves an explicit
configuration surface for a *dedicated lab*. It is not a recommendation to copy
the default list onto a general workstation: distributions and locally required
security modules differ, and LSM stacking/order has operational consequences.
BPF LSM programs are documented as a privileged mechanism for system-wide
mandatory-access-control and audit policy. @bpf-lsm

The module includes two assertions: `x86_64-linux` and a kernel version at least
5.7. The latter is a historical necessary floor associated with BPF LSM support,
not a readiness test. It does not establish readable BTF, the effective LSM list,
a usable hook or helper set, lockdown/other policy compatibility, or the
capabilities of the intended loader. Treat an assertion as an early configuration
guard, then use runtime preflight after rebuilding and booting the selected
NixOS generation.

#kernel-detail(
  title: "A requested configuration is not boot evidence",
  [The authoritative kernel identity is the running `uname -r`, architecture,
  and exposed interfaces after the new generation has booted. Preserve the
  Nixpkgs lock revision, realized `boot.kernelPackages`, and the booted release
  with any load/attach result. A host kernel seen from a container or VM is the
  relevant kernel for the BPF syscall; a declaration in a different build context
  is not.])

== Compile-time symbols and the runtime LSM list

Kernel configuration answers whether a facility was selected when the kernel was
built. The audit script reads the first available source from `/proc/config.gz`
or `/boot/config-$(uname -r)` and reports unavailable configuration text as
`UNKNOWN`, not as an invented failure. It checks `CONFIG_BPF`,
`CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, and
`CONFIG_BPF_LSM`. A value of `y` or `m` is useful evidence, but it is not the
last word on attachability.

The active LSM stack is a distinct runtime fact. When securityfs exposes it,
`/sys/kernel/security/lsm` reports a comma-separated list. A compiled
`CONFIG_BPF_LSM=y` can coexist with a list that does not contain `bpf`; conversely,
the correct module request becomes useful only after the configured generation
boots. For BPF LSM work, require both the configuration evidence where it is
readable and an active `bpf` token in the runtime list. That distinction follows
the kernel’s program-type model rather than a generic eBPF version test. @bpf-lsm

#figure(
  table(
    columns: (2.3fr, 2.8fr, 3.1fr),
    inset: 6pt,
    align: (left, left, left),
    stroke: 0.45pt + luma(170),
    table.header(
      [*Evidence*], [*What it establishes*], [*What it does not establish*],
    ),
    [`CONFIG_BPF=y` and `CONFIG_BPF_SYSCALL=y`], [The BPF subsystem and syscall interface were requested in the kernel build.], [A particular program type, helper, policy context, or loader authority.],
    [`CONFIG_DEBUG_INFO_BTF=y`], [Build-time intent to emit kernel BTF.], [That `/sys/kernel/btf/vmlinux` is readable in the current environment.],
    [`CONFIG_BPF_LSM=y`], [BPF LSM was compiled into the selected configuration.], [That BPF LSM is selected in the boot-time LSM order or that a `file_open` program can attach.],
    [`/sys/kernel/security/lsm` contains `bpf`], [The booted kernel’s active LSM stack includes BPF LSM.], [The availability of a specific hook, helper, privilege context, or safe policy design.],
    [A minimally scoped audit-only load/attach under the service identity], [The chosen object was accepted for the stated target and authority.], [Fleet portability, complete policy coverage, or a safe enforcement rollout.],
  ),
  caption: [Build configuration, runtime state, and a bounded trial answer different questions.],
) <tab:config-runtime>

Run the repository audit before interpreting its stricter mode. The audit makes
no state change and prints architecture, release, effective UID, BTF status,
readable configuration values, and the runtime LSM list when securityfs makes it
available.

#terminal-listing(
  title: "Read-only BTF and BPF-LSM gate",
  "cd /home/ubuntu/learn-eBPF-00\njust kernel-audit\n./scripts/check-kernel.sh --require-btf --require-bpf-lsm\n./scripts/smoke-tests.sh --audit"
)

The first command is informational; the second returns nonzero if BTF is not
readable, BPF LSM cannot be established, or `bpf` is inactive. An `UNKNOWN`
configuration line means the script could not read either supported kernel
configuration source. Diagnose that access limitation separately from a `FAIL`;
do not edit sysctls or security policy merely to turn unknown into pass. The
smoke harness repeats the read-only audit. Its separately gated probe is exact
but should be used only after acknowledging its potentially privileged nature:

#terminal-listing(
  title: "Optional, capability-gated feature probe",
  "./scripts/smoke-tests.sh --probe --allow-privileged"
)

This invokes `bpftool feature probe kernel` with a 30-second timeout. The harness
still does not load or attach a repository program. A failure can mean missing
authority as well as missing kernel support, so record the identity and error
rather than silently escalating privilege.

== BTF, tracefs, bpffs, and cgroup v2

#glossary-term("btf") is compact type metadata used by the kernel and tooling;
CO-RE relocations use local and target BTF to adapt eligible type accesses.
Readable `/sys/kernel/btf/vmlinux` is the primary local test in this repository.
It is a prerequisite for the enriched, type-aware tier and for modern BPF LSM
practice, but it does not manufacture a hook, helper, attach type, or semantic
compatibility. A BTF-free object is a deliberate separate tier; a failed BTF
preflight should select that object or make the feature unavailable, not pretend
that CO-RE is enabled. @libbpf-core

`tracefs` supplies discoverable event definitions. For a tracepoint program, the
local `id` and `format` file are the target’s decoding contract; a static
tracepoint is not a blanket stable ABI. @bpf-design-q-and-a Check the actual
event before compiling offsets into a program. The loop below recognizes the two
common tracefs locations without mounting anything or writing the host.

#terminal-listing(
  title: "Locate a tracepoint format without changing mount state",
  "for tracefs in /sys/kernel/tracing /sys/kernel/debug/tracing; do\n  format=\"$tracefs/events/sched/sched_switch/format\"\n  if test -r \"$format\"; then\n    printf 'using tracefs format: %s\\n' \"$format\"\n    sed -n '1,160p' \"$format\"\n    break\n  fi\ndone"
)

If neither path yields a readable file, first determine whether tracefs is
unmounted, hidden by the current mount namespace, inaccessible to the user, or
lacks the requested event. Do not substitute an offset from a tutorial. Store a
fixture from the target that is actually tested, including its kernel release,
before decoding fields. A payload-free map counter avoids this layout dependency
for an introductory tracepoint exercise.

#glossary-term("bpffs") is different from tracefs: it is a virtual filesystem
used to pin BPF maps, programs, and links. Pinning is a lifecycle reference, not
a safety feature; it can keep an object alive after the loader exits. Early labs
should make no bpffs writes. Later operational designs must declare an owner,
path/schema, expiry/removal procedure, reconciliation rule, and rollback plan.
A read-only mount inventory is enough to establish whether the intended namespace
currently exposes the relevant filesystems.

#terminal-listing(
  title: "Read-only mount inventory",
  "findmnt -t bpf\nfindmnt -t tracefs\nfindmnt -t cgroup2\nfindmnt -T /sys/fs/bpf\nfindmnt -T /sys/kernel/tracing"
)

A failed `findmnt` query is evidence to investigate, not an instruction to mount
bpffs globally. Likewise, cgroup-BPF examples require a mounted, delegated
cgroup v2 target; the existence of `cgroup2` support in `/proc/filesystems` does
not identify the intended workload scope. The cgroup v2 hierarchy and its
membership are part of the target contract. @cgroups-v2

#portability-note(
  title: "BTF adapts layout, not environment",
  [CO-RE can relocate eligible BTF-described accesses; it cannot create readable
  BTF, activate `bpf` in the LSM list, provide tracefs events, grant capabilities,
  or preserve an interface’s meaning across targets. Record the selected object
  tier and the reason it was selected.])

== Authority is an operation-specific constraint

Being UID 0 is neither a sufficient description of BPF authority nor the only
possible one. Modern kernels split previously broad authority into capabilities,
including `CAP_BPF` and `CAP_PERFMON`, but required authority remains dependent
on the BPF operation, program/attach type, namespace, lockdown state, active LSM
policy, and tool behavior. A tracepoint/perf-facing operation may have a
different gate from map inspection or a networking attachment. The relevant
question is therefore: *under the intended service identity, on this booted
target, is this narrowly specified operation authorized?* @capabilities

The current companion runner has a conservative effective-UID-zero gate. That
is an implementation limitation of that runner, not proof that the kernel
requires root for all BPF operations. Do not run `sudo cargo run` as the standard
exercise: it moves dependency resolution and build scripts into a privileged
context while obscuring the actual loader boundary. Build a locked artifact as an
ordinary user, separate the loader, and grant only authority justified by its
specific operation after auditing the target.

The following command records capability masks for the current shell only. It
does not decode them or prove what a service will receive; collect equivalent
evidence from the real unit or execution context before a privileged trial.

#terminal-listing(
  title: "Inspect the current shell’s capability masks",
  "grep -E '^Cap(Prm|Eff|Bnd|Amb):' /proc/$$/status\nid\nuname -m\nuname -r"
)

== The supported VM path and a diagnostic sequence

The repository’s supported isolated route is the NixOS test declared in
`nix/vm-test.nix`. It imports the lab module, enables it, assigns 2048 MiB of VM
memory, and asserts three audit properties: readable
`/sys/kernel/btf/vmlinux`, an active `bpf` LSM token, and a readable BTF dump
through `bpftool`. It performs no repository eBPF attachment. Invoke it exactly
as follows:

#terminal-listing(
  title: "Build and run the isolated NixOS audit VM test",
  "cd /home/ubuntu/learn-eBPF-00\nnix build .#checks.x86_64-linux.vm-test\n# Equivalent project command, when inside nix develop:\njust vm-test"
)

The test is a configuration-audit gate, not an enforcement validation or a
sample certification. In particular, it does not demonstrate that the current
Rust/Aya workspace builds, that a given object’s CO-RE relocations succeed, or
that a BPF LSM hook accepts under a production service identity. Retain its
result alongside the flake revision, booted release, architecture, and the
raw diagnostics from any later authorized test.

#expected-output(
  title: "What a useful preflight record contains",
  [A useful record names the repository and lock revision, NixOS generation or
  VM derivation, `uname -m` and `uname -r`, BTF readability, active runtime LSM
  list, relevant mounts, object hash and toolchain, loader identity/capability
  context, and the precise load/attach/detach result. “Recent kernel” or
  “module enabled” alone is not a support matrix.])

A safe diagnostic sequence begins with `just kernel-audit`, then uses the strict
BTF/LSM audit only for work that actually requires those facilities. Next,
inspect tracefs only for the selected event and inspect mounts only for the
selected lifecycle or cgroup scope. If an optional feature remains unavailable,
keep it unavailable or choose a genuinely lower-tier, BTF-free and non-LSM
exercise. Only after these observations should an authorized, audit-only,
minimally scoped object be considered in the disposable VM. An enforcement
experiment belongs after a separate recovery and rollback design, never as the
remedy for a configuration diagnostic.

#concept(
  title: "The configuration contract",
  [For this book, kernel readiness is a conjunction: a pinned build request, a
  booted target whose observable interfaces meet the selected tier, an operation
  authorized for the actual loader identity, and a bounded test with explicit
  attach and cleanup evidence. If any term is absent, describe the feature as
  unverified rather than compensating with broader privilege or a stronger
  claim.])
