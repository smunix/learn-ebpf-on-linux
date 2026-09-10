// Appendix D is self-contained so book/main.typ remains the sole global style owner.
#import "../../components/callouts.typ": concept, kernel-detail, portability-note, security-note, expected-output
#import "../../components/code.typ": terminal-listing

= Appendix D: Compatibility Matrix and Test Evidence <appendix-d>

Compatibility in this repository is an *observed contract*, not a kernel-version slogan. A result is meaningful only for the particular eBPF object, booted kernel and configuration, architecture and byte order, attachment interface, loader identity, and lifecycle that produced it. Kernel documentation treats an attempted load as the material test for a particular program and host; the verifier then decides whether the emitted object is acceptable for that program type and context. #cite(<bpf-design-q-and-a>) #cite(<bpf-verifier>) A successful build, a Nix evaluation, a readable BTF file, or a feature probe establishes a useful but smaller fact.

This appendix supplies a matrix and evidence record for the repository as it exists. It deliberately records *environment-gated*, *unavailable*, and *unknown* states rather than converting them into a passing claim. The project CI, `just check`, `just kernel-audit`, `just smoke`, and the NixOS VM audit are non-attaching checks. The VM test reads `/sys/kernel/btf/vmlinux`, checks that the runtime LSM list contains `bpf`, and dumps BTF; it does not load or attach a repository object. Consequently, no matrix row in this appendix is a pre-existing runtime pass.

#security-note(title: [The evidence boundary is deliberate])[Build ordinary Rust and eBPF objects as an ordinary user. An authorized load or attachment is a separate, short-lived test on a disposable NixOS VM or another recovery-capable non-production target. Do not turn an unknown state into a pass by disabling `kernel.unprivileged_bpf_disabled`, lowering global perf restrictions, granting a shell broad `CAP_SYS_ADMIN`, or running Cargo through `sudo`. The current runner itself has a conservative effective-UID-zero gate; that implementation limitation is not a general statement that every BPF operation requires UID 0.]

== Read the matrix as a conjunction <sec-matrix-model>

A useful row has four kinds of evidence: *identity* identifies the source and artifact; *environment* identifies the booted target and exposed interfaces; *execution* records the actual load, attach, observation, detach, and rollback outcome; and *limits* say what the row did not test. The absence of any required item keeps the row conditional. An audit with unreadable kernel configuration must say `unknown`, not infer that an option is disabled; `scripts/check-kernel.sh` follows exactly that rule. Similarly, a static tracepoint's local `id` and `format` file are a target fixture for decoding, not a blanket stable ABI promise. #cite(<kernel-trace-events>) #cite(<bpf-design-q-and-a>)

#figure(
  kind: "table",
  supplement: [Table],
  caption: [Support tiers describe bounded behavior and evidence requirements; they do not claim that every tier has passed.],
  table(
    columns: (0.78fr, 1.48fr, 1.85fr, 1.55fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header(
      [*Tier*], [*Selected behavior*], [*Minimum evidence before it may be called supported for one row*], [*Honest state when evidence is absent*],
    ),
    [0 — audit], [Read local kernel, mount, BTF, LSM, toolchain, and source facts; do not invoke a repository load.], [Command exit status plus captured output, repository revision, architecture, and a statement that no object was attached.], [`audited-only`, `unknown`, or an explicit missing-path result.],
    [1 — baseline attachment], [A payload-free or fixed, BTF-free tracepoint/map observation, such as `01-tracepoint-hello`.], [Selected tracefs event and format; approved loader authority; object digest; successful verifier load, attach, bounded observation, and owned-object detach.], [`event-missing`, `tracefs-inaccessible`, `permission-denied`, `verifier-rejected`, or `not-tested`.],
    [2 — transport and decoded records], [A bounded ring-buffer record or a context-decoding tracepoint variant.], [Tier 1 evidence plus record-schema validation, target format fixture where fields are read, and producer/consumer loss metrics.], [`format-incompatible`, `transport-unavailable`, `parse-rejected`, or `loss-unmeasured`.],
    [3 — BTF/CO-RE enrichment], [A separate object with approved kernel-type access, such as the quarantined process inspector path.], [Readable target BTF; inspected object metadata; target-generated binding/fixture; successful relocation, load, attach, and detach.], [`no-target-btf`, `relocation-failed`, `fixture-missing`, or `quarantined`.],
    [4 — BPF LSM audit], [Audit-only `file_open` decision telemetry in a recovery-capable target.], [Tier 3-like BTF evidence plus readable configuration where available, active `bpf` LSM token, exact hook/return contract, cgroup scope, and audit-only lifecycle result.], [`bpf-lsm-inactive`, `hook-unavailable`, `policy-denied`, or `not-tested`.],
    [5 — narrow enforcement], [One explicit denial rule in a disposable cgroup and protected test path.], [Tier 4 evidence plus practiced rollback, detach verification, identity/filesystem tests, loss handling, and negative controls outside the protected scope.], [Remain Tier 4 or `unavailable`; never broaden scope automatically.],
  ),
) <tab:compatibility-tiers>

Tier 0 is the repository's current safe default. Tier 1 is not implied by a green Tier 0 row: an event can be visible while the service lacks authority, an object can compile while the verifier rejects it, and an attachment can fail after a successful load. Conversely, BTF absence does not establish that all eBPF is unavailable; it rules out only an object whose selected contract needs target BTF. A lower tier must use a genuinely lower-tier object, not the enriched object with an assumed skipped relocation. CO-RE adapts eligible BTF-described layout accesses; it does not create BTF, a hook, helper permission, authority, or unchanged semantics. #cite(<libbpf-core>) #cite(<bpf-type-format>)

#portability-note(title: [A decline is an output])[Export the selected tier and a normalized reason at startup and with health evidence. “No events” is not equivalent to “event unavailable”; “BTF unreadable” is not equivalent to “object has no relocations”; and “audit-only” is not equivalent to “enforcement-tested.” A system that cannot establish the chosen tier should remain inactive or select its documented reduced behavior.]

== Inputs that identify one test row <sec-row-inputs>

The following inputs must be captured together. They are intentionally more precise than “NixOS,” “Aya 0.14,” or “a recent kernel.” The flake exposes only `x86_64-linux`; that is the repository's declared architecture surface, not evidence for `aarch64`, big-endian BPF, or another distribution. The sample workspace declares edition 2024 and MSRV Rust 1.87, pins `aya = 0.14.0`, `aya-build = 0.2.0`, and `aya-ebpf = 0.2.1`, and retains the resolved graph in `samples/Cargo.lock`. Its BPF build toolchain file selects `nightly-2026-07-15` with `rust-src`, while `nix/devshell.nix` requests `rust-bin.stable.latest.default`. Record the *resolved* `rustc` and Cargo identities from the test shell; a toolchain mismatch is a diagnostic, not a license to silently substitute a compiler. Aya API names and loader behavior must match the locked release rather than a floating documentation page. #cite(<aya-014-crate>) #cite(<aya-014-ebpf-loader>)

#figure(
  kind: "table",
  supplement: [Table],
  caption: [Inputs required to make a compatibility claim reproducible.],
  table(
    columns: (1.18fr, 1.6fr, 2.0fr, 1.45fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header(
      [*Input family*], [*Repository source of truth*], [*Record with the result*], [*Do not infer*],
    ),
    [Source and Nix inputs], [`flake.lock`, `flake.nix`, and the exact checkout; `nixpkgs` and `rust-overlay` are flake inputs.], [Git revision; `nix flake metadata --json` output or a digest; NixOS generation/VM derivation; realized `boot.kernelPackages`.], [That another checkout, Nixpkgs revision, or VM booted the same kernel.],
    [Kernel and configuration], [The booted target, `/proc/config.gz` or `/boot/config-$(uname -r)` when readable, and runtime files.], [`uname -r`, `uname -m`, BTF readability, config text or `unknown`, active LSM list, and relevant mounts in the loader's namespace.], [That a Nix expression, version string, or compile-time symbol proves an attachment.],
    [Architecture and object], [The selected ELF artifact and compiler target.], [Architecture, endianness/target where applicable, object SHA-256, ELF section listing, and the exact program and attach type.], [That an `x86_64` or little-endian result covers a different architecture.],
    [Rust and Aya], [`samples/Cargo.toml`, `samples/Cargo.lock`, and `samples/rust-toolchain.toml`.], [`rustc -Vv`, `cargo -V`, active toolchain, locked Aya versions, build command, and compiler/linker diagnostics.], [That “Aya 0.14” alone identifies an API or emitted object.],
    [Authority and policy], [The actual loader process and its mount, user, and security context.], [EUID, capability masks, service/unit identity, policy/lockdown errors, and whether the runner's UID-zero gate applied.], [That an administrator's probe covers a production service identity.],
  ),
) <tab:row-inputs>

The NixOS lab module is useful evidence of intent: when explicitly enabled, it requests BPF, BTF, securityfs, and BPF LSM-related configuration, uses `structuredExtraConfig`, keeps unprivileged BPF disabled, and declares its LSM order through `security.lsm`. It defaults to `pkgs.linuxPackages_latest` and asserts `x86_64-linux` plus a historical Linux 5.7 floor. Those settings must be paired with the booted release and runtime LSM list after reboot. In particular, a compiled `CONFIG_BPF_LSM` does not prove that the active list contains `bpf`, and a readable `/sys/kernel/btf/vmlinux` does not prove a hook or a BPF LSM attachment. #cite(<nixos-manual-kernel>) #cite(<bpf-lsm>)

== Audit first, then select a bounded experiment <sec-audit-procedure>

From the repository root, collect safe evidence before considering a load. The first listing evaluates and audits only; it neither loads nor attaches a repository program. The strict audit is appropriate only when the selected tier actually needs BTF and BPF LSM. Its nonzero result is an environment gate, not a repair instruction.

#terminal-listing(
  title: "Read-only repository and target inventory",
  "cd /home/ubuntu/learn-eBPF-00\ngit rev-parse HEAD\nnix flake metadata --json\nnix develop\njust check\njust kernel-audit\n./scripts/check-kernel.sh\n./scripts/smoke-tests.sh --audit\n\n# Run this stricter gate only for a BTF- and BPF-LSM-dependent tier.\n./scripts/check-kernel.sh --require-btf --require-bpf-lsm"
)

`./scripts/smoke-tests.sh --probe --allow-privileged` is a separately acknowledged, read-only `bpftool feature probe kernel` invocation with a 30-second timeout. It can fail because of authority as well as absent support, and it still does not test a repository object. Preserve its exit status and diagnostics instead of rerunning it with broader privilege. The kernel's helper and program-type contracts remain specific to the selected program and attach type. #cite(<bpftool-feature>) #cite(<bpf-program-types>)

Next, build and inspect the locked artifact as an ordinary user. The commands below establish source/build facts and the runner's local environment inventory. They do not establish verifier acceptance or attachment. If the nightly BPF toolchain, `bpf-linker`, or Cargo graph is unavailable, record `build-blocked` with the actual diagnostic and stop; do not call a different host-generated object equivalent.

#terminal-listing(
  title: "Locked workspace build and non-attaching artifact record",
  "cd /home/ubuntu/learn-eBPF-00/samples\nrustc -Vv\ncargo -V\nrustup show active-toolchain || true\ncargo fmt --all -- --check\ncargo check --workspace --exclude samples-ebpf\ncargo test --workspace --exclude samples-ebpf\ncargo xtask build-ebpf\ncargo build -p sample-runner\nsha256sum target/ebpf/samples-ebpf\nreadelf -SW target/ebpf/samples-ebpf | grep -E '\\.BTF(\\.ext)?' || true\n./target/debug/sample-runner lab-check"
)

A layout-dependent tracepoint adds one more read-only fixture. Capture the entire file, not only an offset copied into a program. The event identifier and format digest distinguish the test target from a similarly named event elsewhere. If the loop finds no readable file, retain the explicit unavailable result and choose a payload-free baseline only if that object does not decode the absent context.

#terminal-listing(
  title: "Capture a target-local sched_switch fixture without attachment",
  "set -eu\nmkdir -p evidence/tracefs\nfound=0\nfor tracefs in /sys/kernel/tracing /sys/kernel/debug/tracing; do\n  event=\"$tracefs/events/sched/sched_switch\"\n  if [ -r \"$event/id\" ] && [ -r \"$event/format\" ]; then\n    cat \"$event/id\" > evidence/tracefs/sched_switch.id\n    cp \"$event/format\" evidence/tracefs/sched_switch.format\n    sha256sum evidence/tracefs/sched_switch.format > evidence/tracefs/sched_switch.format.sha256\n    printf 'tracefs=%s\\n' \"$tracefs\" > evidence/tracefs/sched_switch.source\n    found=1\n    break\n  fi\ndone\n[ \"$found\" -eq 1 ] || printf '%s\\n' 'sched/sched_switch unavailable or unreadable' >&2"
)

Only a separately approved Tier 1 test may invoke the already-built loader, for example `sudo ./target/debug/sample-runner run 01-tracepoint-hello --duration 10` from `samples/`. That command is an attachment attempt, not a safe preflight, and must run only in the dedicated lab after its owner has chosen the authority boundary. A passing record needs the command, object hash, `using tracepoint format` output, bounded counter or other relevant observation, process exit, and evidence that the owned attachment dropped without a pin. A failure needs the same metadata and its full error; it must not be rewritten as a passing feature-probe result.

== Version floors are historical clues, not release gates <sec-version-floors>

Version floors help explain why an older target is more likely to lack a facility, but vendor backports, disabled configuration, security policy, architecture, program type, and emitted bytecode keep them from being support predicates. The following values are therefore *documentation aids only*. An on-target object load is decisive for the claimed behavior.

#figure(
  kind: "table",
  supplement: [Table],
  caption: [Useful historical floors and their necessary qualification.],
  table(
    columns: (1.4fr, 1.2fr, 2.25fr),
    inset: 5pt,
    stroke: 0.35pt + luma(165),
    table.header([*Facility*], [*Recorded floor or project guidance*], [*Required qualification*]),
    [Bounded verifier loops], [Linux 5.3 mainline introduction.], [A finite loop can still exceed verifier complexity or fail for emitted control flow; test the object on the oldest claimed target.],
    [`CAP_BPF` and `CAP_PERFMON`], [Linux 5.8 introduction.], [Authority remains operation-, program-, namespace-, and policy-dependent; the runner currently asks for EUID 0.],
    [Aya ring buffer], [Aya guidance: Linux 5.8+.], [A ring-capable kernel does not prove tracepoint attachment, record schema, capacity, or loss accounting.],
    [Aya BPF LSM], [Aya guidance: Linux 5.7+.], [Require BTF, `CONFIG_BPF_LSM` evidence where readable, active `bpf` LSM, hook/helper support, authority, verifier acceptance, and recovery testing.],
    [Repository NixOS module], [Asserts Linux 5.7 or later.], [This is an early configuration guard only; it is not a BPF-LSM readiness or sample-certification result.],
  ),
) <tab:version-floors>

The BPF verifier and helper documentation should guide diagnosis, but their availability is still assessed after the selected object, type, and target meet. Likewise, an accepted object is not a guarantee of complete event delivery, Rust memory-model correctness, semantic portability, or operationally safe policy. #cite(<bpf-bounded-loops-commit>) #cite(<capabilities>) #cite(<aya-ebpf-021-ringbuf>) #cite(<aya-014-lsm>)

== Evidence template and diagnostic states <sec-evidence-template>

Create one evidence directory per matrix row and retain raw artifacts rather than a hand-written “pass.” The template below uses only read-only commands until the last, intentionally commented attachment field. It makes unknown configuration and absent interfaces durable facts. Add the raw loader and verifier diagnostic only if an approved test attempts a load.

#terminal-listing(
  title: "Create a row evidence bundle before any approved attachment",
  "cd /home/ubuntu/learn-eBPF-00\nrow=\"evidence/$(date -u +%Y%m%dT%H%M%SZ)-baseline-x86_64\"\nmkdir -p \"$row\"\ngit rev-parse HEAD > \"$row/git-revision.txt\"\nnix flake metadata --json > \"$row/flake-metadata.json\"\n{ uname -m; uname -r; } > \"$row/kernel.txt\"\n./scripts/check-kernel.sh > \"$row/kernel-audit.stdout\" 2> \"$row/kernel-audit.stderr\" || true\nfindmnt -t bpf,tracefs,cgroup2 > \"$row/mounts.txt\" 2>&1 || true\ncat /sys/kernel/security/lsm > \"$row/active-lsm.txt\" 2> \"$row/active-lsm.stderr\" || true\ncd samples\n{ rustc -Vv; cargo -V; rustup show active-toolchain || true; } > \"../$row/toolchain.txt\" 2>&1\nsha256sum Cargo.lock target/ebpf/samples-ebpf > \"../$row/artifact.sha256\"\n./target/debug/sample-runner lab-check > \"../$row/lab-check.txt\" 2>&1\n# After separate approval, save the exact loader command, exit status, raw diagnostics,\n# bounded observation, detach check, and rollback check in this same directory."
)

The `|| true` lines preserve a failed or inaccessible diagnostic without falsely changing the evidence bundle into a successful preflight. They are appropriate for collection, never for a gate decision: the accompanying matrix state must say which requirement failed or was unknown. This appendix does not prescribe a universal evidence storage system; version control, an artifact store, or a controlled test record can hold the bundle provided it preserves identities and raw results.

#expected-output(title: [Minimum row conclusion])[State the result in one sentence with all material qualifiers: “On `<architecture>` / `<uname -r>`, object SHA-256 `<digest>` was [loaded, attached, observed, detached] under `<loader identity>` for `<program and attach type>`; selected tier was `<tier>`.” If any verb is not evidenced, replace it with the observed state—`build-blocked`, `not-tested`, `permission-denied`, `verifier-rejected`, `unknown`, or the named downgrade reason. Never fill the missing verb with a version floor.]

The most actionable diagnostic sequence is narrow. For `build-blocked`, inspect the recorded Rust/toolchain and linker versions before changing source. For `no-target-btf`, select only a BTF-free artifact that was designed and inspected as such. For a missing tracepoint, preserve the local fixture result and do not substitute another hook with different semantics. For `permission-denied`, compare the intended loader identity with the probe identity rather than escalating automatically. For a verifier rejection, retain the raw log and identify the missing proof—bounds, initialized stack bytes, nullable lookup, helper contract, release, or return value—before rebuilding. For BPF LSM inactivity, keep the feature audit-only or unavailable until the booted target, not merely the Nix module, exposes the active `bpf` token. #cite(<bpf-verifier>) #cite(<bpf-lsm>)

#concept(title: [Support is a maintained test record])[A compatibility matrix remains true only while its input identities and evidence remain connected. Re-run the affected row after a kernel, Nix input, Rust toolchain, Cargo lock, Aya dependency, object, program-type, attach-type, policy, or architecture change. Preserve negative results and downgrade reasons alongside passes. That discipline makes a smaller, honest capability more useful than an unsupported promise of portability.]
