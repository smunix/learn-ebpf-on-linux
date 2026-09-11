# Learning eBPF on Linux

**Author: Providence Salumu**

**Learning eBPF on Linux** is a reproducible, NixOS-first book and laboratory for learning extended Berkeley Packet Filter (eBPF) programming with Rust and [Aya](https://aya-rs.dev/). It begins with a payload-free tracepoint counter, develops verifier-level reasoning and Linux kernel internals, builds an audit-first Linux Security Module (LSM) file policy, and finishes with custom map iterators plus loss-aware real-time ring-buffer telemetry.

The Typst manuscript is a 221-page edition with 19 chapters, five appendices, original diagrams, a glossary, numeric citations, and clickable internal references. Canonical code lives in `samples/`; the book imports that source rather than maintaining independent code copies.

> **Safety boundary:** build and inspect on any suitable development host, but load or attach kernel programs only in a disposable, recovery-capable NixOS virtual machine or another explicitly authorized non-production machine. Do not run Cargo as root. Build as an ordinary user, then grant only the reviewed loader the authority required by the exact hook. The repository never asks readers to weaken `unprivileged_bpf_disabled`, lower global perf restrictions, or grant blanket `CAP_SYS_ADMIN` merely to force an example to run.

## Quick start

The supported reference platform is `x86_64-linux`. Install Nix with flakes enabled, clone the repository, and enter the pinned environment:

```console
nix develop
just check
just book
just samples
```

The resulting flake packages are:

```console
nix build .#book       # result/learn-ebpf.pdf
nix build .#samples    # runner plus compiled eBPF ELF objects
```

To build the Rust workspace directly inside `nix develop`:

```console
cd samples
cargo fmt --all -- --check
cargo check --workspace --exclude samples-ebpf
cargo test --workspace --exclude samples-ebpf
cargo xtask build-ebpf
cargo build --release -p sample-runner
```

The workspace pins `aya = 0.14.0`, `aya-ebpf = 0.2.1`, and `nightly-2026-07-15` with `rust-src`. The nightly toolchain is required to build `core` for `bpfel-unknown-none`; user-space source remains compatible with the declared Rust 1.87 minimum.

## What the commands do

| Command | Result | Changes kernel state? |
|---|---|---:|
| `just check` | Shell syntax, local links, documentation snippets, and flake evaluation | No |
| `just book` | Builds the Typst PDF through the pinned flake | No |
| `just samples` | Builds the user-space runner and eBPF ELF objects | No |
| `just target-bindings -- --install-tool` | Generates selected Rust kernel bindings from this booted kernel's BTF and records hashes | No |
| `just target-btf-object` | Builds a separately named object containing target-BTF-gated programs | No |
| `just diagrams` | Re-renders the 22 original D2 diagrams | No |
| `just kernel-audit` | Reads kernel, BTF, tracefs, cgroup, and LSM evidence | No |
| `just smoke` | Runs the read-only smoke harness | No |
| `just vm-test` | Builds the disposable NixOS BTF/BPF-LSM audit VM | Only inside the VM; no repository eBPF attachment |
| `just test-runtime` | Runs explicitly guarded attachment tests on a compatible lab | Yes, on the approved lab only |

## Book and sample map

| Part | Chapter | Canonical sample |
|---|---|---|
| I. Foundations | 1. Why eBPF Exists | `00-lab-check` |
| I. Foundations | 2. Build a Safe NixOS Lab | `00-lab-check`, `nix/nixos-ebpf-lab.nix` |
| I. Foundations | 3. The First Event | `01-tracepoint-hello` |
| II. Programming Model | 4. Instructions, Program Types, Helpers, and Maps | `02-syscall-counter` |
| II. Programming Model | 5. Rust on the Kernel Boundary | `common`, `ebpf-programs`, `runner` |
| II. Programming Model | 6. Moving Events to User Space | `03-exec-ringbuf`, `04-map-patterns` |
| III. Kernel Internals | 7. System Calls, Tasks, and the VFS | `06-core-process-inspector` |
| III. Kernel Internals | 8. Scheduling and CPU Time | `07-scheduler-latency` |
| III. Kernel Internals | 9. Memory Management | `08-page-fault-profiler` |
| III. Kernel Internals | 10. The Networking Stack | `09-xdp-packet-counter`, `10-cgroup-connect-audit` |
| IV. Containers and Control | 11. Namespaces, Cgroups, and Container Identity | `11-container-attribution` |
| IV. Containers and Control | 12. Seccomp, Capabilities, and eBPF | Earlier labs and `00-lab-check` |
| IV. Containers and Control | 13. Stateful Program Design | `04-map-patterns` |
| V. Verifier and Portability | 14. Reading the Verifier | `05-verifier-lab` |
| V. Verifier and Portability | 15. BTF and CO-RE in Practice | `06-core-process-inspector` |
| V. Verifier and Portability | 16. Kernel-Version Survival | `00-lab-check` |
| VI. Security with LSM | 17. The Linux Security Module Framework | `12-lsm-file-audit` |
| VI. Security with LSM | 18. From Audit to Enforcement | `13-lsm-file-enforce`, `14-sentinel-capstone` |
| VII. Advanced Telemetry | 19. Custom Map Iterators and Real-Time Ring-Buffer Telemetry | `15-map-iterator-telemetry` |

Samples 06, 07, and 12–14 are deliberately **quarantined** from the default object until a target provides the required tracepoint/BTF fixture and retained load–attach–detach evidence. Sample 15's tracepoint, map, ring-buffer, and custom userspace iterator are in the default object; only its optional `iter/bpf_map_elem` program is target-BTF gated. Their source and documentation teach the design and test protocol without claiming runtime portability that this repository has not demonstrated.

### Building a target-BTF-gated object

Run this only in a disposable worktree on the same VM that will perform the load test. The generation script uses the booted kernel's `/sys/kernel/btf/vmlinux`, pins the Aya repository revision used to install `aya-tool`, replaces the manual fixture atomically, and records kernel/BTF/generated-file hashes in `vmlinux.rs.manifest`.

```console
nix develop
just target-bindings -- --install-tool
just target-btf-object

llvm-objdump -h samples/target/ebpf/samples-ebpf-target-btf
llvm-objdump -t samples/target/ebpf/samples-ebpf-target-btf
sha256sum samples/target/ebpf/samples-ebpf-target-btf
```

Review the generated binding diff, retain the manifest and object hash, and inspect `.BTF`/`.BTF.ext` before any load. Supplying `--target-btf-fixture` to the runner is an explicit acknowledgment, not proof of compatibility. Sample 07 remains separately quarantined because scheduler tracepoint formats require generated field-offset fixtures, not BTF structure bindings.

## Kernel prerequisites and evidence

A version number is not a support test. Record the booted kernel, architecture, exact tracefs event format, BTF availability, active LSM list, cgroup v2 mount, effective service authority, object hash, and verifier/load/attach result.

```console
just kernel-audit
./scripts/check-kernel.sh --require-btf --require-bpf-lsm
cat /sys/kernel/security/lsm
```

For BPF LSM work, the kernel must be compiled with `CONFIG_BPF_LSM=y`, expose readable target BPF Type Format (BTF), and include `bpf` in the active runtime LSM list. These are separate conditions. The opt-in NixOS module requests the build-time facilities and configures the runtime list without loading a repository program during activation.

The current sandbox used to produce the first edition had no readable `/sys/kernel/btf/vmlinux`, no mounted tracefs or bpffs, no BPF capabilities, and no readable active LSM list. Therefore formatting, user-space checks, unit tests, eBPF object compilation, Typst compilation, and PDF verification were completed here, while privileged runtime acceptance remains explicitly environment-gated.

## Enforcement safeguards

The file-policy examples never reconstruct a full pathname in eBPF. User space resolves a disposable protected path to `(device, inode)` and inserts that identity into a map. A denial requires all of the following:

1. the user passes `--enforce`;
2. the protected path is beneath `/tmp/learn-ebpf-*`;
3. a nonzero dedicated cgroup v2 identifier is configured;
4. the current task belongs to that exact cgroup;
5. the current file identity matches the policy map;
6. an earlier BPF LSM program has not already returned a denial.

Missing policy, unsupported identity, and telemetry reservation failure do not broaden denial. Audit mode is the default. Read Chapters 17 and 18 before attempting the isolated VM exercise.

## Repository layout

```text
book/       Typst source, semantic components, 19 chapters, appendices, diagrams
samples/    Rust/Aya workspace, eBPF programs, loader, verifier fixtures, READMEs
nix/        Pinned development shell, build packages, NixOS module, VM test
scripts/    Diagram, BTF generation, link, snippet, kernel-audit, and smoke helpers
research/   Authoritative source dossiers and technical/editorial synthesis
ci/         Ready-to-install, non-privileged GitHub Actions workflow template
```

## Verification

The local publication gate is:

```console
nix flake check --no-build
cd samples
cargo fmt --all -- --check
cargo check --workspace --exclude samples-ebpf
cargo test --workspace --exclude samples-ebpf
cargo xtask build-ebpf
cd ..
typst compile --root "$PWD" book/main.typ book/main.pdf
```

Runtime tests are conditional, not silently treated as passing. The first edition's PDF passed deterministic parse, page-count, text, placeholder, and font checks, followed by representative visual inspection of title, contents, prose, tables, diagrams, code, appendices, glossary, and references.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a sample, hook, policy, or kernel claim. A kernel-facing change must name its program and attach types, return contract, privileges, target features, loss behavior, ownership, cleanup, safe default, and a non-privileged validation path. Cross-kernel claims require a recorded matrix rather than an inferred minimum-version statement.

## Licensing

| Material | License |
|---|---|
| Rust, Nix, shell, CI, and configuration code | [MIT](LICENSE-CODE-MIT) OR [Apache-2.0](LICENSE-CODE-APACHE) |
| Original book prose and original diagrams | [Creative Commons Attribution-ShareAlike 4.0](LICENSE-BOOK-CC-BY-SA-4.0) |

Third-party projects and referenced material retain their own terms. The diagrams in this repository are original and generated from the editable D2 sources under `book/assets/diagrams/src/`.
