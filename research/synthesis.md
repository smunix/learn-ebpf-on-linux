# Editorial Synthesis: Rust, Aya, NixOS, and eBPF Security

**Scope and research cut.** This synthesis consolidates the six research dossiers in this directory, whose research cut is **10 September 2026**. Their Linux documentation snapshot identifies itself as 7.3.0-rc2 in places, and several citations point at then-current `master` branches. Those materials are excellent explanations of an interface or implementation direction; they are **not** a deployable kernel baseline. This book must consistently distinguish (a) a documented interface, (b) a source-snapshot observation, and (c) a fact established on the reader's booted kernel under the intended service identity.

**Editorial verdict.** The book should be organized around a small, observable, reversible eBPF program and progressively add contracts: first program type and lifecycle; then verifier proofs, maps, ABI, and loss; then kernel interfaces and cgroup scope; and only finally policy enforcement. The correct recurring message is not “eBPF is safe/portable,” but: **a particular object is accepted, attached, and operationally appropriate only for a stated program type, target kernel/configuration, privilege context, data contract, and lifecycle.**

The source dossiers are mutually reinforcing on that central point. Their few apparent conflicts are either a stale tutorial/API surface, a distinction between program types, or a source/release mismatch. These are catalogued below so the prose never turns a local success into a universal promise.

## 1. Source of record and claim-resolution hierarchy

Use the following hierarchy whenever sources disagree. A lower-ranked source may illustrate or explain an interface, but it cannot override a higher-ranked source for the corresponding claim.

| Rank | Source of record | Use it for | Do not infer from it |
|---|---|---|---|
| 0 | **The running target and a minimally scoped trial load**: `uname -r`; architecture; effective capability/LSM/container context; tracefs event `id` and `format`; `/sys/kernel/btf/vmlinux`; `/sys/kernel/security/lsm`; mounted cgroup v2/bpffs; an authorized feature probe; and the selected object's verifier/load/attach result. | Whether this release can actually use a named tracepoint, BTF object, map, helper, program/attach type, or security policy. A target-local tracefs format is the decoder contract for that target. | Fleet-wide portability, stable ABI, or equivalence to a different privilege context. `bpftool` built-in knowledge and an administrator's privileges are not the service's privileges. |
| 1 | **Released-kernel UAPI and maintained kernel documentation**, plus the matching released kernel source when documentation is insufficient: `include/uapi/linux/bpf.h`, `bpf(2)`, `bpf-helpers(7)`, verifier, BTF, ring-buffer, trace/events, LSM, cgroup-v2, and capabilities documentation. | ABI, helper contract, map/program semantics, return values, privilege history, and documented limitations. | That an optional capability is enabled in a distribution configuration or that a current-mainline behavior shipped in an older target. |
| 2 | **Target release source and selftests**, pinned to the actual kernel tree/commit when a claim is implementation-specific. | Current dispatcher/return behavior, a hook declaration, an attach fallback, and a source-level diagnostic. | A durable public ABI merely because a function, BTF ID, field, kfunc, or tracepoint appears in source. Never use unpinned `master` as a release promise. |
| 3 | **Exact released Aya API documentation and source matching the companion lockfile**. For this project, the stated dependency set is `aya = 0.14.0`, `aya-ebpf = 0.2.1`, and `aya-build = 0.2.0`; the book must name the exact tag/commit used for generated code. | Rust names, methods, return types, macro sections, ownership behavior, and loader defaults. Compile snippets against that exact dependency graph in CI. | Semantics of a kernel facility, or the API signature displayed by a floating `latest` documentation page. |
| 4 | **Pinned NixOS/Nixpkgs and systemd source/manual for the declared flake revision**, followed by the generated boot configuration and unit. | Nix option spelling, package attributes, service-unit construction, kernel-package selection, and systemd feature availability. | That all NixOS machines boot the same kernel/configuration or run a sufficiently new systemd. |
| 5 | **Official Rust documentation**, especially the Rust Reference and standard-library API documentation. | `repr(C)`, padding/alignment, pointer/slice validity, `unsafe`, and synchronization semantics. | That a verifier-approved packet or kernel address automatically supports a Rust reference/slice. |
| 6 | **Aya Book, NixOS Wiki, tutorials, blogs, conference material, and prose examples.** | Pedagogy, orientation, and non-normative workflows. | A stable tracepoint ABI, a current API signature, a minimum deployment contract, or an authorization rule when rank 0–5 evidence differs. |

> **Resolution rule:** cite the rank-1 kernel source for a kernel claim, the exact Aya release for an Aya claim, and the current target for a deployment claim. Where the book teaches a local layout, preserve the target `format`/BTF fixture and its kernel metadata beside the test result.

The original BSD Packet Filter paper is the historical primary source for BPF's packet-capture motivation, but Linux kernel documentation is the primary source for modern Linux eBPF behavior.[^bsd][^kernel-isa]

## 2. Normalized terminology and house style

The book should use the following terms consistently. This prevents several common category errors in security and portability prose.

| Preferred term | Meaning in this book | Avoid or qualify |
|---|---|---|
| **BPF** | The Linux BPF subsystem or the instruction-set family when the distinction from classic BPF is immaterial. | “BPF” as an unqualified synonym for an eBPF program, a seccomp filter, and a BPF LSM program at once. |
| **cBPF / classic BPF** | The older Berkeley/classic filter model. Seccomp filters are classic BPF over syscall metadata; they are not eBPF maps/helpers programs. | Calling seccomp “an eBPF sandbox.” Seccomp reduces syscall surface; it does not replace capabilities, namespaces, LSMs, or application design. |
| **eBPF program** | A verifier-checked BPF object loaded for one program type and attachment contract. | “Kernel Rust,” “kernel module,” “generic VM,” or “arbitrary kernel code.” |
| **program type / attach type / hook** | Respectively, the kernel execution contract; the attachment flavor; and the named execution point. Name all three where the distinction matters. | “Hook” as if it alone implies helpers, return values, privilege, or attachment mechanism. |
| **loader, load, attach, link, pin** | The loader parses/relocates an ELF object; a program is then verified/loaded; it is attached; a **BPF link** is a kernel attachment object where supported; a **pin** is a bpffs reference. | “Load” to mean all stages, or “pinning” to mean safe persistence. An object is freed only after its final FD, pin, attachment, or other reference disappears.[^bpf-syscall] |
| **Aya `Ebpf` / `EbpfLoader`** | The canonical current names for the user-space object and advanced loader in new prose. | New snippets using deprecated `Bpf`/`BpfLoader` aliases. State an alias only when explaining old material. |
| **static tracepoint event** | A named event exposed through tracefs. Its locally exposed `format` file is a target-specific decoding contract. | “Stable ABI.” It is static, discoverable, and usually less coupled than an arbitrary kprobe, but upstream gives no blanket tracepoint ABI promise.[^design-qa][^events] |
| **tracepoint context** | The target event record available to a tracepoint program. | A Rust struct or an offset copied from a tutorial. `TracePointContext::read_at` is `unsafe`; offset, width, alignment, type, and target format must be proved. |
| **BTF / CO-RE** | BTF is compact type metadata. CO-RE uses local and target BTF to relocate eligible type accesses before load. | “Compile once, runs everywhere.” CO-RE cannot create BTF, a hook, a helper, an attach type, privileges, or unchanged semantics.[^btf][^core] |
| **container attribution** | Event-time cgroup ID plus time-bounded, host-side workload lifecycle metadata; optional namespace inode evidence explains isolation context. | “A cgroup is a container” or “a cgroup pathname is a container ID.” Cgroup paths are mutable and cgroup namespaces virtualize their presentation. |
| **identity** | A stated identity domain. For a file policy, use a vetted in-session filesystem/superblock discriminator plus inode number, with filesystem-class rules; use paths as diagnostic context. | A PID, pathname, inode number alone, raw kernel pointer, or runtime label as a universally durable identity. |
| **telemetry / application audit event** | A bounded, application-owned record transported through a map/ring/perf buffer. | “Linux Audit record” unless the application is separately integrated with the Linux Audit pipeline. |
| **verified** | The kernel verifier accepted the bytecode under a specified target contract. | “Bug-free,” “correct,” “private,” “lossless,” “low overhead,” or “semantically portable.” |
| **baseline** | The smallest book-supported capability tier, with explicit preflight and a recorded test matrix. | “Minimum kernel version” as the only predicate for support. |

Use **per-CPU** (hyphenated adjectivally), **user space** (two words), **user-space loader/consumer**, **target kernel**, and **booted kernel**. Reserve “root” for UID 0 and write the actual required capability/policy context; root is not intrinsically the only way to perform modern BPF operations.

## 3. Conflicts, contradictions, and their editorial resolutions

The following table is the mandatory errata and qualification register for the manuscript. It includes conflicts among sources and material project divergences found while reviewing the companion samples.

| Issue | Evidence and resolution | Required book wording/action |
|---|---|---|
| **“Tracepoints are stable.”** | Aya tutorial language can call tracepoints stable relative to dynamic probes, while the kernel BPF Design Q&A explicitly says tracepoints are **not** part of the stable ABI.[^aya-tracepoints][^design-qa] | Kernel guidance wins. Say: “The selected static event is discoverable in tracefs and is often less coupled than a kprobe; validate event existence, fields, offsets, and semantics on each target.” |
| **Aya BTF API source/release split.** | The dossiers found the 10 September upstream Aya source cut exposing `EbpfLoader::btf(&Btf)`, while the published `aya` 0.14.0 docs show `btf(Option<&Btf>)`, including `None` as a way to disable BTF relocation.[^aya-loader] | This is a real version/source mismatch, not a notation choice. Do not publish `.btf(None)` or `.btf(&btf)` until the book locks an exact crate source and CI compiles the snippet. Prefer a distinct BTF-free object rather than presenting disabling relocation as a portable fallback. |
| **`Bpf` versus `Ebpf`.** | `Bpf` and `BpfLoader` remain historical/deprecated aliases; current dossier-checked API uses `Ebpf` and `EbpfLoader`. | Normalize new code and prose to `Ebpf`/`EbpfLoader`; add a one-sentence migration note for readers of older Aya material. |
| **“Loops are forbidden.”** | Older verifier narrative can imply loops are rejected, while bounded-loop support was introduced in mainline Linux 5.3. Bounded syntax still may fail complexity analysis. | Say: “Modern kernels can verify bounded loops when termination and analysis cost are provable; use small explicit caps and test the emitted object.” Do not promise every finite loop loads. |
| **512-byte versus 256-byte tail-call stack statements.** | Upstream documents a 512-byte BPF stack limit. Aya teaching material additionally warns of a 256-byte constraint in tail-call use. The verifier/compiler work with combined call/tail-call realities. | Design to a **512-byte total eBPF stack budget with substantial margin**, and apply the stricter tail-call rule where the exact target/toolchain requires it. Never promise 512 independently usable bytes per Rust/BPF function. |
| **“Zero allows” in BPF LSM.** | For ordinary MAC-style integer LSM hooks, zero permits and a negative errno denies; cgroup LSM has distinct boolean-grant aggregation and cgroup run-context semantics.[^lsm-bpf] | Put return contracts beside every program type. Never reuse global BPF-LSM errno code in `#[lsm_cgroup]`; introduce cgroup LSM only as a separately tested advanced topic. |
| **Tail-call limit 32 versus 33.** | `bpf(2)` nesting language and current helper wording expose a 32/33 presentation difference. | Treat neither number as a correctness invariant. Every tail-call site has a safe fall-through decision and a fallback-hit metric. |
| **“CAP_BPF is all the loader needs” or “root is required.”** | `CAP_BPF` and `CAP_PERFMON` appeared in Linux 5.8, but authority is operation-, program-, namespace-, LSM-, and policy-dependent. Tracepoint work can require perf authority; networking may add other requirements.[^capabilities][^perf-security] | State the actual operation and test under the production identity. The companion runner's `euid == 0` gate is a conservative implementation limitation, not a statement of kernel necessity. |
| **BTF as universal NixOS property.** | Current Nixpkgs configuration may request relevant BPF/BTF settings, but custom package sets, a VM/container host kernel, architecture, hardening, and build prerequisites vary. | Check readability of `/sys/kernel/btf/vmlinux`; record the Nixpkgs revision, `boot.kernelPackages` realization, and booted kernel. The first counter deliberately does not require BTF. |
| **First-lab transport.** | Part 01 recommends a map-only, payload-free `sched/sched_switch` per-CPU counter. The repository's current sample `01-tracepoint-hello` emits a ring-buffer event for each `sys_enter_execve`. | The part-01 design is the canonical first program. Move ring-buffer transport after maps, ABI, and loss accounting. |
| **NixOS kernel patch property.** | The dossier correctly uses `structuredExtraConfig`; the current `nix/nixos-ebpf-lab.nix` uses `extraStructuredConfig`. Current Nixpkgs documents the former property.[^nixos-kernel] | Correct the module before representing it as a verified lab. Also prefer the NixOS `security.lsm` option to an ad hoc additional `lsm=` parameter, and test the effective runtime list after reboot. |
| **NixOS lab assertion.** | The module asserts Linux >= 5.7 as though this alone establishes BPF LSM readiness. The dossiers require BTF, `CONFIG_BPF_LSM`, active `bpf` LSM, hook/helper support, authority, and architecture checks. | Change the assertion/message to a necessary historical floor only, or remove it. Keep runtime preflight and harmless audit-only test as the gate. |
| **Current docs/source as released support matrix.** | Dossiers cite current kernel master, Nixpkgs master, Aya main, and docs rendered 7.3.0-rc2. | Label these “research-cut observations.” A published example needs a lockfile, Nix input revision, object hash, and a tested booted-kernel matrix. |

## 4. Durable constraints versus version-sensitive claims

The book may teach the left column as a design constraint, while the middle column must be feature-probed or test-pinned. The final column records the minimum safe qualification.

| Topic | Durable teaching constraint | Version-/target-sensitive boundary | Safe formulation |
|---|---|---|---|
| Verifier | Every reachable path needs valid register state, pointer provenance/range/alignment, initialized stack bytes, legal helper arguments, and balanced tracked resources.[^verifier] | Exact accepted control flow, loops, heuristics, helper allowlists, diagnostics, and compiler output. | “The target verifier accepted this object”; retain raw logs as diagnostics, not a machine-parsed API. |
| Helpers | Helpers are allow-listed calls with fixed argument/return contracts. `R1`–`R5` are caller-saved/unreadable after a helper; `R6`–`R9` are callee-saved. | Helper/map availability is per program/attach type, configuration, kernel, policy, and sometimes GPL status. | Probe/load the selected variant; do not infer from a UAPI enum or another program type. |
| Stack | Design to a 512-byte eBPF stack budget; helper-visible stack bytes must all be initialized. | Call-frame/tail-call restrictions and generated stack use. | Keep well below the budget; inspect optimized object/verifier evidence on the oldest claimed target. |
| Maps/concurrency | Map lookup can be null; shared multi-step mutation is not transactional; per-CPU aggregation gives snapshot semantics. | Map types, flags, atomics, spin-lock eligibility, CPU topology, accounting limits, and Aya wrappers. | Define a consistency and loss/eviction contract per map value. |
| Ring buffer | Producers do not wait; an unsuccessful output/reservation is an observable loss condition; every reservation is submitted or discarded exactly once. | Linux support (Aya documents 5.8+), NMI behavior, capacity, consumer lag, and Aya API behavior. | Count producer and consumer/application loss separately; no lossless-audit promise under unbounded rate. |
| Perf event array | Per-CPU/indexed perf records can produce `Lost` records. | Aya documents 4.3+; CPU/index allocation and wrapper failure reporting vary. Current Aya eBPF high-level output discards immediate helper status. | Use deliberately as a compatibility/per-CPU alternative and sum `Lost` records; do not call it lossless. |
| Tracepoints | tracefs identifies an event and describes the active record layout. | Event existence, ID, fields, offsets, sizes, semantics, visibility, and permissions. | Capture a per-target format fixture before decoding; raw tracepoint layout is not a portable primary interface. |
| BTF/CO-RE | Eligible, emitted relocation records can adapt BTF-described type access. | BTF presence/readability, relocation support, target types/fields, endianness/architecture, and semantic stability. | Select an enriched object only after BTF/relocation success; otherwise choose a genuinely BTF-free tier or no eBPF feature. |
| XDP | XDP is an early **ingress** packet hook with enum action semantics. | NIC/driver/hardware mode, helpers/actions, offload, CPU/load behavior, and packet layout. | Start with `XdpMode::Skb` and `XDP_PASS` for malformed/unknown frames; native/hardware is explicit opt-in. |
| cgroup BPF | Cgroup BPF scope is cgroup-v2 attachment scope, not a named container. | Mount path/delegation, hierarchy, attachment mode, cgroup migration, program semantics, and runtime correlation. | Discover the target cgroup and map event-time cgroup ID to host control-plane metadata. |
| BPF LSM | BPF LSM is privileged, BTF-described LSM attachment; ordinary int-hook decisions require a target-valid return value. | `CONFIG_BPF_LSM`, BTF, active `bpf` LSM order, hook/sleepable allowlist, helper set, lockdown, architecture, and cgroup-LSM availability. | Make it a late, opt-in security profile; start audit-only and test in a recovery-capable VM. |
| Object lifetime | FDs, attachments, pins, maps, and links are references with explicit ownership. | Which attachment uses a BPF link, link-update support, Aya RAII API, pin behavior, and process supervisor behavior. | Do not pin in introductory labs. In a service, name an owner, schema, expiry/removal action, reconciliation, and rollback. |
| NixOS/systemd | A declarative configuration can request a kernel, unit, or setting reproducibly. | Nixpkgs revision, actual booted kernel, generated unit, systemd version, host policy. `PrivateBPF=`/BPF delegation settings are systemd-258-era features. | Pin inputs; inspect boot/unit result; use runtime preflight; do not claim a Nix expression grants a kernel capability. |

### Version-sensitive floor table

These are documentation/history aids, **not release gates**. Vendor backports, disabled configuration, policy, and program-specific requirements mean an on-target load remains decisive.

| Facility | Dossier-recorded floor/current observation | Editorial rule |
|---|---|---|
| `CAP_BPF` and `CAP_PERFMON` | Introduced in Linux 5.8. | Explain the historical split; diagnose actual authority rather than granting blanket `CAP_SYS_ADMIN`. |
| Bounded loops | Entered mainline in Linux 5.3. | Test verification complexity; do not release-gate solely on 5.3. |
| Aya RingBuf | Aya documents Linux 5.8+. | Optional transport tier, never a prerequisite for the first map-only lab. |
| Aya PerfEventArray | Aya documents Linux 4.3+. | Compatibility alternative only after explicitly testing CPU/perf resource handling. |
| Aya global `Lsm` | Aya documents Linux 5.7+. | Requires all LSM/BTF/configuration/hook/authority preconditions; not a generic 5.7 capability. |
| Aya `LsmCgroup` | Aya documents Linux 6.0+; Aya tests note an aarch64 pre-6.4 attach caveat. | Separate advanced feature with architecture and hierarchy tests. |
| Aya `CgroupSockAddr` | Aya source documents Linux 4.17; BPF-link behavior from 5.7 with legacy attach below. | Validate exact macro-supported attach type and attachment lifecycle. |
| Aya project research cut | Aya `0.14.0`, `aya-ebpf` `0.2.1`; repository pins Rust `1.98.1`, while Aya's stated MSRV evidence is lower. | Pin the complete Cargo graph and toolchain; do not represent “0.14” as sufficient API identity. |

## 5. Primary sources mapped to the original 18-chapter plan

The map below records the **original editorial 18-chapter plan** used to commission the first manuscript. The repository now contains the complete numbered manuscript plus Chapter 19 on map iterators and ring-buffer telemetry; that chapter has its own research note in `research/chapter-19-iterators-ringbuf.md`. This historical table maps each original chapter to its primary source of record. “Runtime evidence” means the rank-0 evidence should be captured by the companion sample or test.

| Ch. | Planned chapter and teaching boundary | Primary sources to cite | Required runtime evidence / companion outcome |
|---:|---|---|---|
| 1 | **From cBPF to Linux eBPF** — history, kernel/user boundary, what an eBPF program is not. | BSD packet-filter paper; BPF ISA; `bpf(2)`.[^bsd][^kernel-isa][^bpf2] | None; conceptual chapter. |
| 2 | **The NixOS laboratory and least authority** — disposable VM, toolchain, mounts, capabilities, reproducibility. | NixOS kernel options; Nixpkgs pinned module; capabilities; perf security. | Record flake revision, NixOS generation, `uname -r`, architecture, tools, mounts, capability/policy context. |
| 3 | **Program types, contexts, returns, and lifecycle** — type before syntax; parse/relocate/load/attach/detach. | Kernel program-type documentation/UAPI; `bpf(2)`; exact Aya API. | A type-correct load/attach/detach test and a documented return contract. |
| 4 | **The first Aya program: a payload-free counter** — `no_std`, `PerCpuArray`, RAII, no persistence. | Aya tracepoint/map APIs; verifier; trace/events. | Locally validate `sched/sched_switch`; fixed-duration per-CPU count, sum user-side, no bpffs writes. |
| 5 | **The verifier as a proof obligation** — registers, stack, nullability, helpers, bounds, references, logs. | Kernel verifier; ABI convention; Design Q&A; `bpf(2)`. | Positive and intentional negative fixtures, preserved object hash and raw log. |
| 6 | **Maps, shared ABI, and concurrency** — arrays/hashes/per-CPU choices, `repr(C)`, `Pod`, schema. | Kernel maps/UAPI; Rust layout/UB docs; Aya map API. | Host+BPF size/alignment assertions; null/error/capacity and multi-CPU tests. |
| 7 | **Event transports and loss** — ring versus perf, backpressure, consumer ownership, health metrics. | Kernel ringbuf; `bpf-helpers(7)`; `perf_event_open(2)`; exact Aya sources. | Full/delayed-consumer/malformed/CPU-slot tests; producer, perf, parser, and queue losses separated. |
| 8 | **Tracepoints and syscall observation** — event discovery, machine-width arguments, bounded user strings, entry/exit correlation. | trace/events; tracepoint API; raw syscall event definitions; `bpf-helpers(7)`. | Target `format` fixture, required-field check, unmatched-state and loss counters. |
| 9 | **Tasks, credentials, and VFS observations** — event snapshots, VFS semantics, no durable raw pointers. | Credentials documentation; VFS documentation; `task_struct` source only as target-specific evidence. | BTF/event test only where a structure access is necessary; otherwise helpers/event scalars. |
| 10 | **Scheduler and page-fault measurements** — cautious metrics, not private queues/page tables. | Scheduler docs/event definitions; page-table docs/exception trace events. | `sched_waking`/`sched_switch` target format fixtures; page-fault feature gate, aggregation/rate cap, interpretation limits. |
| 11 | **Packet parsing and XDP** — pointer proofs plus Rust alignment proof; safe pass default. | XDP UAPI/program docs; Aya XDP docs; Rust pointer/slice documentation. | Isolated veth, `Skb` mode first, malformed/VLAN/short-frame cases, explicit detach/restore. |
| 12 | **Workload network policy with cgroup hooks** — cgroup-v2 scope, connect policy, return semantics. | cgroup-v2 docs; cgroups(7); BPF UAPI/program-type docs; Aya cgroup API. | Confirm mounted/delegated target cgroup, membership and DNS/proxy exceptions, dry-run metrics, rollback. |
| 13 | **Containers and layered controls** — namespaces, cgroup attribution, capabilities, seccomp, LSM composition. | namespaces(7), cgroup_namespaces(7), user_namespaces(7), seccomp docs, capabilities, LSM usage. | Time-bounded cgroup-ID/control-plane join; optional nsfs inode evidence; never path-only identity. |
| 14 | **Control-plane state, pins, tail calls, and upgrades** — schema generations and ownership. | eBPF syscall docs; maps/helpers; exact Aya map/link APIs; systemd resource-control docs. | Map metadata/schema validation, staged activation, fallback-hit metric, rollback/restart/reboot tests. |
| 15 | **BTF, CO-RE, and portability tiers** — layout adaptation, feature probe, BTF-free fallback. | BTF docs; LLVM relocation docs; verifier; exact pinned Aya loader source/API. | BTF-present and BTF-absent matrix; object inspection, target relocation test, selected-tier/reason metric. |
| 16 | **BPF LSM fundamentals** — LSM order, hook return semantics, audit versus deny, deployment preflight. | BPF LSM docs; LSM framework/usage; matching kernel hook source; Aya LSM API. | `CONFIG_BPF_LSM`/BTF/active `bpf` LSM/hook preflight; audit-only load in a recovery-capable VM. |
| 17 | **Protected-file policy capstone** — `file_open` scope, object identity, policy generation, explicit failure modes. | LSM hook declarations/VFS source; inode/stat/path-resolution docs; ringbuf/maps/syscall docs. | Hard-link/rename/filesystem-class/missing-policy/telemetry-full/prior-BPF-denial/link-loss/rollback tests. |
| 18 | **Release engineering and operations appendix** — support matrix, NixOS service split, diagnostics, incident-safe rollback. | NixOS manual/pinned Nixpkgs; systemd.exec; kernel feature probe/docs; Cargo/Rust docs. | Published matrix contains kernel/config/arch, Nix revision, Aya/Rust lock, object hash, privilege tier, verifier logs, and successful load/attach/detach results. |

## 6. Companion sample audit: publication status and required repairs

The current repository has samples `00`–`14`; this is a code-and-documentation review, **not** proof that they load. Every runtime-facing sample must be presented as *conditional* until an isolated NixOS VM runs it under the pinned toolchain and records a load/attach/detach result.

### Cross-cutting defects

1. **The test claim is incomplete.** Repository CI and `nix/vm-test.nix` audit BTF and active LSM state, but do not load or attach a repository eBPF object. The project README states this explicitly. The required runtime test evidence for any sample is absent from the reviewed test harness.
2. **Local validation could not compile the sample workspace.** Shell syntax and local-link checks passed; the documentation snippet checker passed with one Nix parser skip. The read-only kernel audit saw `x86_64`, kernel `6.18.38+`, `CONFIG_BPF=y`, and `CONFIG_BPF_SYSCALL=y`, but no readable BTF, readable boot config for several options, or runtime LSM list. `cargo xtask check` and `cargo xtask build-ebpf` both stopped before compilation because the sandbox has Cargo **1.75.0**, whereas the workspace is edition 2024 and pins Rust 1.98.1; `rustup` and `bpf-linker` are absent. No sample was loaded or attached. This is an **environment/toolchain limitation, not evidence that the pinned build fails**, but it prevents an “already tested” claim.
3. **Do not run `sudo cargo run` as the normal exercise command.** It runs Cargo/build scripts under root and conflates building with privileged attachment. Build the reviewed, locked artifact as an ordinary user; run only the resulting loader in a disposable VM under the narrowly selected authority. The runner currently requires `euid == 0`, so it does not demonstrate a `CAP_BPF`/`CAP_PERFMON`-only deployment.
4. **The generic safety paragraph was copied into samples that cannot deny anything.** It promises an `--enforce` path and inode/cgroup gates in `00`–`11`, although those samples have no denial path. Replace it with per-sample scope, hook, payload, rate, loss, privilege, and cleanup facts.
5. **Telemetry health is not complete.** `DROPPED` increments after ring reservation failure but the runner does not expose it. `Event` lacks an explicit schema version/record length/reserved policy, and the consumer accepts only object-size dispatch. Add schema/version/kind/length validation and publish producer, consumer parse, queue, and intentional-sampling metrics.
6. **`#[repr(C)]` plus `unsafe impl Pod` is not a wire-format proof.** Current records are plausible same-host fixed records, but no cross-target ABI assertion or explicit endian/padding protocol exists. Keep them in-host only until the schema is versioned and checked on host and BPF targets; decode durable records byte-wise.
7. **Current `vmlinux.rs` is a hand-maintained, minimal structural binding.** It must be generated from and tested against the target BTF/object relocation process, not represented as a portable kernel layout. Any manual filler array in `task_struct`, `file`, or `inode` is a red flag unless object relocation output and a target matrix prove the access.

### Sample-by-sample disposition

| Sample | Editorial disposition | Unsafe, obsolete, or unverified aspect | Minimum repair/test before publication |
|---|---|---|---|
| `00-lab-check` | **Publish as read-only preflight after wording repair.** | It reports cgroup-v2 support from `/proc/filesystems`, not the intended mounted/delegated cgroup; “Linux 5.7+ recommended” is not a generic lab predicate. | Report mounts, tracefs event existence, effective capabilities/policy where possible, and “unknown” separately. Keep it attachment-free. |
| `01-tracepoint-hello` | **Replace as the canonical first kernel sample.** | It emits ring-buffer records at `sys_enter_execve`; this adds a Linux-5.8 transport dependency, loss semantics, schema work, and consumer work before the book has taught them. It is not the dossier-recommended payload-free counter. | Make Chapter 4 use `sched/sched_switch` + one-entry `PerCpuArray<u64>`, no context decode, no ring, no pins. Later reuse this as a low-rate event-transport example with version/loss metrics. |
| `02-syscall-counter` | **Conditional, after documentation fixes.** | It calls `tgid` a PID in source/output; a bounded `PerCpuHashMap` can fail at capacity, but failure is not reported. `sys_enter_openat` existence is assumed. | Rename/value-document TGID, expose insertion/capacity loss, inspect the exact local event, and use a short fixed interval. |
| `03-exec-ringbuf` | **Conditional transport chapter sample.** | Ring producer failure is incremented but not exposed; fixed raw event lacks explicit schema/version/length handling. “Linux 5.8+” alone does not establish attach support. | Add complete loss model and consumer validation; test full ring and delayed consumer under the locked target. |
| `04-map-patterns` | **Refactor into focused map exercises.** | It combines unrelated map types; `BUCKETS` is a shared `Array<u64>` but is incremented as a non-atomic value, so its purported count can lose updates. LRU/capacity failures are silently ignored. | Use a `PerCpuArray` or a justified atomic for counters; state LRU eviction/capacity semantics; test each map contract independently. |
| `05-verifier-lab` | **Publish only as a quarantined negative fixture.** | It intentionally lacks an XDP `data_end` proof and requires privileged load to show rejection. A reader must not add it to the default workspace or attach it. | Keep it outside the workspace, label it intentionally rejected, load only in an isolated VM, preserve the versioned verifier log, and compare it with the corrected fixture. |
| `06-core-process-inspector` | **Hold pending target-BTF/CO-RE proof.** | It claims BTF tracepoint/CO-RE access but uses hand-maintained `task_struct` layout material and a BTF tracepoint that is not a baseline portability interface. | Generate bindings from the tested BTF workflow; inspect emitted `.BTF.ext` relocations; test BTF-present/absent behavior and offer a no-structure-access fallback. |
| `07-scheduler-latency` | **Hold; likely incorrect without a fixture.** | It hard-codes `TracePointContext::read_at` offsets. In commonly seen `sched_switch` formats, `next_pid` is after `next_comm` at offset 56 while offset 60 is `next_prio`; the code reads 60. Either way, the repository contains no target `format` fixture that proves the claimed offset. The metric is not total application latency. | Replace hard-coded offsets with generated/tested target metadata or a stored per-target fixture; include PID reuse, missed wakeup/switch, LRU eviction, and unmatched-event metrics. Call the result wakeup-to-observed-run latency. |
| `08-page-fault-profiler` | **Hold; redesign before use.** | It attaches user and kernel fault events unconditionally although availability is architecture/configuration-sensitive. It sends an event per fault, risking large overhead and loss; its `Array<u64>` is shared, not per-CPU, despite the README claim of per-CPU aggregation. | Gate on local events; default to sampled/aggregated user faults only; use true per-CPU storage or defined atomics; never interpret a fault as disk I/O/crash. |
| `09-xdp-packet-counter` | **Hold; unsafe parser/default needs repair.** | It dereferences `*(data + 12) as *const u16`, which needs an independent Rust alignment/validity proof even after a BPF range check. It returns `XDP_ABORTED` for a short frame, which is a drop/exception path and conflicts with the dossier's safe `XDP_PASS` default for malformed/unknown input. | Decode bytes or use a demonstrably unaligned-safe access; return `XDP_PASS` on parse failure; test short, VLAN, unknown, and ordinary frames on an isolated veth in `Skb` mode before any native-mode claim. |
| `10-cgroup-connect-audit` | **Conditional advanced observer.** | It is IPv4-only, assumes cgroup-v2 mount/path and macro support, and needs target validation of socket-address field byte order/port representation. `Single` attach mode and target scope may conflict with existing policy. | Preflight cgroup-v2 mount/delegation, event scope/membership, existing attachments, and DNS/proxy exceptions; test source/destination byte order with a known endpoint. Keep audit-only. |
| `11-container-attribution` | **Conditional, with clearer terminology.** | It records cgroup ID at exec, not container identity. The generic sample prose could cause readers to treat it as a container label. | Record time and host/boot context in user space; join to control-plane lifecycle metadata; do not infer runtime identity from an in-container cgroup path. |
| `12-lsm-file-audit` | **Conditional only in a BPF-LSM-capable VM.** | It is audit-only, but depends on BTF, active `bpf` LSM, exact `file_open` BTF signature, and structural file/inode access. `(device,inode)` needs explicit filesystem-class rules; missing policy/identity failures silently allow and are not decision-complete telemetry. | Retain audit-only mode; emit reason/generation/unsupported-identity signals; test regular, hard-link, rename, overlay/FUSE/network/pseudo cases before presenting an identity model. |
| `13-lsm-file-enforce` | **Hold from general publication as an enforcement exercise.** | The explicit `--enforce`, `/tmp/learn-ebpf-*` path, nonzero cgroup ID, and exact identity gate are useful safeguards, but they do not substitute for BPF-LSM preflight, filesystem classification, link health, policy generation, rollback, and recovery tests. Global `file_open` does not cover every later access/execution path. | Restrict to an isolated recovery-capable VM. Implement observe-first rollout, complete identity/failure telemetry, two policy generations, hard-link/rename/link-loss/reboot/rollback tests, and a separate privileged loader. |
| `14-sentinel-capstone` | **Do not call “production-shaped” yet.** | It shares the same simple map/configuration as sample 13; it has no active-generation selector, versioned pinned schema, startup reconciliation, link-update protocol, rollback window, or control-plane identity history. | Implement the dossier's two-generation map protocol, manifest/schema checks, service split, explicit pin ownership if persistence is needed, and capstone acceptance tests before using the production framing. |

## 7. Unsafe or obsolete patterns that must not be normalized

The following items should be explicit anti-pattern callouts, not merely footnotes.

| Category | Do not publish as the default | Safer replacement |
|---|---|---|
| Tracepoint decoding | A tutorial's hard-coded `read_at` offset/width, raw tracepoint argument layout, or a claim that tracepoints are stable ABI. | Verify category/event/id/format on the target; store a fixture; use a payload-free initial program; feature-gate a layout-dependent variant. |
| Verifier/Rust | Blind raw-pointer dereference, fabricated `&T`/slice from packet or kernel memory, unchecked map lookup, uninitialized event/key padding, post-helper use of `R1`–`R5`, or reservation without one submit/discard. | Make the proof local and documented; use `*const u8` plus byte decode for potentially unaligned packets; null-check; fully initialize; reload/revalidate state after helpers. |
| XDP | `XDP_ABORTED`/drop on a malformed or unsupported frame; “XDP is egress,” “zero-copy,” or “fastest” language. | `XDP_PASS` for new/unknown input; `Skb` on an isolated interface first; explicit parsing scope, actions, mode, counters, and detach procedure. |
| Transport | Per-event high-rate output without rate/loss budget; blocking/retrying in eBPF; calling ring or perf loss a complete audit record. | Filter/aggregate/cap first; count producer, perf, parser, and queue losses separately; prompt bounded consumer drain. |
| ABI | `repr(C)` or `Pod` treated as serialization; pointer/reference/`usize`/`bool`/Rust enum/`Option` raw records; implicit padding/endian policy. | Fixed-width, versioned records with explicit reserved fields and in-host layout tests; byte encoding for durable/cross-machine formats. |
| Privilege | Disabling `unprivileged_bpf_disabled`, lowering `perf_event_paranoid`, setting unlimited memlock, granting `CAP_SYS_ADMIN`, or adding file capabilities to Cargo/a shell just to make a lab run. | Diagnose the observed failure; use the least justified capability/policy for the exact operation in an isolated VM; make an unavailable feature unavailable. |
| Lifecycle | Pinning “temporarily,” generic shared bpffs paths, assuming a process exit frees all objects, or treating pin reuse as schema compatibility. | No pins in early labs. Later use root-owned schema/generation paths, manifest/metadata checks, explicit owner/removal/rollback, and startup reconciliation. |
| Security policy | Beginning with broad BPF-LSM deny rules; policy keyed solely by pathname/inode/raw pointer; treating ring loss as a reason to allow/deny; returning global-LSM values from cgroup LSM. | Observe-first, narrow object scope, composite in-session identity, independent decision from telemetry, explicit failure modes, and program-specific return tests. |
| APIs and build | Deprecated Aya `Bpf`/`BpfLoader`, `set_global`, `set_max_entries`; floating `latest` docs; deprecated legacy TC section conventions presented as current default. | Exact release/tag/lockfile and CI compilation; `Ebpf`, `EbpfLoader`, `override_global`, `map_max_entries`; version-gated TCX/legacy

## 8. Recommended baseline: supported only as a tested capability tier

### Editorial recommendation

The book's **baseline kernel-facing exercise** should be a deliberately boring, BTF-free, payload-free scheduler event counter:

- **Target:** a disposable, NixOS `x86_64-linux` VM or an approved non-production host, booted from a recorded flake/Nixpkgs revision. It is a tested environment, **not** a claim about all NixOS hosts or Linux distributions.
- **Hook:** the locally discovered static `sched/sched_switch` tracepoint. Before running, read both `id` and `format`; the baseline does not decode the context, so the format is learned and archived but not turned into a hard-coded offset.
- **eBPF program:** `#![no_std]`, `#![no_main]`, `#[tracepoint]`, a one-entry `PerCpuArray<u64>`, `get_ptr_mut(0)` with one narrow documented unsafe dereference, wrapping increment, and tracepoint return `0`.
- **User-space owner:** exact pinned Aya release; `Ebpf::load`/`Ebpf::load_file`, `program_mut`, `TryInto::<TracePoint>`, `load`, `attach("sched", "sched_switch")`; a fixed short observation interval; `PerCpuArray::get(&0, 0)` and user-space sum; then ordinary owned-object drop. Keep the `Ebpf` owner alive until after map reading.
- **Non-goals:** no event payload, task/kernel/user memory, BTF or CO-RE requirement, ring/perf stream, pin, service, automatic start, policy update, sysctl change, memory-limit change, user capture, file capture, or enforcement.
- **Result statement:** “The program counted invocations of the selected event while its attachment was alive and reported a non-atomic aggregate snapshot.” It does **not** count all scheduler activity exactly or establish a performance property.

This baseline is intentionally narrower than the repository's current `01-tracepoint-hello`. A one-entry per-CPU counter gives the reader an auditable lifecycle, a map, the loader path, safe cleanup, and one scoped unsafe map-value write without first requiring BTF, a fixed record ABI, a high-rate output plan, or loss accounting. It is a **teaching baseline**; it still needs tracefs availability, the selected event, permitted BPF/perf operations, and a successful target load/attach.

### What “tested baseline” must mean

No current source dossier or project harness proves universal support. A baseline can be called **tested** only after the following evidence exists for every entry in the published support matrix:

| Evidence item | Required artifact |
|---|---|
| Reproducible build identity | Git revision; `Cargo.lock`; Rust toolchain; Aya/aya-ebpf versions; Nixpkgs/flake lock revision; BPF object SHA-256; build command and target triple. |
| Booted target identity | `uname -r`; architecture; NixOS generation and realized `boot.kernelPackages` version where applicable; relevant kernel configuration values or an explicit “unavailable.” |
| Hook contract | Captured `events/sched/sched_switch/id` and `format`, tracefs mount/access result, and a statement that the baseline ignores payload fields. |
| Authority/policy context | Actual service UID/effective capabilities; applicable perf/BPF/LSM/container policy; preflight result. Do not substitute interactive root for the intended service. |
| Load and attach result | Full Aya/kernel error if unsuccessful; otherwise load/attach confirmation, short bounded observation output, and explicit detach/drop confirmation. Preserve full verifier logs in CI/staging. |
| Negative and cleanup evidence | Missing-event behavior, denied-authority behavior, map-null branch reasoning/negative fixture where practicable, object cleanup/no pin proof, and no privileged system tuning made for the test. |
| Matrix boundary | At least one stated baseline VM image and every additional kernel/configuration/architecture claimed in the book. Failure on an unlisted target becomes a documented downgrade, not a compatibility bug hidden by prose. |

The currently reviewed repository has **partial, non-runtime evidence only**: it pins a sample Cargo graph and defines a NixOS VM audit, while its own README states that CI does not load or attach programs. In this synthesis sandbox, the safe checks completed as follows:

| Check | Result | Interpretation |
|---|---|---|
| `bash -n scripts/*.sh` | Passed. | Shell syntax only. |
| Local Markdown-link verification | Passed; external URLs intentionally unchecked in offline mode. | Documentation-local link evidence only. |
| Snippet verification | Four snippets parsed; a Nix snippet was skipped because the local daemon was unavailable. | Not a NixOS configuration build/deployment proof. |
| `scripts/check-kernel.sh` | Ran read-only on `x86_64`, `6.18.38+`; BTF, runtime LSM list, and several kernel config values were unavailable/unreadable. | Demonstrates why runtime probing is required; it cannot validate the BTF/LSM samples. |
| `cargo xtask check` / `cargo xtask build-ebpf` | Did not start compilation: local Cargo is 1.75.0, while the workspace uses edition 2024/Rust 1.98.1; no `rustup` or `bpf-linker` was present. | The companion samples remain **unverified in this environment**; this does not establish that their pinned toolchain build fails. |

### Required baseline preflight

The baseline runner must make the following bounded checks before attachment and emit a machine-readable status. A failure is a result, not an invitation to weaken security policy.

```text
1. Record build identity, uname -r, architecture, and effective service authority.
2. Confirm a readable tracefs event directory and sched/sched_switch id and format.
3. Optionally record BTF and bpffs; neither is a first-counter requirement.
4. Use an authorized feature probe where available, but do not treat its absence as permission to guess.
5. Load only the fixed, payload-free object with verifier diagnostics enabled in CI/staging.
6. Attach only after a successful load; observe for a fixed short duration.
7. Read/sum the per-CPU value; close/drop the owned object; report no pinned state.
8. On any failure, emit one of: event-missing, tracefs-inaccessible,
   permission-denied, BPF-feature-unavailable, verifier-rejected,
   resource-limit, loader-error, or cleanup-failed. Do not auto-escalate.
```

Do **not** require bpffs, BTF, `CAP_SYS_ADMIN`, a changed `perf_event_paranoid`, a changed `unprivileged_bpf_disabled`, or unlimited memlock for this counter. On a current target, plan narrowly around the relevant BPF/perf authority, but do not claim that `CAP_BPF + CAP_PERFMON` alone is sufficient in all namespaces, LSM configurations, container policies, or older kernels.[^capabilities][^perf-security]

### Progressive capability tiers

The remainder of the book should explicitly downgrade rather than silently substitute hooks or broaden authority.

| Tier | Preconditions | Allowed instructional scope | Decline/fallback behavior |
|---|---|---|---|
| **0 — Read-only environment audit** | Ordinary user; no attachment authority. | Kernel/config/BTF/LSM/tracefs/cgroup diagnostics. | Report what is unknown or unavailable. |
| **1 — Baseline map-only tracepoint** | Target event/tracefs plus a successful authorized load/attach. | Payload-free per-CPU counter, bounded run, no BTF/pin/stream. | Mark eBPF observation unavailable. Never guess a replacement tracepoint. |
| **2 — Fixed event telemetry** | Tier 1 plus target event-field fixture and ring-buffer support if selected. | Versioned fixed records; bounded, loss-accounted output. | Use an explicitly tested perf alternative or aggregate-only mode; do not silently discard losses. |
| **3 — BTF/CO-RE enrichment** | Usable target BTF, emitted relocations, and successful target load. | Minimal, guarded kernel-type access with a BTF-free baseline alternative. | Fall back to tier 1/2 or omit the enrichment. |
| **4 — Network/cgroup policy observation** | Exact program/attach contract, cgroup-v2 scope or isolated interface, target helper/mode and rollback checks. | Dry-run cgroup connect audit or isolated XDP `PASS` parser. | Disable policy feature; do not attach at an inferred scope. |
| **5 — BPF LSM audit/enforcement** | BTF; `CONFIG_BPF_LSM`; active `bpf` LSM; exact hook/helper/return support; recovery-capable VM; security owner and rollback. | Audit-first, then one narrow verified enforcement rule. | Remain audit-only or inactive according to the declared product threat model. |

## 9. Manuscript-wide review gate

Before a code listing moves from “illustrative” to “runnable,” the technical editor should require the following completed review record.

| Review area | Non-negotiable questions |
|---|---|
| Scope and safety | What kernel object or decision does the sample observe/enforce? What is excluded? Is it authorized, time-bounded, reversible, and safe on a disposable target? |
| Kernel contract | What are exact program type, attach type, hook, context source, legal return values, helper allowlist, and target-local layout facts? |
| Verifier proof | Is every map/reference result checked; every stack byte initialized; every pointer range/alignment relation obvious; every helper boundary respected; every reserve released; every loop capped; every exit value defined? |
| Rust proof | Does unsafe code state provenance, lifetime, alignment, initialization, aliasing, and representation invariants independently of verifier acceptance? |
| Data/transport | Does the record have version/kind/length/endian/padding rules? Is its loss, parse failure, queue drop, CPU coverage, sampling, and ordering model explicit? |
| Operations | Does preflight run as the production identity? Are link ownership, detach, pin policy, resource limits, privilege boundaries, and cleanup observable? |
| Portability | Is every kernel/Aya/NixOS claim tagged with its source/release and validated in the declared matrix? Are BTF absence, missing event, unsupported helper, error, and downgrade paths tested? |
| Policy | For enforcement, what object identity and filesystem/container scope are trusted? Are fail-open/closed states explicit? Are LSM stacking, telemetry loss, generation transition, detach, restart, and rollback all tested? |

## 10. Editorial directives in one page

1. **Teach contracts before cleverness.** Program type, hook context, return value, helper, map, record ABI, and lifecycle are one unit.
2. **Prefer explicit kernel interfaces.** A locally checked static tracepoint is usually a safer observation starting point than kprobes, fentry, raw tracepoints, or structure walking. “Usually” is not “stable ABI.”
3. **Begin with maps, then streams, then policy.** A payload-free per-CPU counter precedes fixed event records; records precede CO-RE structure reads; audit precedes enforcement.
4. **Use exact versions.** Every Aya listing names its locked crate/tag; every NixOS listing names its flake revision; every result identifies booted kernel and object hash.
5. **Keep unsafe small and two-sided.** A verifier proof is necessary but does not prove Rust alignment, validity, lifetime, aliasing, metrics, privacy, or operational safety.
6. **Measure degradation.** Count loss, eviction, failed reads, fallback, missing correlation, malformed events, attachment failure, and policy generation; never make absence of an event indistinguishable from success.
7. **Separate a narrow privileged loader from an unprivileged consumer.** Build as an ordinary user, pass a narrow reviewed interface, and harden the consumer. Do not grant Cargo or a general-purpose shell privileges.
8. **Treat policy state as a release.** Version schemas, build inactive policy generations, validate, activate one boundary at a time, preserve rollback, and explicitly retire old state.
9. **Never conceal unsupported targets.** Export the selected tier and downgrade reason. A truthful “unavailable” is safer than an invented observation or an attachment at the wrong scope.

---

## Primary references

The six dossiers contain fuller source inventories. These links are the cross-dossier primary authorities used for the normalized rules above.

[^bsd]: [McCanne & Jacobson, *The BSD Packet Filter: A New Architecture for User-level Packet Capture* (USENIX, 1993)](https://www.usenix.org/legacy/publications/library/proceedings/sd93/mccanne.pdf).
[^kernel-isa]: [Linux kernel documentation, *BPF Instruction Set Architecture*](https://docs.kernel.org/bpf/standardization/instruction-set.html).
[^bpf2]: [Linux man-pages, `bpf(2)`](https://man7.org/linux/man-pages/man2/bpf.2.html).
[^bpf-syscall]: [Linux kernel documentation, *eBPF Syscall*](https://docs.kernel.org/userspace-api/ebpf/syscall.html).
[^design-qa]: [Linux kernel documentation, *BPF Design Q&A*](https://docs.kernel.org/bpf/bpf_design_QA.html).
[^events]: [Linux kernel documentation, *Event Tracing*](https://docs.kernel.org/trace/events.html).
[^verifier]: [Linux kernel documentation, *eBPF verifier*](https://docs.kernel.org/bpf/verifier.html).
[^btf]: [Linux kernel documentation, *BPF Type Format (BTF)*](https://docs.kernel.org/bpf/btf.html).
[^core]: [Linux kernel documentation, *BPF LLVM Relocations*](https://docs.kernel.org/bpf/llvm_reloc.html).
[^aya-tracepoints]: [Aya Book, *Tracepoints*](https://aya-rs.dev/book/programs/tracepoints.html).
[^aya-loader]: [Aya 0.14.0 API documentation, `EbpfLoader`](https://docs.rs/aya/0.14.0/aya/struct.EbpfLoader.html). The book must supplement this with the exact source/tag compiled by its locked companion project.
[^capabilities]: [Linux man-pages, `capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html).
[^perf-security]: [Linux kernel documentation, *Perf events and tool security*](https://docs.kernel.org/admin-guide/perf-security.html).
[^nixos-kernel]: [Nixpkgs `nixos/modules/system/boot/kernel.nix`](https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/system/boot/kernel.nix) (source snapshot; pin revision before publishing a configuration example).
[^lsm-bpf]: [Linux kernel documentation, *LSM BPF Programs*](https://docs.kernel.org/bpf/prog_lsm.html).
