# Part 01 — Foundations and the NixOS Laboratory

**Audience:** advanced beginners who want a defensible mental model before writing eBPF in Rust.
**Research cut-off:** **10 September 2026**. Kernel documentation consulted was the current documentation set published as 7.3.0-rc2; the NixOS material was the stable 26.05 option reference plus the current `nixpkgs` source tree. Treat all claims labelled *version-dependent* as things to re-check on the actual booted kernel and pinned Nixpkgs revision.

## Executive position

eBPF is **not kernel C loaded at runtime**, and it is not ordinary userspace Rust. It is a constrained instruction set and object model in which a userspace loader asks the kernel to create maps, verify and load a program, and attach that program to a permitted hook. The kernel verifier proves a conservative safety model over the actual bytecode and its possible paths before the program can run. The kernel may then run the program when its hook fires; information should cross back through explicitly defined maps or event channels, not arbitrary pointers. [2] [3] [7]

For a first laboratory program, attach a tiny Aya `BPF_PROG_TYPE_TRACEPOINT` program to the static `sched/sched_switch` event, increment a **per-CPU array** counter, read and sum it in userspace, and exit without pinning anything. It observes no event payload, reads no task memory, creates no persistent objects, and has an obvious cleanup boundary. This deliberately teaches the full lifecycle while avoiding the most common early failures: event-format offsets, user-pointer reads, large BPF stacks, unbounded event output, cross-CPU counter races, and accidental persistence. [9] [14] [18]

> **Safety boundary:** Rust improves the ergonomics of the userspace loader and can make eBPF code clearer, but it does not replace the kernel verifier. Aya’s `TracePointContext::read_at<T>` is explicitly `unsafe`; a mistaken tracepoint offset or type is still the author’s responsibility. Keep each `unsafe` block narrow and explain its invariant. [17] [24]

---

## 1. Chapter claims and the conceptual foundation

### 1.1 What BPF became, and why it matters

The original **BSD Packet Filter** was introduced for user-level packet capture. Its central performance idea was to reject unwanted packets in a kernel-resident filter before copying them across the kernel/userspace protection boundary. The 1993 paper describes a register-based filter evaluator and reports substantially lower packet-capture overhead than the preceding designs. [1]

Modern Linux **eBPF** retained the controlled in-kernel program idea but generalized it beyond packet filtering. The kernel’s ISA specification says that “BPF” historically meant Berkeley Packet Filter, but it now uses BPF as a standalone term; classic BPF is commonly called **cBPF** and extended BPF **eBPF**. eBPF is a general instruction set whose loaded program is associated with a program type and an execution context. [2] [5]

The motivation is therefore not “run arbitrary Rust in the kernel.” It is to make narrowly scoped kernel extension and observation possible without compiling a bespoke kernel module for every question. A scheduler tracepoint can count switches; networking hooks can process packets; security and other hook families have their own contracts. The benefit comes with a non-negotiable constraint: a program can access only the context fields, maps, helpers, and attach behavior that the kernel permits for **that program type**. [3] [4] [7]

| Chapter claim | What is invariant enough to teach | What must not be over-promised |
|---|---|---|
| eBPF is safe to load only after verification | `BPF_PROG_LOAD` verifies and returns a program file descriptor on success. The verifier models control flow, register state, pointers, stack initialization, helper arguments, bounds, and alignment. [3] [6] [7] | Verification is not an assertion that the program’s *measurement interpretation* is correct, complete, private, or low-overhead. |
| eBPF can be fast | The ISA was designed for efficient implementation and Linux can JIT BPF where supported. [5] [36] | Do not write “eBPF is always JITed” or claim a particular overhead without measuring the specific kernel, CPU, hook, map, and workload. |
| eBPF is portable | The instruction ABI, recognized helpers, helper arguments, and return codes have compatibility commitments; accepted programs are intended to remain accepted by later kernels. [4] | This is forward compatibility, not a promise that a new object loads on an older kernel. Tracepoints, kprobe locations, kfuncs, kernel struct layouts, and helper availability need separate treatment. |
| BPF is a kernel/user collaboration | Maps are shared kernel/userspace data structures accessed through file descriptors; userspace creates, loads, attaches, reads, and tears down. [3] [6] | A file descriptor is not persistence. Objects may outlive a process only while another reference, attachment, or explicit bpffs pin remains. [6] |

### 1.2 The execution model: two Rust worlds and one kernel decision

An Aya project normally has a **userspace loader crate** and an **eBPF crate**. The loader can use `std`, open files, parse configuration, report errors, and coordinate shutdown. The eBPF crate is `#![no_std]` and `#![no_main]`; `no_std` removes automatic linking of `std` and substitutes the `core` prelude. That is appropriate because BPF execution cannot rely on ordinary process facilities such as filesystem I/O, threads, or heap-backed standard-library behavior. [23] [21]

The compiler and linker generate an ELF object containing BPF instructions, maps, program sections, and possibly debug/BTF metadata. The loader passes the object to the kernel. The kernel creates the maps, runs the verifier for each program, and returns file descriptors for the accepted objects. Program type controls the initial context in BPF register `R1`; the verifier then permits only the relevant accesses and helpers. After a helper call, `R1`–`R5` are unreadable, `R0` is the helper result, and `R6`–`R9` are callee-saved. [5] [7]

This partition has a practical consequence: data types that cross the boundary must have deliberate, stable layout. For the first counter, use a scalar `u64`. For later records, prefer a small `#[repr(C)]` plain-data structure, explicit integer widths, and tests for size/alignment on both sides. Do not transmit a Rust `String`, a reference, a pointer, `bool` whose ABI assumptions are implicit, or an enum with an unspecified representation as a map value.

### 1.3 The tracing lifecycle

A static tracepoint is an intentionally placed kernel callback site. The tracepoint API describes static probes at strategic kernel locations, with callback parameters determined by each tracepoint. Its exported event interface is exposed through tracefs. [8] [9]

```text
kernel source selects a static tracepoint
        │
        ▼
tracefs exposes events/<category>/<name>/id and format
        │                         │
        │                         └── inspect before decoding payload bytes
        ▼
Aya loader parses ELF and creates maps
        │
        ▼
BPF_PROG_LOAD → verifier accepts or rejects actual bytecode → program FD
        │
        ▼
Aya TracePoint::attach(category, name)
  reads tracefs event ID → opens perf tracepoint event → attaches program
        │
        ▼
tracepoint fires → BPF program runs with a tracepoint context
        │
        ▼
program updates a map → userspace reads/sums/prints the result
        │
        ▼
controlled shutdown: links, program FDs, and map FDs close; no pin means no
intentional retained object
```

The current Aya `TracePoint::attach(&mut self, category: &str, name: &str)` API returns a `TracePointLinkId`. Aya’s current source finds a usable tracefs mount, reads `events/<category>/<name>/id`, opens the tracepoint through `perf_event_open`, and attaches through its perf attachment path. It is therefore a mistake to describe this particular Aya tracepoint API as universally using `BPF_LINK_CREATE`; attachment mechanics vary by program type and library implementation. [15] [16]

**Tracefs is discovery data, not a hard-coded ABI.** Every event has a `format` file containing its common fields, event-specific fields, offsets, sizes, and the event ID. Before reading a tracepoint context manually, inspect the target system’s `format` file. The directory is normally `/sys/kernel/tracing/events`; legacy tooling may use `/sys/kernel/debug/tracing`. Current Aya probes `/sys/kernel/tracing` first and falls back to the legacy path only when the directory is nonempty. [9] [10] [16]

---

## 2. NixOS laboratory: prerequisites, not assumptions

### 2.1 Laboratory posture

Use a disposable NixOS virtual machine, a non-production host, or a workload-approved test window. Begin with a program that observes a counter only. Do not add file capture, user-memory reads, task names, logging per event, pinning, long-running services, automatic loading, or policy-changing program types to the first exercise.

The NixOS part of the laboratory is **reproducibility**, not a reason to weaken the host. Pin the Nixpkgs revision for the book exercises. Keep the kernel package selection and development tool set in configuration; record `uname -r`, the NixOS generation, and the Nixpkgs revision beside each trace result. A package build environment and the running kernel are separate: a perfect Rust toolchain cannot add an unavailable kernel program type or tracepoint.

### 2.2 Current NixOS facilities and what to verify

The stable NixOS option reference defines `boot.kernelPackages` as the kernel package set, and notes that dependent external kernel modules are tied to that choice. It provides `boot.kernelPatches` with `structuredExtraConfig` for deliberate kernel configuration changes; configuration names omit the `CONFIG_` prefix and values should use `lib.kernel.yes`, `no`, or `module`. [28] [30]

The current Nixpkgs common kernel configuration is favorable to an eBPF laboratory: it enables `BPF_SYSCALL`, `BPF_EVENTS`, ftrace-related options, and debug information. It requests `DEBUG_INFO_BTF` as an optional setting on kernels at least 5.11 and uses `pahole` for kernel versions at least 5.2. These are **current Nixpkgs source defaults, not a guarantee about every NixOS machine**. A custom `boot.kernelPackages`, a deliberately minimized kernel, an unsupported architecture, a VM/container supplied kernel, or a hardened configuration can differ. [29] [30]

The kernel Kconfig dependencies explain the minimum conceptual set. `CONFIG_BPF_SYSCALL` enables the `bpf()` syscall and selects the core BPF facility. `CONFIG_BPF_EVENTS` is the switch that enables BPF attachment to kprobe, uprobe, and tracepoint events; it depends on `BPF_SYSCALL`, `PERF_EVENTS`, and kprobe or uprobe event support. Kernel tracing configuration selects `TRACEPOINTS` and `EVENT_TRACING` under tracing. A tracing lab needs the corresponding tracefs event to be present, regardless of how an option was named in another release. [36] [37]

| Requirement | Safe test on the *running* system | Why it matters | Status to teach |
|---|---|---|---|
| Correct booted kernel | `uname -r`; record `nixos-version` and your pinned input revision | Build packages do not replace the host kernel. | Required |
| BPF syscall and tracepoint support | `test -e /sys/kernel/tracing/events/sched/sched_switch/id` and inspect the event directory | A first static tracepoint must exist before it can be attached. | Required for this example |
| tracefs mounted and readable | `findmnt -T /sys/kernel/tracing`; `ls /sys/kernel/tracing/events/sched` | Aya needs the event ID; users need the `format` file. | Required for tracepoints |
| bpffs mounted | `findmnt -T /sys/fs/bpf` | Needed only for deliberately pinned BPF objects; not needed by the first counter. | Recommended diagnostic; not a first-program requirement |
| kernel BTF | `test -r /sys/kernel/btf/vmlinux && stat -c '%s bytes' /sys/kernel/btf/vmlinux` | Needed for BTF-dependent workflows and useful introspection/CO-RE; not needed by the payload-free counter. | Recommended, later required |
| permissions | run the loader with narrowly reviewed privilege; inspect failures rather than changing global sysctls | A tracepoint program is a performance-observability program and has capability checks. | Required |
| tools | `command -v bpftool bpftrace bpf-linker` | Object inspection, tracepoint discovery, and build. | Recommended |

On a usual NixOS systemd boot, NixOS includes `sys-kernel-tracing.mount` among packaged upstream units. The upstream unit mounts `tracefs` at `/sys/kernel/tracing` with `nosuid,nodev,noexec`, subject to its conditions. Systemd’s early mount setup also mounts bpffs at `/sys/fs/bpf` with `mode=0700`, `nosuid,nodev,noexec`. A container, a non-systemd environment, a constrained VM, or a changed unit policy may not expose either mount, so **check with `findmnt` rather than mounting blindly**. [34] [35] [10]

### 2.3 A small declarative tool baseline

The current Nixpkgs package attribute is `bpftools` (plural); its derivation installs the `bpftool` binary. Current Nixpkgs also exposes `bpftrace` and `bpf-linker`. The latter is packaged as version 0.11.0 in the source consulted. [31] [32] [33]

```nix
# configuration.nix — illustrative laboratory tools, not a privilege grant
{ pkgs, ... }:
{
  environment.systemPackages = with pkgs; [
    bpftools     # installs the `bpftool` executable
    bpftrace     # optional event discovery and comparison tool
    bpf-linker   # required by the Aya template's eBPF build path
    cargo-generate
  ];
}
```

`environment.systemPackages` makes packages available under `/run/current-system/sw` for all users after a rebuild; it does not grant BPF or perf capabilities. Keep kernel selection unchanged unless the verification table demonstrates that a prerequisite is missing. [28]

If a custom laboratory kernel genuinely needs configuration changes, make them explicit, review them, and rebuild/reboot into the result. The NixOS interface is:

```nix
# Only when verification proves a custom kernel needs it.
{ lib, ... }:
{
  boot.kernelPatches = [
    {
      name = "ebpf-lab-prerequisites";
      patch = null;
      structuredExtraConfig = with lib.kernel; {
        BPF_SYSCALL = yes;
        BPF_EVENTS = yes;
        # DEBUG_INFO and DEBUG_INFO_BTF are deployment/version dependent.
        # Set only after confirming the selected kernel exposes these symbols.
      };
    }
  ];
}
```

Do **not** copy that fragment as a universal recipe. Kconfig names and dependencies move; BTF has build-tool dependencies; and the current common Nixpkgs kernel configuration already asks for the relevant options on its supported configurations. Check the generated booted configuration where available, and treat a failed Nix kernel build as a configuration incompatibility to resolve—not a prompt to suppress errors. [29] [30] [36]

### 2.4 Rust and Aya build prerequisites

Aya’s current development guide calls for stable Rust, nightly Rust with the `rust-src` component, `bpf-linker`, `cargo-generate`, and `bpftool` for generating kernel bindings. The current Aya template has the host build invoke `aya_build::build_ebpf`, while its eBPF build script finds `bpf-linker` on `PATH`. [20] [21]

The source snapshot checked for this research declares Aya `0.14.0`, Aya eBPF `0.2.1`, Rust edition 2024, and minimum Rust `1.87.0`. Pin compatible crate versions in a real book repository instead of using a floating `main` branch as a release contract. The bpf-linker README documents direct compilation for `bpfel-unknown-none` with nightly and `-Z build-std=core`; its BTF emission instructions are explicitly marked experimental and use `-C debuginfo=2 -C link-arg=--btf`. Prefer the template/integrated build route for early chapters, then introduce direct invocation as a build-mechanics chapter. [21] [22]

---

## 3. BTF, bpffs, and tracefs: three distinct things

### 3.1 BTF: compact type metadata, not a permission bypass

**BPF Type Format (BTF)** is compact type and debug metadata. The kernel BTF documentation specifies BTF use in `BPF_BTF_LOAD`, BTF-aware map creation, and program load function/line information. The BTF extension section can contain CO-RE relocation records. [11] [12]

The running kernel may publish its base BTF at `/sys/kernel/btf/vmlinux`. Kernel source creates that read-only sysfs binary attribute only when the linked kernel has nonzero BTF data. Aya’s current `Ebpf::load` and `Ebpf::load_file` documentation says that, when the kernel supports BTF debug information, Aya automatically loads `/sys/kernel/btf/vmlinux`. [19] [13]

Use BTF in stages:

1. **First counter:** no BTF dependency is needed because the program ignores the event payload and uses only a per-CPU scalar map.
2. **Inspect types:** on a target with BTF, use `bpftool btf dump file /sys/kernel/btf/vmlinux format c` to generate a target-specific type header for study. [39]
3. **Later portability work:** compile object BTF and CO-RE relocation metadata, then test the artifact against each supported kernel. CO-RE can patch field offsets, sizes, existence tests, type properties, and enum values at load time; it does not make every kernel interface a stable ABI. [12]

> **Cautious wording:** “BTF and CO-RE can reduce kernel-structure layout coupling.” Do **not** write “compile once, runs on every kernel.” A target still needs the relevant program type, helper/kfunc, attach target, BTF data when required, compatible semantic behavior, and a loader that understands the object’s metadata. [4] [12]

### 3.2 bpffs: named references and lifecycle control

**bpffs** is the BPF filesystem, normally mounted at `/sys/fs/bpf`. It is a special filesystem for holding references to BPF maps, programs, and links. `BPF_OBJ_PIN` associates a path with a BPF object and retains a reference after the original FD closes; `unlink` removes that pin, and the object is freed only if no other FD, pin, attachment, or other kernel reference remains. The filesystem implementation identifies program, map, and link objects separately. [6] [13]

That lifecycle is useful for controlled, reviewed services. It is counterproductive for the first exercise. The first program should **not pin** a map, program, or link. Let process lifetime be the experiment lifetime.

Aya currently exposes `TracePoint::pin`, `unpin`, and `from_pin`. Its API documentation says a pinned program remains loaded after Aya unloads it, and removing the bpffs path is required to remove the pin. Therefore, pinning is an explicit state-management decision that needs ownership, cleanup, permission, upgrade, and rollback design; it is not an optimization or a debugging shortcut. [15]

### 3.3 tracefs: tracepoint inventory and format oracle

**tracefs** exposes the kernel tracing control and event interface. Ftrace documentation describes `/sys/kernel/tracing` as the tracefs location and documents the older `/sys/kernel/debug/tracing` path as backward compatibility. Event documentation says each event’s `format` file describes fields, offsets, and sizes, and separates common fields from event-specific fields. [9] [10]

For a tracepoint whose payload will be read, capture this evidence in a test artifact:

```sh
EVENT=/sys/kernel/tracing/events/sched/sched_switch
cat "$EVENT/id"
sed -n '1,160p' "$EVENT/format"
```

The `id` is an attachment input. The `format` is a target-specific decoding contract. Neither tells you that field names, ordering, layout, or event availability will be identical on a different kernel. The kernel design FAQ is explicit: tracepoints are not a stable ABI. [4]

---

## 4. Capability and policy model

### 4.1 Minimum-privilege interpretation

Linux capabilities split parts of traditional root authority. `CAP_BPF` and `CAP_PERFMON` were added in Linux 5.8 to split BPF and performance-monitoring authority from the overloaded `CAP_SYS_ADMIN`. The current kernel program-load path classifies `BPF_PROG_TYPE_TRACEPOINT` as a performance-monitoring program type and checks both BPF authority and performance-monitoring authority. `CAP_SYS_ADMIN` remains a backward-compatible, broader authority. [25] [40]

For a current tracepoint lab, express the requirement this way:

| Operation | Current least-broad capability interpretation | Conservative lab practice |
|---|---|---|
| Create/load tracepoint BPF program | `CAP_BPF` plus `CAP_PERFMON` in the applicable capability context; the current kernel source places tracepoint programs in the perfmon class. [40] | Use a short, reviewed elevated run on a disposable system. Do not turn off security controls globally. |
| Attach Aya `TracePoint` | Aya uses a perf tracepoint event; perf access is controlled by `CAP_PERFMON` (or the broader `CAP_SYS_ADMIN`) and `perf_event_paranoid` rules. [16] [27] | Do not reduce `perf_event_paranoid` merely to make a system-wide experiment run. |
| Mount a filesystem | Mounting normally requires broad administration authority. [38] | Do not mount bpffs/tracefs from the app. Have the OS boot policy provide them, then verify them. |
| Read/write pinned objects | Path permissions plus BPF-object/capability rules apply. | Avoid pins in the first program. Give a production service a dedicated directory and explicit owner/cleanup policy. |

On kernels predating the 5.8 capability split, documentation and tools commonly require `CAP_SYS_ADMIN`; on modern systems, use the narrower capabilities when a reviewed service design needs delegated authority. Do not attach file capabilities to a general-purpose shell, compiler, Cargo binary, or broad wrapper merely to run a book example. The performance-security documentation explicitly recommends `CAP_PERFMON` over `CAP_SYS_ADMIN` for performance/observability cases. [25] [26]

The current BPF syscall documentation also describes **BPF tokens**, which can delegate allowed BPF commands, map types, program types, and attach types from a bpffs instance. Tokens alter where capability checks are evaluated. This is advanced containment design, not a beginner setup step; the first program must work with ordinary, short-lived supervision and must not depend on token configuration. [6]

### 4.2 Sysctls and limits: diagnose; do not weaken

`/proc/sys/kernel/unprivileged_bpf_disabled` has three documented states: `0` permits unprivileged BPF calls, `1` disables them irreversibly for the running kernel, and `2` disables them but permits a later administrative change. `CONFIG_BPF_UNPRIV_DEFAULT_OFF` makes `2` the default. This setting is a security policy, not a laboratory convenience switch. A privileged tracepoint loader should not require changing it. [38] [36]

Older kernels may account BPF memory through `RLIMIT_MEMLOCK`; Aya’s tracepoint example raises it because older kernels use that model. Current systems can instead use memory-cgroup-based accounting. For a single one-element counter map, do not set `RLIM_INFINITY` preemptively. If a load fails due to an accountable resource limit, record the kernel/version/error and make the smallest scoped adjustment justified by the deployment model. [14]

---

## 5. Safe first Aya tracepoint program

### 5.1 Design goals and non-goals

**Goal:** count scheduler switch events for a brief run and print an approximate aggregate count.
**Not a goal:** identify tasks, collect paths, log each switch, inspect raw tracepoint bytes, pin anything, or run as a background service.

`sched/sched_switch` is a good first attachment because it is a named static tracepoint that can be discovered in tracefs. It can be frequent, so the BPF side does exactly one map lookup and one local counter update. The program does not inspect its context. That means no hard-coded field offset, no dependency on a particular `format` layout, and no need to read unsafe kernel or userspace memory. [9] [14]

A per-CPU array has one value per CPU for a given index. Aya’s eBPF-side `PerCpuArray::get_ptr_mut(0)` returns a pointer to the current CPU’s value, and its userspace map API returns a `PerCpuValues<V>` collection for all CPU values. Summing those values in userspace avoids a contended shared global counter. The aggregate is a snapshot, not a transactionally consistent global measurement; events can occur while it is being read. [18]

### 5.2 eBPF crate (`lab-count-ebpf/src/main.rs`)

The exact macro and map API names below were checked against current Aya documentation and source: `#[tracepoint]`, `TracePointContext`, `PerCpuArray::with_max_entries`, and `get_ptr_mut`. [17] [18] [21]

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

// One index, but a separate u64 value for every CPU.
#[map]
static HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn count_switches(_ctx: TracePointContext) -> u32 {
    // `get_ptr_mut` is fallible from the verifier's point of view.
    // Do nothing rather than attempting an invalid dereference.
    if let Some(counter) = HITS.get_ptr_mut(0) {
        // SAFETY: `counter` came from the current CPU's element in `HITS`.
        // This program does not retain it, use it after another helper, or
        // pass it across the kernel/userspace boundary. The map value is u64
        // and the operation deliberately wraps rather than panics on overflow.
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }

    // Tracepoint programs in this lesson always return success.
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

The explicit `unsafe(...)` attribute syntax follows current Rust rules: `link_section` and `no_mangle` are unsafe attributes whose obligations cannot be checked by the compiler. The raw-pointer dereference is the only operation in the program’s body that needs an `unsafe` block. [23] [24]

**Why no `ctx.read_at`?** Aya exposes `TracePointContext::read_at<T>(&self, offset: usize) -> Result<T, i32>` as `unsafe`, and its implementation reads from the context through a kernel-read helper. Any example that says “offset 16 is the filename pointer” is specific to a particular trace event layout and should first derive and test that offset from the target’s `format` file. The Aya `sys_enter_execve` chapter demonstrates such an offset-based read, but that is a *second* lesson, not the zero-payload first program. [14] [17]

### 5.3 Userspace loader sketch (`lab-count/src/main.rs`)

The `include_bytes_aligned!` approach is Aya’s documented safe way to supply an appropriately aligned embedded object to `Ebpf::load`. Keep the `Ebpf` owner and the typed map alive for the duration of observation. The exact generated artifact name depends on the template/build script; replace `lab-count-ebpf` with the file emitted by your pinned project. [19] [21]

```rust
use std::{thread, time::Duration};

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::PerCpuArray,
    programs::TracePoint,
};

fn main() -> Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lab-count-ebpf"
    )))?;

    {
        let program: &mut TracePoint = ebpf
            .program_mut("count_switches")
            .context("count_switches program missing from the BPF object")?
            .try_into()?;

        program.load().context("verifier rejected the tracepoint program")?;
        let _link = program
            .attach("sched", "sched_switch")
            .context("cannot attach to sched/sched_switch on this kernel")?;
        // The link is managed by `program`; `ebpf` remains alive below.
    }

    thread::sleep(Duration::from_secs(1));

    let map = PerCpuArray::<_, u64>::try_from(
        ebpf.map_mut("HITS").context("HITS map missing from BPF object")?
    )?;
    let values = map.get(&0, 0)?;
    let total = values.iter().copied().sum::<u64>();
    println!("scheduler switches observed during the ~1 s window: {total}");

    // `ebpf` is dropped on return. No map/program/link has been pinned.
    Ok(())
}
```

A production-quality loader should additionally print the booted kernel release, selected tracepoint, duration, and a redacted diagnostic for loader errors. It should keep the program name and event pair in a narrow allow-list rather than accepting arbitrary attachment targets from untrusted input. It should also handle `Ctrl-C` by exiting cleanly rather than pinning state to survive the process.

### 5.4 Run checklist and expected cleanup

1. Confirm the event exists: `test -r /sys/kernel/tracing/events/sched/sched_switch/id`.
2. Read the event `format` anyway, even though this first program ignores it; learn where the contract lives.
3. Run for a short fixed interval under the narrowly reviewed privilege context appropriate to the host.
4. Confirm the process exits. It must not have written under `/sys/fs/bpf`.
5. If load fails, capture the complete Aya error and kernel/version metadata. Do not respond by disabling `unprivileged_bpf_disabled`, reducing `perf_event_paranoid`, granting blanket `CAP_SYS_ADMIN`, or pinning the program.

Aya documents `TracePoint::unload` as detaching tracked links before unloading, while links taken with `take_link` become the caller’s lifetime responsibility. The first program does neither pinning nor link transfer, so normal owned-object drop is the desired experiment cleanup. [15]

---

## 6. Verifier-first engineering

### 6.1 A useful mental model

The verifier follows all reachable control-flow paths. It tracks whether a register has a safe scalar or pointer type, whether a pointer access is in bounds and aligned, whether a stack byte was initialized before read, whether a helper’s arguments are valid, and whether nullable values are checked before dereference. It rejects uncertain paths rather than guessing. [7]

The kernel reference gives concrete examples: an unread register is rejected; `R1`–`R5` cannot be used after a helper call; stack reads require prior writes; a map lookup result is `PTR_TO_MAP_VALUE_OR_NULL` until a null check; and an 8-byte store at an unaligned offset is rejected. [7]

| Trap | Typical beginner symptom | Defensive design response |
|---|---|---|
| Read from an uninitialized stack slot | Verifier: invalid indirect stack read | Initialize every buffer/struct field on every path before passing it to a helper. [7] |
| Dereference a nullable map result | Verifier: `map_value_or_null` invalid memory access | Use `Option`/`ok_or` or an explicit branch immediately after lookup. The sample does this. [7] |
| Incorrect tracepoint offset or width | Load rejection, helper error, or silently wrong measurement | Derive offsets/types from the running target’s `format`; begin with a payload-free program. [9] [14] |
| Excessive stack use | Stack-depth or complex verifier failure | Keep BPF locals small. The design FAQ states a 512-byte BPF stack limit; use a fixed per-CPU buffer for later bounded strings. [4] [14] |
| State explosion | “program too large/complex” or verification limit failure | Split logic, bound loops explicitly, simplify branches, and test the oldest target kernel early. The only authoritative acceptance test is loading on that kernel. [4] |
| Shared counter race | Lost counts or a slow contended atomic update | Prefer per-CPU aggregation where semantics permit; sum on the userspace side. [3] [18] |
| Logging every high-rate event | Drop/noise/overhead, or test machine distortion | Count first; sample, filter, and rate-limit later. Do not put an unbounded logger in a scheduler hook. |
| A long `unsafe` block | Rust source hides the actual invariant | Isolate pointer use. State origin, lifetime, type/alignment, and why no helper call invalidates assumptions. [24] |

### 6.2 Verifier logs are design feedback

A verifier error is neither merely a compiler bug nor something to bypass. Record the exact BPF object build, `uname -r`, event name, map definition, error, and source line. Reduce the program until it loads, then reintroduce logic in small steps. This gives the book reader a reproducible methodology and prevents accidental dependence on a newer verifier’s analysis improvements. The kernel design FAQ explicitly says verifier limits evolve and that loading is the only way to know whether a program will be accepted. [4]

---

## 7. Portability risks and exact wording to use

### 7.1 Invariants versus version-dependent behavior

| Topic | Teach as an invariant | Version-dependent detail to verify | Preferred chapter wording |
|---|---|---|---|
| BPF object lifecycle | FDs, pins, attachments, and other refs determine object lifetime. [6] | Exact attachment/link implementation and which refs persist vary by program type and library. | “The object remains while a kernel or userspace reference exists; inspect the attachment model used by this API.” |
| Tracepoints | Events have an event-specific format file in tracefs. [9] | Event names, fields, offsets, sizes, and semantics are not a stable ABI. [4] | “Discover and validate this event on each target kernel.” |
| BTF | BTF encodes type/debug metadata and participates in BPF loads/maps. [11] | `/sys/kernel/btf/vmlinux`, object BTF, CO-RE support, and relevant type availability depend on kernel/build. | “Use BTF when present; make the feature optional or fail clearly when it is required.” |
| Aya tracepoint API | Current `TracePoint` has `load`, `attach(category, name)`, `detach`, `take_link`, `unload`, and pin APIs. [15] | Aya releases and implementation mechanics change; source checked was 0.14.0/0.2.1. | “Pin Aya versions and compile the example in CI; do not copy an API signature from an unpinned blog post.” |
| Privilege | Modern Linux has `CAP_BPF` and `CAP_PERFMON`; current tracepoint load checks need both capability classes. [25] [40] | Pre-5.8 kernels and deployment user namespaces/tokens differ. | “On current kernels, start by planning for `CAP_BPF` + `CAP_PERFMON`; test the real kernel and document the fallback.” |
| NixOS defaults | Nixpkgs current common config enables relevant BPF/tracing options and requests BTF under stated conditions. [29] | Custom kernel package, architecture, container kernel, and future Nixpkgs revision may differ. | “NixOS commonly supplies these prerequisites; verify the booted kernel instead of assuming a distribution promise.” |
| Memlock | BPF memory is accountable. | Older kernels use `RLIMIT_MEMLOCK`; newer accounting can use memory cgroups. [14] | “Do not raise limits until a documented load failure identifies the applicable limit.” |

### 7.2 Claims that need cautious wording

1. **Do not say “tracepoints are stable.”** Say static tracepoints are intentionally defined observation points and their current layouts can be discovered in tracefs; the kernel does not promise tracepoints as a stable ABI. [4] [8]
2. **Do not say “the verifier proves the program is bug-free.”** Say it proves the kernel’s BPF safety properties for the loaded bytecode under the program type’s model. It cannot prove that a count answers the desired performance question or that collection is appropriate for the data classification.
3. **Do not say “BTF makes programs portable.”** Say BTF/CO-RE can adapt certain type-layout and existence differences, subject to both object and target capabilities. [12]
4. **Do not say “root is required.”** Say current capability checks matter; `CAP_BPF` and `CAP_PERFMON` are narrower than `CAP_SYS_ADMIN`, but deployment, user namespace, LSM, and perf policy can add constraints. [25] [26] [40]
5. **Do not say “NixOS enables BTF.”** Say the inspected current Nixpkgs common config requests it conditionally; verify `/sys/kernel/btf/vmlinux` on the booted target. [29]
6. **Do not say “the program disappears when the process exits.”** Say it disappears when its last reference is released. A pin or attachment can retain it. [6]
7. **Do not say “Aya abstracts away tracefs.”** Say current Aya discovers tracefs and reads event IDs for `TracePoint::attach`; a missing/inaccessible tracefs remains an operational failure. [16]
8. **Do not say “this sample measures all scheduler activity exactly.”** Say it counts invocations of the selected event while attached and reports a non-atomic userspace aggregate snapshot.

---

## 8. Recommended exercises after the first counter

Progress only after the preceding exercise has a repeatable build, a recorded target matrix, and a demonstrated cleanup path.

| Next exercise | New idea | Protective constraint |
|---|---|---|
| Add a duration and repeat the count | Measurement baseline and variance | Keep the BPF program unchanged; compare userspace aggregates only. |
| Read one fixed scalar from a tracepoint context | Event `format`, alignment, `read_at` safety | Capture the target `format` in a fixture; validate offset/size before code. |
| Emit a bounded record to userspace | Data transport and loss accounting | Fixed-size schema, explicit maximum rate, no path/argument capture, loss counter. |
| Add BTF inspection | `/sys/kernel/btf/vmlinux`, target metadata | Fail clearly if BTF is absent; do not regenerate target bindings from a different kernel and call them portable. |
| Test two pinned NixOS kernels | Compatibility discipline | Run the same CI fixture and record attach/load behavior; no dynamic fallback to unrelated hooks. |
| Introduce a pin only in a dedicated lifecycle chapter | bpffs ownership and rollback | Named project directory, explicit owner, idempotent cleanup, inspection, and uninstall test. |

The essential habit is to treat the kernel as a versioned execution environment with explicit contracts. Build the smallest useful thing, inspect its target-specific interfaces, load it under the least authority that satisfies current checks, observe briefly, and prove that it cleaned up.

---

## Source ledger and references

The following are the authoritative and supporting sources actually read for this dossier. Direct source-code links are included when an API or default was verified from implementation rather than prose. The Nixpkgs and Aya `main` URLs are source snapshots, not release guarantees.

[1]: https://www.usenix.org/legacy/publications/library/proceedings/sd93/mccanne.pdf "The BSD Packet Filter: A New Architecture for User-level Packet Capture"
[2]: https://docs.kernel.org/bpf/standardization/instruction-set.html "BPF Instruction Set Architecture"
[3]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — perform a command on an extended BPF map or program"
[4]: https://docs.kernel.org/bpf/bpf_design_QA.html "BPF Design Q&A"
[5]: https://docs.kernel.org/bpf/classic_vs_extended.html "Classic BPF vs eBPF"
[6]: https://docs.kernel.org/userspace-api/ebpf/syscall.html "eBPF Syscall"
[7]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier"
[8]: https://docs.kernel.org/core-api/tracepoint.html "The Linux Kernel Tracepoint API"
[9]: https://docs.kernel.org/trace/events.html "Event Tracing"
[10]: https://docs.kernel.org/trace/ftrace.html "ftrace - Function Tracer"
[11]: https://docs.kernel.org/bpf/btf.html "BPF Type Format (BTF)"
[12]: https://docs.kernel.org/bpf/llvm_reloc.html "BPF LLVM Relocations"
[13]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/inode.c "Linux kernel bpffs implementation"
[14]: https://aya-rs.dev/book/programs/tracepoints.html "Building eBPF Programs with Aya: Tracepoints"
[15]: https://docs.rs/aya/latest/aya/programs/trace_point/struct.TracePoint.html "Aya TracePoint API"
[16]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/programs/trace_point.rs "Aya TracePoint implementation"
[17]: https://docs.rs/aya-ebpf/latest/aya_ebpf/programs/tracepoint/struct.TracePointContext.html "Aya eBPF TracePointContext API"
[18]: https://docs.rs/aya-ebpf/latest/aya_ebpf/maps/per_cpu_array/struct.PerCpuArray.html "Aya eBPF PerCpuArray API"
[19]: https://docs.rs/aya/latest/aya/struct.Ebpf.html "Aya Ebpf loader API"
[20]: https://aya-rs.dev/book/start/development/ "Building eBPF Programs with Aya: Development Environment"
[21]: https://github.com/aya-rs/aya-template "Aya project template"
[22]: https://raw.githubusercontent.com/aya-rs/bpf-linker/main/README.md "bpf-linker README"
[23]: https://doc.rust-lang.org/reference/names/preludes.html "The Rust Reference: Preludes and no_std"
[24]: https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html "The Rust Programming Language: Unsafe Rust"
[25]: https://man7.org/linux/man-pages/man7/capabilities.7.html "capabilities(7)"
[26]: https://docs.kernel.org/admin-guide/perf-security.html "Perf events and tool security"
[27]: https://man7.org/linux/man-pages/man2/perf_event_open.2.html "perf_event_open(2)"
[28]: https://nixos.org/manual/nixos/stable/options "NixOS option reference"
[29]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/os-specific/linux/kernel/common-config.nix "Nixpkgs common Linux kernel configuration"
[30]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/system/boot/kernel.nix "NixOS kernel options module"
[31]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/by-name/bp/bpftools/package.nix "Nixpkgs bpftools package"
[32]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/by-name/bp/bpftrace/package.nix "Nixpkgs bpftrace package"
[33]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/by-name/bp/bpf-linker/package.nix "Nixpkgs bpf-linker package"
[34]: https://raw.githubusercontent.com/systemd/systemd/main/src/shared/mount-setup.c "systemd API filesystem mount setup"
[35]: https://raw.githubusercontent.com/systemd/systemd/main/units/sys-kernel-tracing.mount "systemd tracefs mount unit"
[36]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/Kconfig "Linux BPF Kconfig"
[37]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/trace/Kconfig "Linux tracing Kconfig"
[38]: https://docs.kernel.org/admin-guide/sysctl/kernel.html "Linux kernel sysctl documentation"
[39]: https://docs.kernel.org/bpf/prog_lsm.html "LSM BPF Programs"
[40]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/syscall.c "Linux BPF syscall implementation"
[41]: https://raw.githubusercontent.com/aya-rs/aya/main/ebpf/aya-ebpf/src/programs/tracepoint.rs "Aya eBPF TracePointContext source"
[42]: https://raw.githubusercontent.com/aya-rs/aya/main/ebpf/aya-ebpf/src/maps/per_cpu_array.rs "Aya eBPF PerCpuArray source"
[43]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/maps/array/per_cpu_array.rs "Aya userspace PerCpuArray source"
[44]: https://raw.githubusercontent.com/aya-rs/aya/main/aya-ebpf-macros/src/tracepoint.rs "Aya tracepoint macro source"
[45]: https://raw.githubusercontent.com/aya-rs/aya/main/Cargo.toml "Aya workspace manifest"
[46]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/Cargo.toml "Aya crate manifest"
[47]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/tests/bpf.nix "NixOS BPF integration test"
[48]: https://systemd.io/API_FILE_SYSTEMS/ "systemd API File Systems"
[49]: https://docs.kernel.org/trace/tracepoint-analysis.html "Notes on Analysing Behaviour Using Events and Tracepoints"
[50]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7)"
[51]: https://doc.rust-lang.org/reference/attributes.html "The Rust Reference: Attributes"
[52]: https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html "systemd.mount"
[53]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/sysfs_btf.c "Linux kernel vmlinux BTF sysfs implementation"
[54]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/trace/trace.c "Linux tracefs implementation"
[55]: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h "Linux BPF userspace API header"
[56]: https://docs.rs/aya-build/latest/aya_build/ "Aya build crate API"
[57]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/os-specific/linux/kernel/generic.nix "Nixpkgs generic Linux kernel builder"
[58]: https://wiki.nixos.org/wiki/Linux_kernel "NixOS Wiki: Linux kernel"
[59]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/system/boot/systemd.nix "NixOS systemd boot module"
[60]: https://docs.rs/aya-ebpf/latest/aya_ebpf/ "Aya eBPF crate documentation"
[61]: https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.tracepoint.html "Aya tracepoint attribute macro documentation"
[62]: https://api.github.com/repos/NixOS/nixpkgs/contents/pkgs/by-name/bp?ref=master "Nixpkgs BPF package directory listing"
[63]: https://raw.githubusercontent.com/systemd/systemd/main/src/shared/mount-setup.c "systemd API filesystem setup source"
[64]: https://raw.githubusercontent.com/systemd/systemd/main/units/sys-kernel-tracing.mount "systemd tracefs mount unit source"

*Author: Providence Salumu*
