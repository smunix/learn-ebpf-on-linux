# Linux Kernel Internals for eBPF: Defensive Hook Selection and Portable Design

**Research dossier for an advanced, beginner-accessible Linux eBPF book**
**Scope:** syscall entry; tasks and credentials; VFS; scheduler; memory management and page faults; networking; XDP; cgroup socket hooks; safe hook choices.
**Research snapshot:** 10 September 2026. The rendered kernel documentation consulted identifies itself as **Linux 7.3.0-rc2**; several source citations are the then-current `master` branch. A `master` source observation is evidence of current direction, **not** a released-kernel compatibility promise.

## Executive conclusion

eBPF is safest when it observes or enforces at the **highest-level, explicitly typed hook that expresses the policy**. For observability, start with a locally inspected tracepoint event rather than a kprobe or a private structure walk. For per-workload network policy, start with a cgroup v2 socket-address hook when the decision is about `connect`, `bind`, or UDP peer addressing; use cgroup SKB only when the decision genuinely requires packet contents. Use XDP only for simple, early **ingress** packet decisions whose failure mode has been rehearsed, because it runs before the ordinary networking stack and can discard traffic at very high rate. [1] [11] [12]

The kernel verifier establishes memory safety and termination properties for the bytecode. It does **not** establish that an attach point is a stable interface, that an observed field has a stable business meaning, that an enforcement default is operationally safe, or that Rust code has avoided undefined behavior before it becomes bytecode. Those are the book reader’s engineering responsibilities. [2] [3] [16] [17]

> **Book rule:** Treat BPF program type, context, helper set, return convention, attach mode, kernel configuration, network-driver support, and target architecture as one compatibility unit. Do not copy a helper call or a return value from a different program type.

## 1. What is invariant, and what is only a current implementation detail?

The eBPF instruction set, calling convention, helper signatures, recognized return codes, and program arguments form a BPF ABI. A program may call only helpers or kfuncs made available to its program type; it cannot make arbitrary kernel calls or directly read or write arbitrary kernel memory. The verifier tracks pointer provenance, bounds, alignment, initialized stack contents, and every reachable control-flow path. These are useful **invariants to teach first**. [2] [3]

By contrast, a kernel C symbol, a kprobe location, a tracepoint’s fields, a `task_struct` layout, a `struct file` layout, a scheduler data structure, and the exact page-fault call chain are kernel implementation details. The kernel BPF design FAQ is explicit that tracepoints and kprobe attachment locations are not a stable ABI. The current UAPI header repeats that tracing-program interfaces may break as internal structures change. [3] [29]

| Category | Teach as | Why it matters to eBPF | Engineering response |
|---|---|---|---|
| BPF instructions, verifier typing, helper prototypes, defined return codes | ABI-level contract, subject to program type and kernel support | The verifier uses this information to prove safety. | Use documented helpers and legal returns only. Record the required feature or minimum kernel in release metadata. |
| `struct xdp_md`, `struct bpf_sock_addr`, map UAPI layouts | UAPI structures with documented access rules | They are the intended context contracts for XDP and cgroup socket-address code. | Read only documented fields and respect byte order and writable-field constraints. [29] |
| `task_struct`, `cred`, `mm_struct`, `file`, `dentry`, `inode`, `sk_buff`, scheduler run queues | Internal structures | Layout and locking vary with release, architecture, and Kconfig. | Prefer event fields/helpers. If a structure field is indispensable, use BTF/CO-RE-style relocation where the toolchain supports it, test each target, and have a graceful no-feature path. [20] [21] |
| Tracepoint name and record format | Locally discoverable interface, **not** a formal stable ABI | An event might be absent, renamed, or reshaped by kernel/configuration. | Discover `/sys/kernel/tracing/available_events`; inspect that target’s `format` file; treat its offsets as target data. [22] |
| kprobes/fentry on named kernel functions; kfuncs | Version-specific instrumentation | Names, linkage, prototype, BTF availability, and semantics may change. Kfuncs have explicitly non-stable lifecycle expectations. | Do not make these the book’s first portable design. Gate and test them; offer a tracepoint or no-op fallback. [3] |

### BTF and CO-RE are adaptation mechanisms, not a stability guarantee

BTF describes types. A BTF-aware loader can use the running kernel’s `/sys/kernel/btf/vmlinux` data to match recorded type/field information and relocate an access at load time. CO-RE relocation kinds include field offset, field existence, type existence and size, and enum-value existence/value. That makes many **layout shifts** survivable. It does not promise a field still means the same thing, a tracepoint or function still exists, the target exports BTF, a helper is allowed for the chosen program type, or a kfunc remains available. [20] [21]

For a book example that correlates a current task with a parent task, the right sentence is: “On BTF-equipped targets, a CO-RE-aware loader can relocate a read such as `task->parent`; still feature-test the target and treat the result as a sampling observation.” It is not: “`task_struct::parent` is a stable eBPF API.” [20]

## 2. A kernel mental model for choosing the hook

A system call begins at an architecture-specific user-to-kernel entry boundary, carries a register frame, and ultimately dispatches a kernel implementation. Current common source creates `raw_syscalls:sys_enter` and `raw_syscalls:sys_exit` trace records using `syscall_get_nr()` and `syscall_get_arguments()`. The current event definition records a syscall number and six `unsigned long` arguments on entry, and a number plus `long` return value on exit. It is useful for broad accounting, but the meaning of argument slots is syscall- and ABI-specific, and 32-bit compatibility tasks make naïve `u64` interpretation especially risky. [23] [34] [29]

A scheduled entity is represented by a `task_struct`. Current source shows familiar fields such as `pid`, `tgid`, `comm`, `mm`, `active_mm`, `real_cred`, and `cred`; it also shows that many members are conditional on Kconfig and have concurrency annotations such as `__rcu`. The same source identifies scheduler bits as serialized by scheduler locks. Therefore, field presence is not proof that arbitrary BPF code may safely dereference the field or that its location/meaning is portable. For stable event correlation, use `bpf_get_current_pid_tgid()`—whose returned layout is `tgid << 32 | pid`—and record an event-time `comm` with `bpf_get_current_comm()` instead of exporting task pointers. [35] [26]

A pathname operation enters the Virtual File System (VFS), which resolves name components through the dentry cache and then inodes. A dentry is a cached directory-entry view, often points at an inode, and multiple dentries may point at one inode because hard links exist. The VFS documentation also notes RCU-walk and ref-walk behavior: some dentry operations may occur in RCU-walk mode where sleeping is prohibited and fields can change. This explains why a syscall’s user pathname, a final dentry, a mount namespace path, and an inode identity should not be presented as interchangeable facts. [6]

The scheduler selects tasks subject to policy and run queue state. The current CFS documentation describes virtual runtime and a time-ordered rbtree, but also says CFS is making room for EEVDF. That is a strong signal not to teach CFS internals as a generic scheduler ABI. The `sched_switch` trace event already records the previous and next command names, PIDs, priorities, and previous state; `sched_waking` records wakeup data. These events are preferable to walking current run queues for latency telemetry, after local event-format validation. [7] [24]

Virtual memory maps a task’s virtual address space to physical frames through architecture-dependent page tables. The software hierarchy currently names PGD/P4D/PUD/PMD/PTE, but lower levels may be folded and page size/levels are architecture dependent. An MMU fault can be a normal consequence of demand allocation, copy-on-write, or swap, not an error. Current documentation gives the common high-level route through `handle_mm_fault()` and likely `__handle_mm_fault()`, while explicitly noting architecture-dependent early handling. The current `exceptions:page_fault_user` and `page_fault_kernel` definitions record address, instruction pointer, and error code, but their availability is architecture/configuration dependent. A fault count should be described as “observed fault events,” never as a direct measure of disk I/O or application failure. [8] [25]

On receive, packet processing begins at a NIC queue/driver and can later involve NAPI, SKBs, RPS, RFS, routing, protocol processing, and sockets. RPS is deliberately later than hardware RSS: it queues work for protocol processing above the interrupt handler. XDP is earlier still: in native mode it runs in the driver receive path before ordinary network-stack allocation. That placement explains both its performance and why XDP has neither a general `struct sk_buff` nor a reliable owning process/socket for every frame. [11] [32]

## 3. System-call, task, credential, VFS, scheduler, and MM designs

### 3.1 Syscall entry: measure intent, then pair with an outcome

For an observability chapter, use a syscall tracepoint to record a narrowly scoped intent and an exit tracepoint to record result. A design keyed by `{tgid, pid, syscall-id}` can store an entry timestamp in a bounded map and compute duration at exit. It must clean up on all exits and tolerate missed events, PID reuse, nested syscalls, and tasks that exit before a paired record is processed. For a reader’s first implementation, start with an aggregate counter or histogram rather than a per-syscall state map.

Use specific `syscalls:sys_enter_<name>` events only after reading the local `format` file. The Aya tracepoint example reads the target’s `sys_enter_execve` format and attaches with `TracePoint::attach("syscalls", "sys_enter_execve")`; this illustrates an important workflow, but its hard-coded offset is a **host-specific example**, not a book-wide constant. Aya describes tracepoints as “stable” relative to dynamic probes, whereas kernel documentation explicitly declines to make tracepoints part of the stable ABI. The careful formulation is “static, discoverable, and generally less coupled than an arbitrary kprobe; still validate the event and its format on every target.” [10] [22] [3]

A raw `sys_enter` record contains machine-width argument slots, not a typed Rust function signature. Decode an argument only after checking the syscall number and target ABI. A user pointer remains untrusted. In a tracing program, `bpf_probe_read_user_str()` can attempt a bounded NUL-terminated copy and returns the number of bytes written including NUL on success; handle a negative result and truncate deliberately. Avoid event-time allocation and do not copy unbounded command lines or environment strings. [26]

### 3.2 Tasks and credentials: take an event snapshot, not a live identity oracle

Credentials in Linux are reference-counted `struct cred` objects referenced by `task_struct`. Once committed, credentials are effectively immutable except for reference-count/keyring-related exceptions; changing credentials follows copy-and-replace under RCU. The credentials documentation distinguishes a task’s real/effective/FS identities and explains that an open file carries the opener’s `f_cred`. This is a useful security model: “the UID of the task currently executing” is not necessarily the credential context used for a subsequent operation through an already opened file. [5]

For defensive telemetry, capture stable scalar identifiers at the hook: PID/TGID, UID/GID, cgroup ID when relevant, command name, and a monotonic timestamp. Mark them as **event-time attribution**. Do not retain a raw `task_struct *`, `cred *`, `file *`, or dentry pointer in a map for later dereference. Pointers can be invalid after the hook, and credentials can be replaced. If a policy needs a durable principal, define the principal in user space—such as a service cgroup plus effective UID—not as an assumed task-structure relationship.

### 3.3 VFS: separate request strings, resolved objects, and authority

A safe beginner design for file activity is an **audit-style observer**, not an in-kernel pathname resolver. At syscall entry, record a bounded, explicitly labeled request string only when a target-specific event/context exposes a user pointer. At syscall exit, record the result. In user space, enrich only with data that is still meaningful for the workload and namespace. Explain that a requested string can contain `..`, symlinks, relative paths, bind mounts, overlay filesystems, or paths invalidated before later lookup; a successful `open` names an object through VFS resolution, not necessarily the string the caller supplied.

For authorization or mediation, do not propose “block `openat` by kprobe” as a baseline. The VFS path walk, file-open credential snapshot, LSM decisions, and filesystem semantics are richer than a syscall argument. If a later chapter covers enforcement, it should use an intentionally selected supported policy interface, be explicit about scope, begin in observe-only mode, and retain a tested rollback path. [5] [6]

### 3.4 Scheduler and page faults: use generated event facts, not private queues or page tables

A robust scheduler-latency example joins `sched_waking` to `sched_switch` by PID and measures elapsed time with a monotonic kernel clock. It must call the result “wakeup-to-observed-run latency,” not total application latency. `sched_waking` is called in waking context; `sched_wakeup` is not always called in waking context. Use that distinction to select a precise definition and document the possibility of dropped/lost telemetry. [24]

A page-fault example should count or histogram the locally available `exceptions:page_fault_user` events by PID/TGID and error-code category, with sampling/rate limits. It must not dereference the reported address, infer a physical address, or equate each fault with a major fault, storage access, or SIGSEGV. The page-table and fault flow are architecture-specific; page-table levels can be folded, and a user fault can be part of ordinary lazy allocation or copy-on-write. [8] [25]

## 4. Networking hook choice, from policy intent to packet mechanics

| Question to answer | Safest first hook | Context and what it can know | Do **not** claim | Escalate only if |
|---|---|---|---|---|
| “Which program asked to open a TCP connection?” | cgroup socket-address `connect4`/`connect6` | Address, port, family/type/protocol, selected writable address fields, socket cookie; cgroup scope | That a hostname is visible after DNS resolution, or that this governs packets from other scopes | The decision depends on packet payload or post-routing facts. [1] [29] |
| “May this workload bind a listener?” | cgroup socket-address `bind4`/`bind6` | Request-time local address/port and socket properties | That a later accepted connection is individually identified | A connection-level policy is required. [1] [29] |
| “May a cgroup’s traffic reach a destination IP?” | cgroup SKB egress | `SkBuffContext` / packet data associated with the cgroup | That it sees an application’s original hostname or every networking context identically | L2 early ingress performance is required. [12] |
| “What enters this interface at line rate?” | XDP in `Skb` test mode first | Raw ingress frame range `[data, data_end)`, ingress ifindex/queue; no general SKB | That it covers egress, every NIC mode, or has socket/process ownership | A simple L2/L3 decision has been tested under load and an explicit fallback is acceptable. [11] [29] |
| “Why did this task run late?” | `sched_waking` + `sched_switch` tracepoints | Trace-record fields | That scheduler internals or every state transition are captured | A target-pinned deep diagnosis needs a version-specific probe. [22] [24] |
| “How did this syscall return?” | `raw_syscalls:sys_enter` + `sys_exit`, or a locally validated specific syscall tracepoint | Number/arguments/return record | That six slots are a portable typed signature | A target-pinned function-level diagnosis is justified. [23] |

### 4.1 XDP: ingress, early, deliberately simple

The UAPI defines legal XDP actions as `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, and `XDP_REDIRECT`; unknown XDP return codes are reserved and result in packet drops plus a warning. `struct xdp_md` starts with `data`, `data_end`, `data_meta`, ingress ifindex, RX queue index, and later egress ifindex; documented extensions are appended. `XDP_PASS` lets the frame proceed, `XDP_DROP` discards it, `XDP_TX` sends it back through the receiving NIC, and `XDP_REDIRECT` sends it to an eligible target such as a device or AF_XDP socket. [11] [29]

An XDP program should be small enough that a reviewer can enumerate every outcome. Its safe default for a new observational/deployment exercise is `XDP_PASS`. Add `DROP` only for an explicit, bounded match with a clear owner, expiry/review process, metrics, and a rollback runbook. Never use `XDP_ABORTED` as an ordinary malformed-packet path; it is intended to surface an exception. A map lookup miss, parse failure, unknown EtherType, unknown IP version, IP options, fragments, VLAN complexity, or unavailable feature should normally choose the explicitly documented safe default.

Aya currently presents `XdpMode::{Default, Skb, Driver, Hardware}`. `Xdp::attach(&str, XdpMode)` attaches by interface name; current Aya source first tries a BPF link and falls back to legacy netlink attachment when the link request is unavailable/rejected with `EINVAL`. `XdpMode::Skb` is the portable test mode; native driver and hardware modes require driver/NIC support and may differ in available behavior or performance. Do not promise that `XdpMode::default()` selects a desired mode. Try the mode you require, inspect the result, and expose mode selection in the operator-facing configuration. [11] [30]

AF_XDP is not necessary for an introductory XDP firewall. If used, the design must account for XSKMAP routing: a redirect to a missing or wrongly bound XSK entry is dropped. AF_XDP `Skb` mode is a broadly compatible fallback; driver support can improve performance. Its rings are single-producer/single-consumer, so do not concurrently share a ring without a design that preserves that ownership. [9]

### 4.2 Cgroup socket hooks: scoped, request-time policy

Cgroup BPF attaches to **cgroup v2**. Cgroup v2 has one unified hierarchy, and cgroup membership is inherited by `fork` and preserved across `execve`. This makes a service/container cgroup a better policy boundary than a mutable command name. It also means book instructions must discover the actual cgroup v2 mount rather than assuming `/sys/fs/cgroup/unified`; current Aya examples name both `/sys/fs/cgroup` and `/sys/fs/cgroup/unified` as common locations. [12] [27]

`struct bpf_sock_addr` documents the fields exposed at socket-address hooks. `user_family`, `family`, `type`, and `protocol` are read-only. `user_ip4`, `user_ip6`, and `user_port` have explicitly listed read/write widths and are in **network byte order**. The source current at the research snapshot says the address is the userspace sockaddr intended for use by the socket, depending on attach type. This supports request-time enforcement or controlled address rewrite, but a beginner chapter should initially **inspect and allow/deny**, not rewrite. [29]

Current kernel source describes the socket-address runner as returning `-EPERM` if an attached program was found and its result was not `1`; otherwise it returns zero. Therefore, an allow-list example should return **exactly `1` to allow and `0` to deny** for its tested cgroup socket-address attach point. This rule must not be copied to XDP or TC, whose legal action sets differ. The Aya cgroup-SKB example separately uses `1` to accept and `0` to drop packet traffic, which happens to look similar but is a distinct program contract. [31] [12]

There is a notable current Aya boundary. The kernel’s program-type table includes IPv4/IPv6 and Unix-domain socket-address attach types. The current Aya `#[cgroup_sock_addr(...)]` macro source accepts only `connect4`, `connect6`, `bind4`, `bind6`, `getpeername4`, `getpeername6`, `getsockname4`, `getsockname6`, `sendmsg4`, `sendmsg6`, `recvmsg4`, and `recvmsg6`. Do not teach Unix socket support through that macro without verifying the Aya release in use and supplying an alternative or waiting for support. [1] [15]

### 4.3 Cgroup SKB and the ordinary stack

Cgroup SKB programs see ingress or egress traffic associated with a cgroup and receive `SkBuffContext`. They are a better fit than XDP when the teaching goal is “apply policy to a workload’s network traffic” rather than “protect an interface at the earliest ingress point.” Aya’s current example attaches `CgroupSkb` to a cgroup file with `CgroupSkbAttachType::Egress` and `CgroupAttachMode::Single`. Its packet access model uses context load operations and returns an integer verdict. [12]

When a policy requires ingress and egress after different portions of the stack, state exactly which direction and layer are being governed. The current kernel program-type documentation marks legacy `tc`, `classifier`, and `action` section forms as deprecated in favor of `tcx/*`; this is current-kernel guidance, not a promise that TCX exists on older distribution kernels. Feature-gate it rather than silently replacing an older TC workflow. [1]

## 5. Verifier-first implementation rules

The verifier initially treats `R1` as `PTR_TO_CTX`; it simulates all reachable paths, rejects unread registers, checks pointer types/bounds/alignment, and rejects stack reads before writes. After a helper/kernel function call, `R1`–`R5` are unreadable; `R0` has the helper’s return type and `R6`–`R9` are callee-saved. These are central concepts for Rust eBPF code even though LLVM hides the registers. [2]

| Verifier or safety trap | Typical bad instinct | Defensive pattern |
|---|---|---|
| Map lookup may return NULL | Dereference `map.get()` as if it always succeeds. | Split control flow immediately: `match`/NULL check, then use the non-null branch only. [2] |
| Stack is small and must be initialized | Build large event/string buffers on stack or pass unwritten bytes to a helper. | Keep records compact and fixed-size. Use a per-CPU map buffer for bounded scratch storage when the program type and map semantics support it. Current kernel documentation says the BPF stack limit is 512 bytes. [3] [10] |
| Packet data is a moving bounded range | Parse once, mutate/adjust packet, then reuse prior pointers/bounds proof. | Check each header range before every dereference. Reacquire `data`/`data_end` and re-check after helpers that may change the underlying packet. The UAPI explicitly warns that packet-changing helpers invalidate prior direct-packet-access checks. [2] [29] |
| A pointer is not an integer | Mask, multiply, or freely cast a context/map/packet pointer. | Preserve pointer provenance. Add only verifier-provable bounded offsets where permitted; keep indices scalar and range-check them first. [2] |
| Complex branches multiply verifier state | Encode a protocol parser as deep branching, unbounded dynamic work, or many overlapping predicates. | Parse a small supported subset; use early returns; bound loop trip counts and input lengths; move policy complexity into a map/user space. The only reliable acceptance test is loading on the target kernel. [3] |
| Socket lookup acquires a reference | Exit with a `PTR_TO_SOCKET` on a path where lookup succeeded. | NULL-check, release on every non-null path, and structure cleanup so every exit is visibly balanced. [2] |
| Helper availability is context-specific | Copy a tracing helper into XDP/cgroup code. | Check the helper’s supported program types and load a feature-specific object. Do not substitute arbitrary kernel memory reads for unavailable helper APIs. [2] [26] |
| A legal value has the wrong byte order | Compare a packet/cgroup address to host-order map keys. | State map key byte order in the ABI. Convert exactly once at a defined boundary; use network order for packet/UAPI fields where documented. [11] [29] |
| Telemetry can be lost | Treat perf/ring-buffer loss as “no event occurred.” | Count loss and expose it. Design all state correlation to tolerate unmatched entry/exit events. [12] |

### Rust-specific caution: verifier approval is not a Rust safety proof

A raw `*const T` or `*mut T` may be null, out of bounds, or unaligned. Rust requires a raw-pointer load/store to be valid for the access and aligned; `slice::from_raw_parts` further requires non-null, aligned, initialized consecutive `T` objects within one allocation, a nonwrapping length, and no conflicting mutation for the returned lifetime. An XDP buffer is not automatically a valid Rust `&T` or `&[T]` just because the BPF verifier approved a packet range check. [16] [17]

The Aya XDP tutorial demonstrates a bounds-checking `ptr_at<T>` pattern and then returns `&*ptr`. Treat it as a teaching sketch that requires an additional Rust-layout audit. Ethernet and IP headers may not satisfy `T` alignment, and creating a reference asserts alignment and validity. Prefer a helper that returns a raw byte pointer after a verifier-visible bounds check. Decode bytes explicitly, or use a representation and access strategy that is demonstrably compatible with unaligned packet data. Keep the unsafe block narrow and document both proofs: (1) BPF range proof against `data_end`, and (2) Rust alignment/layout/aliasing proof. [11] [16]

A conservative parser shape is:

```rust
// Illustration only: compile and load-test it on the exact target/toolchain.
#[inline(always)]
fn packet_bytes_at(ctx: &XdpContext, off: usize, need: usize) -> Result<*const u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start > end {
        return Err(());
    }
    let available = end - start;
    if off > available || need > available - off {
        return Err(());
    }
    // The preceding checks establish start + off <= end for this packet range.
    Ok((start + off) as *const u8)
}
```

This code intentionally returns `*const u8`, not `&T` or a fabricated slice. It still needs a target load test because compiler code generation and verifier recognition are part of the compatibility unit. Define BPF-to-user events as `#[repr(C)]` fixed-width scalar fields and byte arrays. Avoid Rust references, `String`, `Vec`, `bool` when an exact wire representation matters, pointers, and non-`repr(C)` enums in map/event values.

## 6. Current Aya API notes and version boundaries

The maintained Aya source exports `Ebpf`, `TracePoint`, `Xdp`, `CgroupSkb`, `CgroupSockAddr`, their attach-type enums, `CgroupAttachMode`, and link abstractions. The basic loader sequence is `Ebpf::load` or `Ebpf::load_file`, obtain a mutable named program with `program_mut`, convert it to the concrete program type, call `load()`, then call the program-specific `attach()`. Current Aya book material explicitly says the old `aya::Bpf` name is deprecated since Aya 0.13.0 in favor of `aya::Ebpf`; avoid copying older snippets unchanged. [14] [11]

| Program | Current Aya loader shape | Important caveat |
|---|---|---|
| Tracepoint | `let p: &mut TracePoint = ebpf.program_mut("name")?.try_into()?; p.load()?; p.attach("syscalls", "sys_enter_execve")?;` | Category/name must exist in target tracefs. Inspect target format before decoding. [10] [14] |
| XDP | `let p: &mut Xdp = ...; p.load()?; p.attach("eth0", XdpMode::Skb)?;` | `XdpMode` currently has `Default`, `Skb`, `Driver`, and `Hardware`. Aya documents XDP minimum kernel 4.8, but a particular action/helper/mode can require more. [30] |
| Cgroup SKB | `p.load()?; p.attach(File::open(cgroup_path)?, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)?;` | Cgroup v2 scope; return semantics belong to this program type, not XDP. [12] [14] |
| Cgroup socket address | Encode the attach type in `#[cgroup_sock_addr(connect4)]`; then `p.load()?; p.attach(File::open(cgroup_path)?, CgroupAttachMode::Single)?;` | Current Aya source says this program type needs kernel 4.17. It uses BPF links from 5.7 and legacy `BPF_PROG_ATTACH` below that. The macro’s accepted attach types are narrower than the latest kernel table. [15] [38] |

Aya links are RAII-managed. The book lifecycle page says attachment lasts until its parent BPF object is dropped; the maintained source says `Xdp::from_pin` does not unload a program if it remains pinned. For defensive examples, keep the `Ebpf` owner alive for the explicit intended lifetime, retain returned link IDs where the API exposes them, detach during orderly shutdown, and make all attachment ownership observable. Do not make persistent pinning the default deployment lesson. [13] [30]

## 7. Portability and operations checklist

A distribution kernel is not equivalent to an upstream version number. It may backport features, disable a Kconfig option, omit BTF, alter a driver’s XDP support, restrict privileges, or run in a container without access to the host’s tracefs/cgroup hierarchy. Preflight every feature on the **running target**, then select a known-safe reduced mode if it is absent.

| Check before attach | Reason | Safe response when absent or different |
|---|---|---|
| `/sys/kernel/tracing/available_events` and the event’s `format` | Event names, IDs, offsets, and fields are target facts. [22] | Disable that collector or use a separately validated alternative; do not guess offsets. |
| `/sys/kernel/btf/vmlinux` and loader CO-RE support | BTF enables type matching/relocation but is not universal. [20] | Use an event/helper-only variant or decline the feature with a clear diagnostic. |
| cgroup v2 mount and delegated target cgroup | Cgroup BPF scope is v2; the unified hierarchy may be mounted at a different path. [12] [27] | Refuse to enforce rather than attach at an unintended scope. |
| Required capability, LSM/container policy, and mount permissions | `CAP_BPF` was added in Linux 5.8 to split privileged BPF operations from `CAP_SYS_ADMIN`; network attachment may require additional network authority. [18] [4] | Grant the least privileges for the exact operation, log the failure, and avoid automatic privilege escalation. |
| Kernel config and actual helper/program-type support | The verifier accepts only what this kernel exposes for this context. [2] [3] | Feature-probe/load-test a small program; select a reduced object. |
| NIC and XDP mode capability | Generic, driver, and hardware modes differ. Redirect targets/AF_XDP also need correct binding. [9] [11] | Start in `Skb`; make driver/hardware an explicit opt-in and monitor mode/action counters. |
| Architecture and process ABI | Syscall numbers/argument widths and page-fault implementation differ. [8] [23] | Bundle or generate ABI-aware decoders; never hard-code an x86-64 syscall table as universal. |
| Record layout from BPF to user space | Rust ABI/layout assumptions can corrupt telemetry even when BPF loads. [16] [17] | Use versioned `repr(C)` fixed-width records; reject size/version mismatch. |

NixOS is useful for reproducibility, not for pretending that all host kernels are identical. Its `boot.kernelPackages` option overrides the kernel **and kernel-coupled packages**, while the manual warns that NixOS retains actively maintained kernels and a pinned non-longterm package can disappear when upstream maintenance ends. Pin the Nixpkgs input or package set used to build/test a release, record `uname -r`, kernel config and BTF availability in test artifacts, and test the installed kernel rather than only the build host. `boot.kernelPatches` supports declared patches/configuration and `boot.kernelParams` adds kernel command-line parameters; any BPF-dependent Kconfig change should be reviewed as a kernel build change, not slipped into application configuration. [19] [28]

## 8. A defensible sample chapter sequence

1. **Observe a local tracepoint.** List one event from tracefs, read its format, attach an Aya `TracePoint`, and export only PID/TGID, timestamp, and a fixed event code. The goal is the full lifecycle and a visible verifier log, not parsing every field. [10] [22]

2. **Pair syscall entry/exit conservatively.** Instrument a single target-specific syscall tracepoint or raw syscall number, handle a bounded user string only where appropriate, and show unmatched-event/loss counters. Explain user pointers and ABI dependence. [23] [26]

3. **Measure scheduler wakeup-to-run delay.** Use `sched_waking` and `sched_switch`, record a histogram, and discuss what the metric excludes. Do not read a run queue or explain fields in `sched_entity` as portable. [24] [7]

4. **Observe user page faults.** Attach only when `exceptions:page_fault_user` exists locally. Publish counts and error-code categories, then explain demand paging/COW before interpreting any spike. [8] [25]

5. **Enforce a cgroup-scoped connection allow list in dry-run mode.** Start at `connect4/connect6` with a read-only decision and metrics. Flip enforcement only after an operator confirms the service cgroup, exception paths, DNS/proxy behavior, and rollback. Use `1`/`0` only for the tested cgroup socket-address program. [29] [31]

6. **Build an XDP parser that passes by default.** Validate Ethernet and a minimal IPv4 subset with repeated range checks; emit sampled counters only. First attach in `XdpMode::Skb`, then test native mode separately. Add a controlled `DROP` example only on an isolated interface with a tested detach/restore procedure. [11] [30]

Every sample should include an explicit scope, legal return values, accepted input subset, unknown-input default, performance budget, privilege needs, feature probes, counters for parse/error/loss, and a detach/rollback instruction. This makes the reader practice defensive engineering rather than merely make bytecode load.

## 9. Claims that require cautious wording in the book

| Avoid this sentence | Prefer this sentence |
|---|---|
| “Tracepoints are stable.” | “Tracepoints are static and locally discoverable, often less coupled than arbitrary kprobes; kernel documentation does not treat their names/formats as a stable ABI.” [3] [10] |
| “A `task_struct` has these fields.” | “The target kernel’s BTF/source currently describes these fields; they are internal and configuration-dependent.” [20] [24] |
| “A page fault means disk I/O/the app crashed.” | “A page fault can be routine demand allocation, copy-on-write, swap-related activity, or an invalid access; correlate before assigning cause.” [8] |
| “XDP is a firewall.” | “XDP is an early ingress packet hook. A policy program can drop/pass/redirect frames, but must account for driver mode, parsing limits, and outage risk.” [11] [29] |
| “XDP is always zero-copy/fastest.” | “Native/hardware modes can reduce overhead when supported; generic XDP is a compatibility/test path, and AF_XDP behavior depends on mode, driver, and ring ownership.” [9] [11] |
| “A cgroup hook sees a container.” | “It sees activity scoped by a cgroup v2 attachment. The deployment must establish that the intended service/container processes are in that cgroup.” [12] [27] |
| “CO-RE means compile once, run everywhere.” | “CO-RE can relocate supported type/field accesses using target BTF; it does not create missing hooks/helpers/BTF or stabilize semantics.” [20] [21] |
| “The verifier makes Rust packet parsing safe.” | “The verifier proves BPF memory access constraints; Rust still requires valid alignment, layout, lifetimes, and aliasing for references/slices.” [2] [16] [17] |
| “Return zero to allow.” | “Use the return convention documented for the **specific program type and attach type**. For the current cgroup socket-address runner, `1` allows and a non-`1` result is denied; XDP uses `enum xdp_action`.” [29] [31] |
| “CAP_BPF is all that is needed.” | “Privileges depend on the operation, kernel version, namespace/LSM policy, and network attachment. Request the least capabilities and test the real deployment.” [18] [4] |

## Source inventory and evidence notes

The following are **all sources actually read for this dossier**. URLs are intentionally retained as sources of record. The first group is authoritative kernel/UAPI/man-page material; Aya, Rust, and NixOS sources are maintained project documentation/source used for API and deployment details. Search result snippets were not used as evidence.

| ID | Source read | Authority and use |
|---|---|---|
| [1] | Linux kernel, *Program Types and ELF Sections* | Current program/attach-type table and deprecation note for legacy TC sections. |
| [2] | Linux kernel, *eBPF verifier* | Pointer types, register/stack model, null/reference and packet-bounds examples. |
| [3] | Linux kernel, *BPF Design Q&A* | ABI versus internal interface, verifier/stack limits, kfunc and portability caveats. |
| [4] | `bpf(2)` | BPF syscall operation, verifier/load errors, historical privilege notes. |
| [5] | Linux kernel, *Credentials in Linux* | `cred` immutability/RCU, current/other-task access, file opener credentials. |
| [6] | Linux kernel, *Overview of the Linux Virtual File System* | Dentry/inode/path lookup and RCU-walk behavior. |
| [7] | Linux kernel, *CFS Scheduler* | CFS concepts and EEVDF transition caution. |
| [8] | Linux kernel, *Page Tables* | MMU/page-fault model, arch dependence, `handle_mm_fault` route. |
| [9] | Linux kernel, *AF_XDP* | XSKMAP routing, generic/driver modes, ring ownership, need-wakeup. |
| [10] | Aya book, *Tracepoints* | Aya tracepoint macro/context and contemporary loader example. |
| [11] | Aya book, *XDP* | XDP placement/actions/modes and current `Ebpf`/`XdpMode` example. |
| [12] | Aya book, *Cgroup SKB* | Cgroup v2 scope, `SkBuffContext`, Aya attach/verdict example. |
| [13] | Aya book, *Program Lifecycle* | Owner lifetime and attachment teardown explanation; checked alongside current source because naming is dated. |
| [14] | Aya source, `aya/src/programs/mod.rs` | Current public program exports and `Ebpf` load/attach model. |
| [15] | Aya source, `aya-ebpf-macros/src/cgroup_sock_addr.rs` | Exact accepted macro attach-type names and generated sections. |
| [16] | Rust standard library, primitive `pointer` | Raw-pointer validity/alignment and reference/slice caveats. |
| [17] | Rust standard library, `slice::from_raw_parts` | Exact slice validity, allocation, initialization, lifetime/aliasing requirements. |
| [18] | `capabilities(7)` | `CAP_BPF` introduction in Linux 5.8 and network-capability context. |
| [19] | Nixpkgs, `nixos/modules/system/boot/kernel.nix` | `boot.kernelPackages`, kernel patch/config and parameter option semantics. |
| [20] | Linux kernel, *libbpf Overview* | BTF at `/sys/kernel/btf/vmlinux`, CO-RE field relocation purpose and limits. |
| [21] | Linux kernel, *BPF LLVM Relocations* | Exact CO-RE relocation kinds and load-time patching. |
| [22] | Linux kernel, *Event Tracing* | Tracefs discovery and per-event format record layout. |
| [23] | Linux current source, `kernel/entry/syscall-common.c` | Current raw syscall trace generation. |
| [24] | Linux current source, `include/trace/events/sched.h` | Current scheduler event facts. |
| [25] | Linux current source, `include/trace/events/exceptions.h` | Current page-fault tracepoint record definition. |
| [26] | `bpf-helpers(7)` | Current-task helper layouts and safe bounded user-string helper semantics. |
| [27] | `cgroups(7)` | cgroup v2 unified hierarchy and membership inheritance/`execve` behavior. |
| [28] | NixOS manual, *Linux Kernel* | Kernel package selection and maintained-kernel lifecycle. |
| [29] | Linux current UAPI source, `include/uapi/linux/bpf.h` | Program/attach enums, `bpf_sock_addr`, XDP UAPI, helper caveats. |
| [30] | Aya current source, `xdp.rs` | Exact XDP modes and attach fallback behavior. |
| [31] | Linux current source, `kernel/bpf/cgroup.c` | Current cgroup socket-address executor and non-`1` deny behavior. |
| [32] | Linux kernel, *Scaling in the Linux Networking Stack* | RSS/RPS/RFS receive-path placement. |
| [33] | Linux kernel, *BPF Type Format (BTF)* | BTF/split-BTF context and compatibility limits. |
| [34] | Linux current source, `include/trace/events/syscalls.h` | Current raw syscall entry/exit trace record fields. |
| [35] | Linux current source, `include/linux/sched.h` | Current `task_struct` fields, configuration conditionals, and concurrency annotations. |
| [36] | Aya book, *Cgroups* | Read for completeness; it is explicitly a work in progress and supplies no additional normative API detail. |
| [37] | NixOS options search, `boot.kernelPackages` | Read as the official option-index endpoint; client-side rendering exposed no option content, so the Nixpkgs source and NixOS manual are the evidence used here. |
| [38] | Aya current source, `cgroup_sock_addr.rs` | Cgroup socket-address minimum version and BPF-link versus legacy-attach behavior. |
| [39] | Linux current source, `net/core/filter.c` | Read for XDP redirect and invalid-action implementation context; UAPI and kernel documentation remain the normative citations. |
| [40] | Aya current source, `trace_point.rs` | Directly read to verify `TracePoint::load` and `TracePoint::attach(category, name)` signatures. |
| [41] | Aya current source, `cgroup_skb.rs` | Directly read to verify `CgroupSkb::load` and cgroup attachment API shape. |

## References

[1]: https://docs.kernel.org/bpf/libbpf/program_types.html "Program Types and ELF Sections — Linux Kernel documentation"
[2]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier — Linux Kernel documentation"
[3]: https://docs.kernel.org/bpf/bpf_design_QA.html "BPF Design Q&A — Linux Kernel documentation"
[4]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — Linux manual page"
[5]: https://docs.kernel.org/security/credentials.html "Credentials in Linux — Linux Kernel documentation"
[6]: https://docs.kernel.org/filesystems/vfs.html "Overview of the Linux Virtual File System — Linux Kernel documentation"
[7]: https://docs.kernel.org/scheduler/sched-design-CFS.html "CFS Scheduler — Linux Kernel documentation"
[8]: https://docs.kernel.org/mm/page_tables.html "Page Tables — Linux Kernel documentation"
[9]: https://docs.kernel.org/networking/af_xdp.html "AF_XDP — Linux Kernel documentation"
[10]: https://aya-rs.dev/book/programs/tracepoints.html "Tracepoints — Building eBPF Programs with Aya"
[11]: https://aya-rs.dev/book/programs/xdp.html "XDP — Building eBPF Programs with Aya"
[12]: https://aya-rs.dev/book/programs/cgroup-skb.html "Cgroup SKB — Building eBPF Programs with Aya"
[13]: https://aya-rs.dev/book/aya/lifecycle.html "Program Lifecycle — Building eBPF Programs with Aya"
[14]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/mod.rs "Aya program-type exports and load/attach lifecycle source"
[15]: https://github.com/aya-rs/aya/blob/main/aya-ebpf-macros/src/cgroup_sock_addr.rs "Aya cgroup_sock_addr procedural macro source"
[16]: https://doc.rust-lang.org/std/primitive.pointer.html "pointer — Rust standard library documentation"
[17]: https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html "std::slice::from_raw_parts — Rust standard library documentation"
[18]: https://man7.org/linux/man-pages/man7/capabilities.7.html "capabilities(7) — Linux manual page"
[19]: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/system/boot/kernel.nix "Nixpkgs NixOS boot kernel module source"
[20]: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html "libbpf Overview — Linux Kernel documentation"
[21]: https://docs.kernel.org/bpf/llvm_reloc.html "BPF LLVM Relocations — Linux Kernel documentation"
[22]: https://docs.kernel.org/trace/events.html "Event Tracing — Linux Kernel documentation"
[23]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/entry/syscall-common.c "Linux current syscall common entry source"
[24]: https://raw.githubusercontent.com/torvalds/linux/master/include/trace/events/sched.h "Linux current scheduler trace-event source"
[25]: https://raw.githubusercontent.com/torvalds/linux/master/include/trace/events/exceptions.h "Linux current exceptions trace-event source"
[26]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) — Linux manual page"
[27]: https://man7.org/linux/man-pages/man7/cgroups.7.html "cgroups(7) — Linux manual page"
[28]: https://nixos.org/manual/nixos/unstable/#sec-boot "NixOS Manual: Linux Kernel"
[29]: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h "Linux current BPF UAPI header"
[30]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/xdp.rs "Aya XDP program source"
[31]: https://github.com/torvalds/linux/blob/master/kernel/bpf/cgroup.c "Linux current cgroup BPF source"
[32]: https://docs.kernel.org/networking/scaling.html "Scaling in the Linux Networking Stack — Linux Kernel documentation"
[33]: https://docs.kernel.org/bpf/btf.html "BPF Type Format (BTF) — Linux Kernel documentation"
[34]: https://raw.githubusercontent.com/torvalds/linux/master/include/trace/events/syscalls.h "Linux current raw syscall trace-event source"
[35]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/sched.h "Linux current task structure source"
[36]: https://aya-rs.dev/book/programs/cgroups.html "Cgroups — Building eBPF Programs with Aya"
[37]: https://search.nixos.org/options?channel=unstable&show=boot.kernelPackages "NixOS Options: boot.kernelPackages"
[38]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/cgroup_sock_addr.rs "Aya cgroup socket-address program source"
[39]: https://github.com/torvalds/linux/blob/master/net/core/filter.c "Linux current networking BPF filter source"
[40]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/trace_point.rs "Aya tracepoint program source"
[41]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/cgroup_skb.rs "Aya cgroup SKB program source"
