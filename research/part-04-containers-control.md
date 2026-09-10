# Containers and Linux control layers: a defensive eBPF engineering dossier

**Research snapshot:** 10 September 2026
**Intended reader:** an advanced beginner who can read Rust and C-like pseudocode, but needs a reliable model of Linux isolation and eBPF lifecycle boundaries.
**Scope:** namespaces, cgroup v2, container identity, seccomp, Linux capabilities, LSM composition, map concurrency, pinning, tail calls, and safe upgrades. This dossier deliberately addresses **defensive observability and enforcement engineering**. It does not cover stealth, evasion, persistence tactics, or offensive deployment.

## Editorial conclusion

A container is not a single kernel object with one canonical identity. It is a runtime-managed collection of processes whose resource placement, visible paths, credentials, and security policy are each governed by different Linux control layers. An eBPF program therefore should not infer a container from a PID, a cgroup pathname seen inside the container, or a runtime label alone. For a host-side policy or telemetry agent, the most useful kernel join key is usually the task's **current cgroup identifier**, with host-side metadata that records the cgroup's lifecycle and runtime workload identity. Namespace inode pairs are valuable supplementary evidence, not a replacement for cgroup attribution. [1] [2] [3] [15]

The engineering corollary is simple: keep policy decisions small and explicit in the eBPF data plane, keep naming and reconciliation in a privileged but narrow host control plane, and treat every cross-layer assumption as version- and configuration-sensitive. eBPF verifier acceptance does not prove that a rule is semantically correct under cgroup migration, LSM ordering, seccomp stacking, or a rolling upgrade.

> **Book-level thesis:** Use cgroup-backed kernel identity for fast attribution, namespaces for isolation context, and an external control-plane record for human-meaningful workload identity. Version and test the interfaces between those layers.

## 1. A learner's model: four independent control planes

The same event can be subject to several mechanisms. They solve different problems and do not substitute for one another.

| Layer | Primary question | What it does **not** establish | Defensive eBPF consequence |
|---|---|---|---|
| Namespaces | “Which view of a global resource does this task see?” | A resource budget, a runtime container name, or host-wide privilege | Record relevant namespace evidence only when it answers an analysis question; do not use a namespace pathname as an authoritative tenant key. |
| cgroup v2 | “Which hierarchical resource and cgroup-attached-policy domain contains this task now?” | A cryptographic or forever-stable container identity | Attribute an event with a current cgroup ID, then enrich it in user space. |
| Credentials and capabilities | “Which privileged operations may this thread perform in the applicable user namespace?” | Permission to perform every host-wide BPF or kernel operation | Grant only narrowly justified capabilities to the loader; treat root inside a user namespace as distinct from host privilege. |
| seccomp | “Which system-call interfaces may this process invoke?” | A complete information-flow sandbox or an eBPF program policy | Use it to reduce a loader/agent's syscall surface; do not confuse classic seccomp BPF with eBPF maps or helpers. |
| LSMs | “Does an active mandatory-access-control hook permit this operation?” | A fixed global policy order on all machines | Preserve an earlier nonzero LSM-BPF result and inspect the host's active LSM order before relying on audit coverage. |
| BPF maps and links | “What shared state and attachment lifecycle does the BPF application use?” | A transaction across maps, semantic compatibility across releases, or automatic deployment | Design explicit generations, ownership, rollback, and removal paths. |

Namespaces wrap global resources so that tasks in a namespace see an isolated instance. The common types isolate cgroup-root view, IPC, network stack, mount points, PIDs, time offsets, users/groups and hostnames. Linux exposes handles under `/proc/<pid>/ns`; tasks sharing a namespace have the same `st_dev` and `st_ino` for that namespace entry. [2] This is a useful **host-observed equality test**. It is not a friendly container name, and access to those proc links is permission checked. [2]

### Chapter claims to teach explicitly

1. **Isolation is plural.** Explain each layer before showing any eBPF attachment. A container can share a host network namespace, run in a user namespace, and occupy a dynamically changing cgroup path at the same time.
2. **Identity is an observation with a time and scope.** A PID is a process handle in a PID namespace; a cgroup path is a namespace-relative representation; the cgroup ID is a better fast join key, but still needs host/boot/lifecycle context.
3. **Security mechanisms compose conservatively, not magically.** A capability is checked in a relevant user namespace; seccomp filters stack; LSM checks execute in host-selected order; any earlier denial can prevent a later auditing program from seeing a successful operation.
4. **Maps are concurrently shared kernel data structures.** “Map lookup followed by mutation” is not a transaction. Pick a concurrency model for every value type.
5. **An upgrade is a protocol.** Load and verify a new object before activation, use versioned map schemas and guarded link changes where available, and retain a tested rollback path.

## 2. Namespaces and cgroup v2: visibility versus control

### 2.1 Namespace facts that survive explanation

A namespace gives a task a particular view of a resource. It does not by itself limit CPU, memory, processes, or I/O; cgroups provide those hierarchical controls. The namespace API creates namespaces through `clone(2)`/`unshare(2)`, joins an existing namespace with `setns(2)`, and exposes handles in `/proc/<pid>/ns`. A namespace can outlive all member tasks while an nsfs file descriptor or bind mount holds it. [2]

A **cgroup namespace** virtualizes the paths shown through `/proc/<pid>/cgroup` and `/proc/<pid>/mountinfo`. When created, the caller's current cgroups become the namespace's roots. Consequently, the string `/` inside a container can mean a host subtree, and paths outside the reader's cgroup root are rendered with `..` components. [3] The host-relative or in-container cgroup path is therefore a presentation field, not a durable tenant key.

User namespaces need especially careful wording. A process may be UID 0 with a full capability set **inside** a newly created user namespace while having no capabilities in its parent namespace. Privilege obtained in a user namespace affects resources governed by that namespace; operations on non-namespaced host-wide resources still require privilege in the initial user namespace. [4] “Root in a container” is not a synonym for “host root,” and neither phrase alone answers whether a specific BPF action is permitted.

### 2.2 cgroup v2 invariants

cgroup v2 uses hierarchical distribution. A non-root cgroup can enable a domain controller for its children only if its parent has enabled that controller. It also cannot disable a controller while a child still has it enabled. [1] This top-down rule is a strong teaching invariant.

A second invariant is the **no-internal-process constraint** for domain controllers: a non-root domain cgroup may distribute a domain resource to children only when it contains no processes itself. In ordinary domain subtrees, processes belong at leaves. Threaded subtrees are a special mode with different constraints; transitioning a cgroup to `threaded` is one-way, and invalid topology operations can fail with `EOPNOTSUPP`. [1]

Delegation has a narrow meaning. A parent either grants access to a subtree's directory plus `cgroup.procs`, `cgroup.threads`, and `cgroup.subtree_control`, or—when the v2 hierarchy has the system-wide `nsdelegate` mount option—delegates to a newly created cgroup namespace. `nsdelegate` can only be set at mount/remount from the initial namespace and is ignored on non-initial-namespace mounts. [1] Do not teach “write access to `/sys/fs/cgroup`” as safe delegation.

### 2.3 Recommended container attribution record

For each event, emit a compact kernel key. A host control plane then joins it to a time-versioned workload record.

| Field | Produced where | Why it belongs in the model | Required qualification |
|---|---|---|---|
| `cgroup_id: u64` | eBPF, using `bpf_get_current_cgroup_id()` where supported by the chosen program type | Fast attribution to the task's current cgroup; suitable map key and event field | It identifies a current kernel cgroup in this host deployment, not an orchestrator's immutable workload ID. A task can migrate. [15] |
| `event_time` and a control-plane observation time | eBPF and user space | Allows an honest join when cgroup membership changes | Do not enrich an old event with a current cgroup assignment without recording the observation time. |
| host boot identity and host ID | user space | Separates hosts and host lifetimes | Choose and document the host/boot identity source; this is outside the BPF event ABI. |
| namespace `(st_dev, st_ino)` pairs for selected `user`, `pid`, `mnt`, and `net` namespaces | privileged user-space reconciler | Explains which isolation views applied to a process | These are observed handles, may be unavailable due to proc permission checks, and should be collected only where needed. [2] |
| cgroup-v2 host path, ancestry, and runtime workload UID | privileged user space | Makes events understandable and joins to deployment metadata | Paths can be renamed or virtualized. Runtime labels are control-plane data, not kernel truth. [3] |
| schema/generation | eBPF and user space | Keeps old and new event interpretations distinct during an upgrade | It must be carried through storage and tests, not merely documented. |

A cgroup storage UAPI key calls its identifier `cgroup_inode_id`, and current BPF kfuncs expose `bpf_cgroup_from_id()` and `bpf_cgroup_ancestor()` with explicitly reference-counted results. [17] [19] These interfaces support cgroup-centric designs, but they do **not** make a cgroup ID a cross-host, cross-boot, or runtime-independent identifier. Teach the stronger claim only after defining the scope: “unique enough for this host's live cgroup graph and reconciled with lifecycle metadata,” not “globally unique container ID.”

A defensive design emits the ID at the decision point, records a “seen” or creation record from a trusted host observer, and removes the association only after a deliberate lifecycle rule. The BPF fast path should not parse a runtime-specific pathname or depend on a container engine's naming convention.

## 3. Security composition: capabilities, seccomp, and LSMs

### 3.1 Capabilities: narrow privilege, namespace-relative checks

Linux capabilities are per-thread privilege bits, partitioning traditional superuser authority. The effective set is used for permission checks; permitted bounds what can become effective; inheritable participates in `execve`; the bounding set restricts what may be gained across `execve`; and the ambient set, introduced in Linux 4.3, is retained across a nonprivileged `execve` only while it remains both permitted and inheritable. [5]

`CAP_BPF` was introduced in Linux 5.8 to separate privileged BPF operations from the historically overloaded `CAP_SYS_ADMIN`. [5] This is a **historical API boundary, not a portable loader recipe**. Actual permission for loading, attaching, obtaining FDs, tracing, or operating on a target can depend on kernel version, `unprivileged_bpf_disabled`, program type, `CAP_PERFMON`, `CAP_NET_ADMIN`, the relevant user namespace, and an LSM. Build the loader to fail closed with an actionable diagnostic; do not convert a load failure into a request for blanket `CAP_SYS_ADMIN`.

The safe deployment pattern is a small, separately audited loader that obtains exactly the authorities it needs, creates or opens the intended objects, passes narrowly scoped data interfaces to an unprivileged consumer, and then drops privileges. The event consumer should not be able to load arbitrary programs, mutate policy maps, or access a host bpffs tree merely because it can display telemetry.

### 3.2 Seccomp: syscall-surface reduction, not an eBPF policy engine

Seccomp filters are Berkeley Packet Filter programs over system-call metadata—number, architecture, arguments, and related fields. They cannot dereference pointers, which avoids an interposition-style TOCTOU class. The kernel documentation is explicit that syscall filtering reduces exposed kernel surface; it is **not** a complete sandbox or information-flow policy. [6]

Installing `SECCOMP_SET_MODE_FILTER` requires either `no_new_privs` or `CAP_SYS_ADMIN` in the caller's user namespace. Filters are inherited across permitted `fork`/`clone` and preserved across permitted `execve`. Further filters can be layered if the filter allows the installation path. [6] [7] For a multi-threaded loader, `SECCOMP_FILTER_FLAG_TSYNC` attempts to synchronize the filter tree across the process; synchronization can fail if a thread is already in strict mode or has diverged with its own filters. [7]

Several filters may apply to one system call. The result with the highest-action precedence governs, and when actions have equal precedence, the data from the most recently installed filter is used. [6] This is an invariant of seccomp filter stacking, but not an argument to build a policy whose meaning depends on incidental installation order.

**Defensive seccomp guidance for the book:**

- Verify `seccomp_data.arch` before comparing a syscall number. The kernel documentation names omission of the architecture check as the major pitfall on architectures with multiple calling conventions. [6]
- Start a loader or collector in audit/log mode only in a controlled test environment, then maintain an explicit allowlist derived from integration tests. The available return actions can be checked through `SECCOMP_GET_ACTION_AVAIL` or `/proc/sys/kernel/seccomp/actions_avail`; actions and flags have version histories. [6] [7]
- Treat `SECCOMP_RET_USER_NOTIF` as a request/response protocol with cancellation and TOCTOU hazards, not as a universal authorization service. The listener's `pid` can be zero when the target PID namespace is not visible, and user memory consulted by a supervisor must be copied before a policy decision. [6]
- Do not state a universal execution ordering between seccomp and all LSM hooks. Seccomp filters syscalls; LSMs authorize individual kernel-object operations at hook-specific points. The relevant ordering is defined by the kernel path and active host configuration.

### 3.3 LSM ordering and BPF LSM interaction

The Linux Security Module framework is compiled and boot-configured. The LSM documentation says that `/sys/kernel/security/lsm` is a comma-separated list of active modules and reflects the order in which checks are made; it always includes `capability` first, followed by enabled minor modules and the configured major module. [8] The boot-time choice can override build-time selection. Therefore, documentation and startup diagnostics should capture the actual contents of that file rather than assuming an ordering from a distribution name.

Current kernel source shows the key semantic: an integer-returning LSM dispatcher starts with the hook default and stops at the first return value that is not that default. [9] Thus a denial from an earlier component can prevent later hook callbacks from running. A BPF LSM program also receives the prior BPF-LSM return value (or zero for the first BPF program); the kernel LSM-BPF example returns a nonzero prior result unchanged. [11] This is the correct defensive default:

```text
if previous_bpf_lsm_result != 0:
    return previous_bpf_lsm_result
perform local audit/decision only if policy requires it
return 0 for allow, or a documented negative errno for deny
```

This rule preserves a prior BPF-LSM denial. It does **not** promise that the BPF LSM ran before or after another active LSM, nor that it observed every denied operation. Use a separate, appropriate telemetry channel if complete audit coverage is required.

BPF LSM requires a kernel built with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`, and the `bpf` LSM must be enabled in the boot LSM list. Aya's current `Lsm` source documents Linux 5.7 as the minimum and loads against the BTF function named `bpf_lsm_<hook>`. [26] The available hook signatures come from `include/linux/lsm_hook_defs.h`; they are kernel interfaces and must be treated as BTF/CO-RE-sensitive, not as a frozen source ABI. [10]

## 4. Map concurrency: define the consistency contract before choosing a map

BPF maps are shared storage between kernel and user space. Different BPF programs can access the same map in parallel; the kernel does not infer the semantic invariant of a multi-field value or a multi-map update. [13] The question is not merely “which map type is fast?” It is “what value may an observer see while another CPU or the control plane updates it?”

### 4.1 A decision table for defensive designs

| State class | Preferred pattern | What readers may observe | Avoid |
|---|---|---|---|
| Per-event immutable record | Ring buffer/perf-event style transport; validate record ABI in user space | A complete submitted record or a loss/error condition defined by the transport | Mutating a shared map value just to serialize one event. |
| Monotonic counter | Per-CPU counter map when exact instant global total is unnecessary; aggregate in user space | Per-CPU components and a sampled aggregate | A global lock on every hot event. |
| One scalar flag or counter with defined atomic semantics | BPF atomic operation on an aligned scalar, after verifying target/program support | A single atomic field update | Using atomics to imply a consistent multi-field snapshot. |
| Multi-field per-cgroup state with infrequent writes | `bpf_spin_lock` only if its restrictions fit; otherwise publish versioned immutable values | Lock-protected state or an old/new generation | Locking across helpers, tail calls, or costly work. |
| Policy with multiple related entries | Build an inactive generation completely, validate it, then change a small selector/version | A documented old or new generation during the switch | Claiming that several `BPF_MAP_UPDATE_ELEM` calls are one atomic transaction. |
| Userspace-only handle ownership | `Arc<Mutex<...>>` around mutable loader/map-control state; pass cloned FDs or messages deliberately | One writer at a time, with a defined poisoned-lock response | Sharing mutable map wrappers among async tasks without a synchronization policy. |

The current UAPI exposes atomic BPF operations, including read-modify-write operations and acquire/release load/store forms. [18] Availability in an object is still dependent on the kernel, program type, verifier, architecture, and toolchain. For a book example, choose the simplest mechanism that establishes the needed invariant rather than optimizing prematurely.

### 4.2 Spin locks: powerful but deliberately restrictive

`bpf_spin_lock` protects fields in one map value. The helper manual imposes material restrictions: the lock is allowed only in hash and array maps (with possible future expansion), BTF map-value description is mandatory, only one lock may be held at a time, only one `struct bpf_spin_lock` is allowed in a map element, and every execution path must unlock before return. While held, neither helpers nor BPF-to-BPF calls are allowed; `BPF_LD_ABS` and `BPF_LD_IND` are also prohibited. [15]

The lock must be a top-level, four-byte-aligned field of the BTF-described map-value struct. It is not copied by ordinary `BPF_MAP_LOOKUP_ELEM` and is not updated by ordinary map update. User space must use `BPF_F_LOCK` when looking up or updating a spin-locked value. [15] [17] Current documentation also says tracing and socket-filter programs cannot use this helper and labels it root-only; these are exactly the sort of restrictions that must be verified against the target kernel, not generalized from a successful XDP or cgroup test. [15]

A safe teaching example is a per-cgroup rate-limit state with a short critical section that updates `tokens`, `last_refill_ns`, and a decision counter. The example should acquire the lock, compute and write only those fields, unlock on every branch, and then emit telemetry. It should never call a map helper, tail call, or output helper while holding the lock.

### 4.3 Userspace concurrency is also part of the map contract

Aya map operations move `Pod` values across the kernel/user boundary, so values must be plain data. [22] Give every shared value an explicit `#[repr(C)]` layout, fixed-width integer fields, explicit padding when needed, a format version, and no Rust references, pointers, enums with unspecified layout, or process-local handles. When a schema changes, use a new map name/path rather than silently interpreting old bytes as the new struct.

For the loader/control plane, `MapData` is `Send` and `Sync`, but this does not turn an application-level sequence of operations into a transaction. Protect mutable sequencing with `Mutex` or a single-writer task. Rust's `Mutex` returns an RAII guard and reports possible poisoning if a thread panics while holding it; poisoning is advisory and not a soundness mechanism. [23] [32] Rust atomics are safe to share but data races involving nonsynchronized conflicting non-atomic accesses are undefined behavior; `Ordering::Relaxed` does not establish a broader synchronization relationship. [31]

## 5. Pinning, tail calls, and controlled upgrades

### 5.1 Pinning is an explicit lifecycle reference

`BPF_OBJ_PIN` makes a bpffs path retain a reference to a map or program. Closing the original FD then does not deallocate that object. `unlink` removes the bpffs reference, and the object is deallocated only when no references remain. The parent must be a BPF filesystem; the current UAPI documentation also says the pathname must not contain a dot. [14] Use conservative, controlled path names without dots and verify the deployed kernel's behavior—this documented pathname restriction is an example of a fact that should not be copied blindly into a portability promise.

Aya 0.14's current API is `MapData::pin(path)` and `MapData::from_pin(path)`. Parent directories must already exist and the path must be on bpffs. Pinning an already existing path is reported as `PinError::SyscallError` with `ErrorKind::AlreadyExists`. [23] Map-specific wrappers forward `pin`; Aya's current source states that a pinned map remains loaded until its corresponding file is deleted. [24]

Treat a pin as an **owned lifecycle reference**. Record its owner, schema version, purpose, expected map info, and removal condition. Do not use a shared generic directory such as `/sys/fs/bpf/shared`; use a service-owned directory, a versioned map name, restrictive filesystem permissions, and startup reconciliation. A stale pin is an operability problem because it can accidentally reconnect a new binary to an incompatible state object.

### 5.2 Tail calls are a one-way dispatch boundary

A tail call uses `bpf_tail_call(ctx, prog_array, index)` to jump through a `BPF_MAP_TYPE_PROG_ARRAY`. It does not return to the caller. The callee receives the same context, but caller stack and register values are not accessible to it. If the target is absent or the tail-call limit has been reached, execution continues at the instruction after the tail-call helper. [15]

There is a documentation-sensitive limit worth teaching carefully. The overview in `bpf(2)` describes a nesting limit of 32, while the current `bpf-helpers(7)` page says the internal `MAX_TAIL_CALL_CNT` is currently 33. [13] [15] Do **not** write a security rule that assumes either bare number as an invariant. Budget a small fixed pipeline, keep a local fallback immediately after every tail call, test the target kernel, and include a counter for fallback execution.

Aya's current public implementation provides `ProgramArray<T>`. A user-space controller obtains it through typed conversion, then calls `ProgramArray::set(index, &ProgramFd, flags)` or `clear_index(&index)`. The source documents Linux 4.2 as the minimum for this feature. [24] A program-array update is useful for switching a known dispatch slot, but it is not a substitute for compatibility discipline: caller and callee must obey the same context, map-schema, return-value, and generation contract.

### 5.3 A defensible upgrade protocol

Use the following protocol for a host-side agent. It makes no claim of universal zero downtime; the available atomicity depends on the attachment mechanism and running kernel.

1. **Discover and preflight.** Record kernel release/configuration, `/sys/kernel/security/lsm`, cgroup v2 availability, target BTF, active attachment information, map metadata, and required helpers/program types. Enable Aya verifier logs during staging. BTF/CO-RE reduces field-offset coupling but does not add an unavailable helper, attach type, LSM hook, or map feature. [8] [25] [33] [34]
2. **Validate the data ABI.** Compare map type, key size, value size, flags, max-entry behavior, BTF value layout, and semantic version. If any incompatible field changes, make a new map and migrate through an application-defined process. Do not reuse an old pin just because the map name matches.
3. **Load before activate.** Parse/relocate/load the new object, set initial map data, run available test paths, and verify it before attaching. Separating load from attachment means initial state can be created before the program executes; this lifecycle separation is documented for libbpf and is a sound model for other loaders. [33]
4. **Switch one boundary at a time.** Prefer a BPF link where the target supports it. `BPF_LINK_CREATE` returns a manageable attachment FD, and `BPF_LINK_UPDATE` changes that link to a new program. The current UAPI supplies an expected-old-program field when replacement is requested, enabling a compare-and-replace style guard. [14] [17] If the target lacks compatible link update, use a documented overlap/gap strategy and make duplicate or missed-event behavior visible in metrics.
5. **Switch dispatch only after targets are ready.** Populate a new tail-call target before placing it in the active `ProgramArray` slot. Retain the local fallback. For policy state, publish a generation selector only after the complete inactive generation has been validated.
6. **Observe, then retire.** Count new generation hits, tail-call fallbacks, errors, and dropped events. Keep the prior program/map reference only for the declared rollback window. Then detach/unlink/remove through an audited cleanup action. Never leave “temporary” references without an owner and expiry.
7. **Rollback with the same ABI checks.** A rollback must restore both code and the intended map-generation interpretation. Reattaching old code to a map written with a newer schema is not a safe rollback.

For legacy or non-link attachments, state plainly that the implementation may have an observation overlap or gap. That is better engineering than calling an update “atomic” without an attachment-specific proof.

## 6. Aya API notes (current source reviewed on 10 September 2026)

Aya's canonical types have moved from `Bpf`/`BpfLoader` to `Ebpf`/`EbpfLoader`; the former aliases are documented as deprecated. The current `aya` crate page describes Aya as a Rust-native loader with transparent BTF support when the target kernel supports it. [20] The book's older lifecycle page still uses `Bpf` in prose/code, so an advanced-beginner book should use `Ebpf` and point out the alias change rather than reproduce stale names. [21]

| Need | Current Aya API verified | Usage advice |
|---|---|---|
| Basic object ownership | `Ebpf::load_file`, `Ebpf::load`, `Ebpf::{map,map_mut,take_map}`, `Ebpf::{program,program_mut}` | Programs are parsed/relocated on object load, but program `load()` and `attach()` are separate. Keep the `Ebpf` object alive for the objects/links it owns. [20] [22] [35] |
| Advanced loading | `EbpfLoader::new()`, `btf(...)`, `default_map_pin_directory(...)`, `map_pin_path(...)`, `map_max_entries(...)`, `override_global(...)`, `verifier_log_level(...)`, `load_file(...)`, `load(...)` | Pin path supplied for one map takes precedence over default directory. `set_global` and `set_max_entries` are deprecated since Aya 0.13.2. Do not use `allow_unsupported_maps()` as a general compatibility escape hatch. [25] |
| Typed maps | `TryFrom`/`TryInto` from `Map`/`&mut Map` into wrappers such as `HashMap`, `PerCpuHashMap`, `ProgramArray` | Match map type and `Pod` layout exactly. `take_map` deliberately transfers ownership out of `Ebpf`. [22] |
| Pin/open a map | `MapData::pin`, `MapData::from_pin`, `MapData::from_id`, `MapData::from_fd` | `from_pin` is for bpffs. `from_fd` is for a validated FD received by another controlled channel. Check map info before treating an opened map as your schema. [23] |
| Tail-call table | `ProgramArray::set`, `ProgramArray::clear_index`, `ProgramArray::indices` | Call `set` only after target program load succeeded; record index-to-generation mapping. [24] |
| BPF LSM | `aya::programs::Lsm`; `Lsm::load(lsm_hook_name, &Btf)`; `Lsm::attach()` | Requires BTF plus `CONFIG_BPF_LSM=y` and `bpf` active in the boot LSM order. Confirm the exact hook on the deployed host. [26] |

Aya's current crate manifest on the reviewed `main` branch reports `aya` version **0.14.0**. [36] This is a source-snapshot fact, not a promise that a reader's lockfile resolves the same version. Pin the dependency in the book repository, cite the generated API documentation version used in examples, and compile examples in CI against the supported matrix.

## 7. NixOS and systemd as defensive control layers

NixOS can express a service's systemd unit declaratively. In Nixpkgs, `systemd.services.<name>.serviceConfig` is serialized into the unit's `[Service]` section; the stable options manual identifies `systemd.services` as the service-unit definition surface. [27] [28] The security semantics, however, are systemd and kernel semantics. A correct Nix expression does not guarantee the requested feature exists in the installed systemd or kernel.

For a **consumer** that does not load, attach, or mutate BPF objects, use a hardened, capability-free unit. The following is deliberately not a loader configuration:

```nix
{
  systemd.services.ebpf-event-consumer = {
    description = "Unprivileged eBPF event consumer";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      User = "ebpf-consumer";
      Group = "ebpf-consumer";
      NoNewPrivileges = true;
      CapabilityBoundingSet = "";
      AmbientCapabilities = "";
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      RestrictNamespaces = true;
      RestrictAddressFamilies = [ "AF_UNIX" ];
    };
  };
}
```

`CapabilityBoundingSet=` controls the bounding set and also affects effective, permitted, and inheritable sets; an empty assignment resets it to empty. [29] `NoNewPrivileges=` is an appropriate complement, but it does not grant access to a pinned map or neutralize an LSM. Test this illustrative unit against the actual collector's required sockets/files, inspect the generated unit, and verify runtime behavior. Keep the privileged loader separate and make the interface between loader and consumer explicit—for example, a narrowly permissioned Unix socket or deliberately passed FD.

Systemd's current documentation has newer BPF-specific controls: `PrivateBPF=` mounts a private bpffs view, while `BPFDelegateCommands=`, `BPFDelegateMaps=`, and `BPFDelegatePrograms=` limit a bpffs delegation token's allowed capabilities. They were added in systemd 258 and require `PrivateBPF=yes` to be effective. [29] These controls are promising least-privilege mechanisms but are **version-dependent**. Do not assume a stable NixOS channel packages systemd 258+ or that a given kernel supports the corresponding bpffs delegation feature; gate them on deployment tests.

Systemd uses cgroups for unit resource control. `Slice=` determines hierarchy placement, and `Delegate=` permits a unit to create/manage a private subhierarchy below its unit cgroup. The documentation warns that, because internal cgroup nodes should not contain processes, a supervising process in a delegated unit usually needs to run in a subgroup. [30] This agrees with cgroup v2's no-internal-process rule and is a useful bridge from container theory to an operational systemd host. [1]

## 8. Verifier traps to make visible in examples

The verifier simulates all reachable paths and tracks register types, scalar ranges, stack initialization, pointer bounds/alignment, and references. A program is accepted only if every path is safe. [16] Treat verifier logs as a design artifact: capture them in development and write the invariant that each check establishes.

| Trap | Why it is rejected or unsafe | Beginner-accessible repair |
|---|---|---|
| Dereferencing map lookup return without a null branch | A lookup result is `PTR_TO_MAP_VALUE_OR_NULL` until checked | Branch immediately on null; use the non-null value only in the proven branch. [16] |
| Passing an undersized/uninitialized stack key to a map helper | Verifier knows the map key size and tracks stack writes | Zero/initialize the complete typed key before the helper. Avoid handcrafted byte offsets. [13] [16] |
| Reading uninitialized stack/register state | Registers and stack slots start unreadable; stack must be written before read | Initialize every local on all paths; return a defined value on all exits. [16] |
| Forgetting helper-call clobbers | After a kernel helper call, `R1`–`R5` are unreadable; `R6`–`R9` are callee-saved | Save needed scalars/allowed pointers in callee-saved registers and revalidate data after helpers that can invalidate assumptions. [16] |
| Out-of-bounds or misaligned access | Pointer type, range, and alignment are checked on every path | Bound-check before access, preserve the checked pointer relationship, and use naturally aligned fields. [16] |
| Exceeding stack budget | The current kernel header declares `MAX_BPF_STACK` as 512 bytes | Keep eBPF stack structures small; move fixed state into a map only when its concurrency/lifecycle contract is clear. [18] |
| Holding a spin lock across a call or returning locked | Lock rules forbid calls while held and require unlock on every path | Make the lock scope a short straight-line block; compute/output afterward. [15] |
| Tail call assumed to succeed | Missing target or exhausted chain returns to the instruction after the helper | Put a safe fallback decision and metric immediately after it. [15] |
| Using a helper/attach type based only on headers | Headers may define a UAPI that the deployed kernel/configuration does not enable | Feature-detect and fail closed; test every supported kernel in CI. [17] [34] |
| Treating a BPF LSM hook signature as stable source ABI | Hook declarations and BTF layouts can vary with kernel/configuration | Use BTF-aware bindings/CO-RE where available, minimize accessed fields, and test the real hook. [10] [11] |

The verifier documentation's examples are intentionally worth reproducing in a chapter: an unchecked map value produces `R0 invalid mem access 'map_value_or_null'`; an uninitialized indirect stack read fails; a map-value store beyond the declared `value_size` fails. [13] [16] Show readers how the error corresponds to a violated invariant instead of teaching a ritual of adding casts until compilation succeeds.

## 9. Portability and version matrix

The following separates durable concepts from facts that must be checked on the target. “Minimum” means the cited source documents the feature at that level; it is not a statement that every distribution enables the required configuration or policy.

| Feature/fact | Cited minimum/current statement | Engineering rule |
|---|---|---|
| cgroup namespace proc handle | `/proc/<pid>/ns/cgroup` since Linux 4.6 | If namespace evidence is optional, omit it gracefully on older hosts; do not parse its pathname as identity. [2] |
| Unprivileged user-namespace creation | Linux 3.8 | Distribution sysctls and policy may still prohibit it; do not use as a deployment prerequisite unless tested. [2] [4] |
| `CAP_BPF` | Linux 5.8 | Older kernels fold privileged BPF authority differently; do capability/policy diagnostics rather than unconditional capability grants. [5] |
| BPF LSM / Aya `Lsm` | Linux 5.7; `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `bpf` active in LSM list | Check config, BTF, and `/sys/kernel/security/lsm`; have an audit-only/no-enforcement fallback or fail closed according to product requirements. [26] |
| Aya `ProgramArray` | Linux 4.2 according to current Aya source | Tail-call chain limit and helper/program compatibility still require target testing. [24] |
| seccomp `LOG` / `NEW_LISTENER` / `TSYNC_ESRCH` / `WAIT_KILLABLE_RECV` | 4.14 / 5.0 / 5.7 / 5.19 respectively | Probe actions/flags before relying on them; keep a simpler allowlist fallback. [7] |
| systemd BPF delegation settings | systemd 258 | Gate on `systemd --version` and feature tests; NixOS expression acceptance is not enough. [29] |
| Aya public naming | `Ebpf`/`EbpfLoader` current; `Bpf`/`BpfLoader` deprecated aliases | Pin Aya version and use `Ebpf` in new examples. [20] [25] |
| CO-RE/BTF | Reduces kernel type-offset coupling where target BTF is present | It does not provide an unavailable hook/helper or make a tracing interface a stable semantic contract. [33] [34] |

The current kernel documentation site used here identifies itself as **7.3.0-rc2**, and the current man-pages pages identify the 6.19 tarball. Those are source-snapshot observations, not target baselines. Distribution kernels commonly backport features and retain configuration choices that differ from upstream version numbers. Record the actual kernel release, BTF presence, LSM list, bpffs mount, and feature-test results in deployment diagnostics. [2] [6] [16]

## 10. One worked defensive design: cgroup-keyed policy telemetry

Consider a host agent that reports—and optionally enforces—a small policy for workloads assigned to cgroup v2 subtrees. It is intentionally generic: no runtime-specific container engine is trusted in the BPF fast path.

**Data-plane contract.** At an eligible hook, obtain the current cgroup ID and look up a compact `PolicyV1` value keyed by that ID. The value contains `abi_version`, `policy_generation`, a mode enum represented as a fixed `u32`, and fixed-width thresholds. If the lookup is absent, return the documented safe default. If state requires a compound update, use either a very short eligible-map spin-lock critical section or a generation selector with prebuilt state. Emit `{event_time, cgroup_id, policy_generation, decision, reason_code}`. [15] [16]

**Control-plane contract.** A host reconciler observes cgroup lifecycle and runtime workload metadata. It stores a time-bounded mapping from `cgroup_id` to host cgroup path, namespace evidence, workload UID, and labels. A policy writer is the only component allowed to update policy maps; a consumer receives events but has no BPF load or map-write permission. Its NixOS service is capability-free and constrained with systemd hardening. [1] [2] [29] [30]

**Upgrade contract.** Version 2 uses a distinct `PolicyV2` map path rather than a larger value under the V1 pin. Load and test the V2 program while it refers only to V2 maps. Populate and validate the V2 map. Switch a supported BPF link with an expected-old-program guard, or use a documented staged attachment procedure. Keep counters for V1/V2 events and tail-call fallback; rollback restores the prior code **and** V1 map interpretation. Finally, retire V1 after the declared observation window. [14] [17] [23] [25]

This design accepts that a cgroup can change membership and that an observer may see a transition. It makes the transition measurable rather than concealing it behind an unjustified claim of global atomicity.

## 11. Claims that require cautious wording in the book

| Unsafe or overly broad wording | Recommended wording |
|---|---|
| “A cgroup is a container.” | “A cgroup is a kernel resource/policy grouping. A runtime may use one or more cgroups to implement a workload; correlate it with runtime metadata outside the fast path.” |
| “The cgroup path identifies the container.” | “A cgroup path is a view-dependent, mutable label. Prefer the event-time cgroup ID plus host lifecycle metadata.” |
| “Container root can load BPF.” | “Capabilities are evaluated in relevant user namespaces and BPF operations have kernel-, configuration-, program-type-, and LSM-dependent requirements.” |
| “`CAP_BPF` is all a loader needs.” | “`CAP_BPF` split privileged BPF operations from `CAP_SYS_ADMIN` in Linux 5.8, but requirements vary by operation and target policy.” |
| “Seccomp is a sandbox.” | “Seccomp minimizes syscall surface. Combine it with namespaces, capabilities, LSM policy, and application design.” |
| “LSMs run in this fixed order.” | “Read `/sys/kernel/security/lsm` on the target. It reports active order, which is selected by build/boot configuration.” |
| “Our BPF LSM logs every denied action.” | “An earlier LSM denial can stop later integer hooks. Verify audit coverage separately.” |
| “A map update makes policy atomic.” | “A map-element update affects that element. Define what readers see across related elements and generations.” |
| “Pinned maps are automatically compatible after upgrade.” | “A pin preserves an object reference. Reuse only after validating the complete map ABI and semantics.” |
| “Tail calls are function calls with a larger stack.” | “A tail call is a non-returning jump; callee cannot use caller registers/stack, and failure falls through.” |
| “CO-RE makes eBPF run everywhere.” | “CO-RE can relocate type accesses with target BTF. It does not supply missing features or stabilize hook semantics.” |
| “NixOS hardening options guarantee security.” | “NixOS declaratively requests systemd/kernel controls; verify the generated unit, systemd version, kernel support, and application behavior.” |

## Sources actually read

The following inventory lists every external document or source file read for this dossier. Search-result snippets were not used as evidence. The two unsuccessful raw Nixpkgs fetches were excluded; the successful Nixpkgs sources read through GitHub/API retrieval are included.

| Ref. | Source read | Authority and use |
|---|---|---|
| [1] | Linux kernel, *Control Group v2* | Primary cgroup v2 hierarchy, threaded and delegation rules. |
| [2] | Linux man-pages, *namespaces(7)* | Primary namespace semantics, nsfs identity and lifecycle. |
| [3] | Linux man-pages, *cgroup_namespaces(7)* | Primary cgroup-namespace virtualization and path caveats. |
| [4] | Linux man-pages, *user_namespaces(7)* | Primary capability and ownership boundaries for user namespaces. |
| [5] | Linux man-pages, *capabilities(7)* | Capability sets and `CAP_BPF` history. |
| [6] | Linux kernel, *Seccomp BPF* | Primary seccomp semantics, composition, and notification cautions. |
| [7] | Linux man-pages, *seccomp(2)* | Seccomp flag/version history and TSYNC details. |
| [8] | Linux kernel, *Linux Security Module Usage* | Active LSM list and ordering documentation. |
| [9] | Linux source, `security/security.c` | Current integer-hook dispatcher and BPF LSM authorization source. |
| [10] | Linux source, `include/linux/lsm_hook_defs.h` | Current LSM hook declarations. |
| [11] | Linux kernel, *LSM BPF Programs* | BPF LSM prior-return example and attachment model. |
| [12] | Linux kernel, *BPF maps* | Primary map overview and syscall operations. |
| [13] | Linux man-pages, *bpf(2)* | Map sharing, program arrays, lifetimes, and verifier map-size checks. |
| [14] | Linux kernel, *eBPF Syscall* | Primary object pin/get and BPF link command semantics. |
| [15] | Linux man-pages, *bpf-helpers(7)* | Tail-call, cgroup-ID, local-storage synchronization, and spin-lock contracts. |
| [16] | Linux kernel, *eBPF verifier* | Primary verifier state-tracking rules and failure examples. |
| [17] | Linux source, `include/uapi/linux/bpf.h` | Current UAPI map, cgroup storage, link, and map-operation definitions. |
| [18] | Linux source, `include/linux/filter.h` | Current BPF stack and atomic instruction definitions. |
| [19] | Linux kernel, *BPF Kernel Functions (kfuncs)* | cgroup kfunc acquisition/release and ID/ancestor semantics. |
| [20] | Aya docs.rs, *crate aya* | Current public crate naming and deprecated aliases. |
| [21] | Aya book, *Program Lifecycle* | Historic lifecycle explanation; read to identify stale `Bpf` naming. |
| [22] | Aya docs.rs, *aya::maps* | Typed-map conversion, map ownership accessors, and `Pod` values. |
| [23] | Aya docs.rs, *MapData* | Current pin/open/map-info API and errors. |
| [24] | Aya source, `ProgramArray` | Exact current tail-call table method names and stated minimum. |
| [25] | Aya docs.rs, *EbpfLoader* | Advanced loader API and deprecations. |
| [26] | Aya source, `programs/lsm.rs` | Exact LSM loader API, requirements, and stated minimum. |
| [27] | Nixpkgs source, `nixos/lib/systemd-lib.nix` | `serviceConfig` unit-generation implementation. |
| [28] | NixOS stable options manual | Public NixOS service-option surface. |
| [29] | systemd, *systemd.exec(5)* | Capability, namespace, and BPF delegation controls. |
| [30] | systemd, *systemd.resource-control(5)* | Unit cgroups, slices, controllers, and delegation. |
| [31] | Rust standard library, `std::sync::atomic` | Rust atomic memory model and portability caveats. |
| [32] | Rust standard library, `std::sync::Mutex` | Mutex ownership, blocking, and poisoning behavior. |
| [33] | Linux kernel, *libbpf Overview* | Lifecycle separation, BTF, and CO-RE portability limitations. |
| [34] | Linux kernel, *Program Types and ELF Sections* | Current program/attach-type surface and deprecation warning. |
| [35] | Aya source, `programs/mod.rs` | Current program load/attach model and exported program types. |
| [36] | Aya source, `aya/Cargo.toml` | Reviewed Aya main-branch package version. |
| [37] | Aya book, *LSM* | Aya's reader-facing LSM requirements and example behavior. |
| [38] | NixOS stable manual, *Changing the configuration* | Declarative NixOS service examples and upgrade caveats. |
| [39] | Aya source, `maps/mod.rs` | Current map pin forwarding, reopening, and pin-on-load behavior. |

## References

[1]: https://docs.kernel.org/admin-guide/cgroup-v2.html "Control Group v2 — The Linux Kernel documentation"
[2]: https://man7.org/linux/man-pages/man7/namespaces.7.html "namespaces(7) — Linux manual page"
[3]: https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html "cgroup_namespaces(7) — Linux manual page"
[4]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html "user_namespaces(7) — Linux manual page"
[5]: https://man7.org/linux/man-pages/man7/capabilities.7.html "capabilities(7) — Linux manual page"
[6]: https://docs.kernel.org/userspace-api/seccomp_filter.html "Seccomp BPF (SECure COMPuting with filters) — The Linux Kernel documentation"
[7]: https://man7.org/linux/man-pages/man2/seccomp.2.html "seccomp(2) — Linux manual page"
[8]: https://docs.kernel.org/admin-guide/LSM/index.html "Linux Security Module Usage — The Linux Kernel documentation"
[9]: https://raw.githubusercontent.com/torvalds/linux/master/security/security.c "Linux kernel security/security.c source"
[10]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/lsm_hook_defs.h "Linux kernel LSM hook declarations"
[11]: https://docs.kernel.org/bpf/prog_lsm.html "LSM BPF Programs — The Linux Kernel documentation"
[12]: https://docs.kernel.org/bpf/maps.html "BPF maps — The Linux Kernel documentation"
[13]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — Linux manual page"
[14]: https://docs.kernel.org/userspace-api/ebpf/syscall.html "eBPF Syscall — The Linux Kernel documentation"
[15]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) — Linux manual page"
[16]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier — The Linux Kernel documentation"
[17]: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h "Linux BPF UAPI header"
[18]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/filter.h "Linux kernel socket filter header"
[19]: https://docs.kernel.org/bpf/kfuncs.html "BPF Kernel Functions (kfuncs) — The Linux Kernel documentation"
[20]: https://docs.rs/aya/latest/aya/ "aya crate documentation"
[21]: https://aya-rs.dev/book/aya/lifecycle.html "Program Lifecycle — Building eBPF Programs with Aya"
[22]: https://docs.rs/aya/latest/aya/maps/index.html "aya::maps module documentation"
[23]: https://docs.rs/aya/latest/aya/maps/struct.MapData.html "aya::maps::MapData documentation"
[24]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/maps/array/program_array.rs "Aya ProgramArray source"
[25]: https://docs.rs/aya/latest/aya/struct.EbpfLoader.html "aya::EbpfLoader documentation"
[26]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/programs/lsm.rs "Aya LSM program source"
[27]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/lib/systemd-lib.nix "Nixpkgs systemd unit library source"
[28]: https://nixos.org/manual/nixos/stable/options "NixOS stable configuration options"
[29]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html "systemd.exec(5)"
[30]: https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html "systemd.resource-control(5)"
[31]: https://doc.rust-lang.org/std/sync/atomic/ "std::sync::atomic module documentation"
[32]: https://doc.rust-lang.org/std/sync/struct.Mutex.html "std::sync::Mutex documentation"
[33]: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html "libbpf Overview — The Linux Kernel documentation"
[34]: https://docs.kernel.org/bpf/libbpf/program_types.html "Program Types and ELF Sections — The Linux Kernel documentation"
[35]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/programs/mod.rs "Aya programs module source"
[36]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/Cargo.toml "Aya Cargo manifest"
[37]: https://aya-rs.dev/book/programs/lsm.html "LSM — Building eBPF Programs with Aya"
[38]: https://nixos.org/manual/nixos/stable/#sec-changing-config "NixOS Manual: Changing the configuration"
[39]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/maps/mod.rs "Aya maps module source"
