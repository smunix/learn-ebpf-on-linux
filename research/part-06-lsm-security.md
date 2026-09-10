# Part 06 — BPF LSM Security and Enforcement

**Research cutoff:** 10 September 2026
**Audience:** Advanced eBPF learners who are new to Linux security engineering
**Scope:** Defensive, host-local BPF Linux Security Module (LSM) policy and telemetry only

## Executive conclusion

**BPF LSM is a programmable Mandatory Access Control (MAC) and audit mechanism at Linux security decision points.** It is not a syscall filter, a pathname matcher, or a general-purpose endpoint product. A defensible design begins by stating a narrow threat model, chooses an LSM hook that observes the kernel object actually being protected, identifies that object without trusting a pathname, and makes one clear decision: **allow (`0`) or deny (a negative errno)** for ordinary LSM hooks. The BPF program must preserve an earlier nonzero BPF-LSM result when it participates in a stacked BPF program chain. [1] [2]

For a first enforcement project, use `file_open` to protect a small, explicitly inventoried set of regular files for an explicitly scoped workload. Compute policy identity from the opened `struct file` and its inode/superblock relationship, rather than from a mutable path string. Begin in **observe** mode, collect decision-complete telemetry, test policy coverage and false positives, then enable enforcement with a documented rollback. This is safer than beginning with a broad deny rule. [3] [4] [5]

> **Core rule:** A telemetry failure must not silently change the security decision. If a ring-buffer reservation fails, increment a loss counter and return the policy decision already reached. If the policy lookup is unavailable during a deliberately configured learning or degraded phase, allow and record the reason; after the policy is proven, enforcement behavior must be an explicit, tested product decision rather than an accidental consequence of an empty map.

This chapter treats source facts as either **invariants** or **target-kernel-dependent** behavior. The live kernel documentation consulted was built for 7.3.0-rc2, current source snapshots included Linux `master` and v6.19-rc8, and Aya/Nixpkgs `main` were read on the cutoff date. A book should tell readers to validate the deployment kernel, its configuration, BTF, enabled LSM order, and permitted helpers before claiming a hook or helper is available. [1] [6] [7]

## 1. The security model: LSM framework, BPF LSM, and stacking

The **Linux Security Module framework** inserts security hooks into kernel operations over objects such as credentials, inodes, files, superblocks, sockets, and tasks. The framework itself does not implement policy. It dispatches the security modules configured into the kernel. `/sys/kernel/security/lsm` exposes the active LSMs in their check order. The LSM documentation states that hooks are ordered by `CONFIG_LSM`; current dispatch code implements an integer hook by returning the first result that differs from that hook’s default result. Thus, a non-default result from an earlier LSM can stop later LSM checks for that hook. [2] [8] [9]

**BPF LSM** is the `bpf` LSM component. When enabled at build and boot time, it permits privileged BPF programs to attach to BTF-described LSM hook stubs. The kernel’s BPF LSM verifier requires a GPL-compatible program, checks that the requested attachment BTF ID names a supported BPF-LSM hook, and rejects disabled hooks. The kernel Kconfig option is `CONFIG_BPF_LSM`; it depends on `BPF_EVENTS`, `BPF_SYSCALL`, `SECURITY`, and `BPF_JIT`. Aya additionally documents `CONFIG_DEBUG_INFO_BTF=y` as a practical requirement because the loader resolves the hook through kernel BTF. [1] [6] [10] [11]

| Layer | What it does | Engineering consequence |
|---|---|---|
| VFS / subsystem operation | Performs an operation such as opening a file or binding a socket. | Choose a hook from the operation and object lifecycle, not from a desired log message. |
| LSM framework | Calls configured LSMs and stops an integer-hook dispatch on the first non-default return. | BPF LSM is additive to other LSMs; it does not bypass SELinux, AppArmor, Landlock, or DAC. Hook order is part of the deployment contract. |
| BPF LSM hook stub and trampoline | Invokes BPF programs attached to the BPF LSM hook. | A BPF program must preserve an earlier BPF-chain denial. Do not overwrite `ret` with `0`. |
| Policy maps and telemetry | Hold policy data and report decisions to user space. | Treat map schema, pinning, migration, and telemetry loss as control-plane design concerns. |

### 1.1 Three different kinds of “stacking”

A beginner should distinguish three interactions that are often all called “stacking.”

1. **Stacking ordinary LSMs.** The LSM framework orders module checks. For an integer hook, the generic dispatcher begins with the hook default and exits once a module returns a non-default value. A BPF LSM program cannot observe or reverse an earlier LSM’s result if that earlier LSM stopped dispatch before BPF was reached. [2] [9]
2. **Multiple BPF programs at one BPF-LSM MAC attachment.** The BPF LSM context carries an extra, final `int` return argument. Kernel documentation says it is the result of the previous BPF program, or `0` for the first program. Aya’s `LsmContext` documents the same synthetic final argument. A program should normally return an inherited nonzero result unchanged. [1] [12]
3. **Cgroup LSM attachment.** This is a distinct BPF LSM attachment type with different aggregation semantics; it is not merely a globally attached LSM program with a cgroup ID check. The cgroup runner evaluates the effective programs for the workload’s cgroup and uses the program’s boolean outcome together with a cgroup run-context return value. See §5. [13] [14]

### 1.2 Hook return semantics: do not guess

For ordinary BPF-LSM hooks whose declared return type is `int`, the current BPF-LSM verifier permits **zero** or a **negative errno**. The source identifies a small special set of boolean LSM hooks where only `0` or `1` is valid. It rejects an arbitrary positive integer for the usual `int` hooks. The safe book wording is therefore: **“For ordinary authorization hooks, return `0` to permit and a documented negative errno such as `-EPERM` to deny; inspect the hook declaration and target verifier behavior for exceptions.”** [6]

The LSM hook definition supplies the function arguments. BPF LSM adds the synthetic trailing prior-result argument. For example, the current declaration is `file_open(struct file *file)`, so a non-cgroup BPF LSM program sees `file` at argument 0 and the synthetic `ret` at argument 1. Do not hard-code an argument list copied from a blog: use the target kernel’s `include/linux/lsm_hook_defs.h` and the BTF the loader uses. [12] [15]

```rust
// Pseudocode: type bindings and safe field reads are intentionally omitted.
// The shape is the important security invariant.
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        let previous: i32 = ctx.arg(1); // file_open has one native argument.
        if previous != 0 {
            return previous;            // Never erase an earlier BPF-LSM denial.
        }

        match decide_file_open(ctx) {
            Decision::Allow { reason } => { emit_best_effort(reason, 0); 0 }
            Decision::Deny { reason }  => { emit_best_effort(reason, -EPERM); -EPERM }
            Decision::Degraded { reason } => { emit_best_effort(reason, 0); 0 }
        }
    }
}
```

The pseudocode’s `Degraded` branch is **not** a universal recommendation to allow. It demonstrates that a policy can make its fail-open state explicit and observable. A high-assurance deployment may intentionally deny a protected operation if its policy generation is absent; that decision belongs to the threat model and rollout contract, not to an implicit `NULL`-map behavior.

## 2. Attach prerequisites and a preflight checklist

### 2.1 Invariants

The following conditions are intrinsic to the interface, although exact error codes and tooling vary.

| Preflight check | Why it matters | Defensive test |
|---|---|---|
| Kernel built with `CONFIG_BPF_LSM=y` and BPF prerequisites | Without it, the LSM program type cannot implement BPF-LSM hooks. | Read the target kernel config where available; attempt a harmless audit-only load with verifier logging. [10] |
| Kernel BTF available and compatible with the target | The BPF LSM attachment resolves `bpf_lsm_<hook>` by BTF function name. | Check `/sys/kernel/btf/vmlinux`; load BTF using `Btf::from_sys_fs()` and report a clear preflight failure. [11] |
| `bpf` is active in the boot LSM list | Compiling BPF LSM is insufficient when it is omitted from the active LSM configuration. | Read `/sys/kernel/security/lsm` and require the comma-separated list to contain `bpf`. [2] [16] |
| Loader has only the privileges it truly needs | Loading security policy is highly privileged. | Use a dedicated root-owned service with a narrow capability/privilege model; `CAP_BPF` was introduced in Linux 5.8, while `CAP_SYS_ADMIN` remains a broader alternative. [17] |
| Hook and helper exist on the target | Kernel source and BTF expose version/configuration-dependent hook sets. | Feature-probe the exact object on every supported kernel image; keep the verifier log on failures. [6] |

The BPF LSM Kconfig help describes it as instrumentation of security hooks for dynamic MAC and audit policies. The system configuration must be evaluated as a whole. An enabled BPF LSM does not mean that a particular helper, filesystem kfunc, sleepable hook, or cgroup attachment is usable in a given kernel/configuration. [10] [6]

### 2.2 NixOS: declare LSM order; do not append an ad hoc duplicate parameter

NixOS currently exposes `security.lsm` as “a list of the LSMs to initialize in order” and renders it as `lsm=` in `boot.kernelParams`. Its current security module adds `landlock`, `yama`, and uses `lib.mkAfter [ "bpf" ]`, with a comment that BPF must load last because of observed AppArmor/LSM-stacking problems around kernels 6.12–6.18. It also asserts that a raw `security=` parameter is not used when `security.lsm` is configured. This is valuable **distribution-specific** guidance, not a generic Linux invariant. [18] [19]

```nix
# Illustrative NixOS configuration. Confirm the required LSM set for this host.
{
  security.lsm = [ "landlock" "yama" "apparmor" "bpf" ];
}
```

After a reboot, test the effective result rather than trusting the configuration expression:

```sh
cat /sys/kernel/security/lsm
# Require an entry exactly named bpf, and retain the full observed order in deployment evidence.
```

Do not claim that an arbitrary `lsm=...` replacement is safe. Replacing the list can omit a system’s existing protection, alter which LSM sees a hook first, or change breakage behavior. On any distribution, record the pre-change list, specify the desired final list, reboot in a recovery-capable window, and test representative workloads.

## 3. A `file_open` enforcement pattern

### 3.1 What `file_open` means

`file_open` is declared as an integer LSM hook over a `struct file *`. The VFS calls `security_file_open(f)` after assigning the file operations and before the shown fsnotify open-permission call. Its source comment says it saves open-time permission state for later use and rechecks access if state has changed since `inode_permission`. It returns `0` when permission is granted. [15] [20]

This makes it a useful hook for a narrow policy expressed as: **“may this task open this already-resolved file object?”** It is not equivalent to “may this pathname be typed,” “may a file be read forever,” or “may an executable be run.” Those requirements may need additional hooks such as `inode_permission`, executable hooks, `mmap_file`, or other object-specific checks. The chapter should teach hook selection as a coverage exercise, not a one-hook security claim. Current hook declarations include `inode_permission`, `file_open`, `file_post_open`, and superblock mount/unmount hooks. [15]

| Requirement | Candidate hook class | Caution |
|---|---|---|
| Gate the act of opening an already resolved file | `file_open` | Best introductory file-object rule; not a blanket guarantee for all later access paths. |
| Gate an inode permission check | `inode_permission` | The `mask` must be interpreted correctly; it can run often, so keep policy fast. |
| Need content after open | `file_post_open` | The documented hook is for LSMs that need content available; consider latency and availability. [3] |
| Control mount topology | `sb_mount`, `sb_umount`, related superblock hooks | Separate threat model; do not pretend an inode rule controls mount administration. [15] |
| Need immutable content evidence | A suitable sleepable hook plus supported integrity/filesystem facility | Feature-probe. IMA hash helpers can sleep; filesystem kfunc availability is target-dependent. [6] [21] |

### 3.2 Identity: make the policy about an object, not a spelling

A pathname is a **lookup instruction**, not a durable file identity. It is evaluated relative to a process root or directory file descriptor; a process may have a private mount namespace; path walks can follow symbolic links; and mounts, including bind mounts, alter what a pathname reaches. Therefore, a policy keyed only by `/some/path` is vulnerable to semantic mistakes and is hard to explain across namespaces. [22]

For a `file_open` policy, obtain the associated inode from the file and make the primary policy key from an inode identity **within its superblock/filesystem**. At the conceptual level:

```text
FileKey = {
    filesystem_or_superblock_discriminator,
    inode_number,
    optional_inode_generation,
    policy_namespace_or_tenant
}
```

The current kernel `struct inode` contains `i_sb`, `i_ino`, and `i_generation`. Linux user-space documentation states that an inode number is unique only within one filesystem. That supports a composite key of a superblock/filesystem discriminator plus inode number; it does **not** justify treating `i_ino` alone as host-wide identity. An inode generation, when exposed by BTF and meaningful on the deployed filesystem, can help distinguish reuse but must not be advertised as an all-filesystem, permanent guarantee. [23] [24]

| Identity element | Good use | Do **not** assume |
|---|---|---|
| `inode->i_ino` | Object identity within one filesystem. | It is globally unique, or sufficient without filesystem/superblock context. [24] |
| `inode->i_sb` / a superblock-derived discriminator | Separate inode number spaces and classify filesystem domain. | A raw kernel pointer is stable across reboot, safe to persist, or portable as a policy key. |
| Superblock device/filesystem characteristics | Add a deployment-specific filesystem dimension where the target’s BTF exposes a suitable field. | All filesystems have a meaningful block-device identity; pseudo, network, overlay, and anonymous filesystems need special treatment. |
| `i_generation` | Optional, in-session incarnation signal where verified. | All filesystems implement it consistently or that it replaces lifecycle management. [23] |
| Resolved path | Operator-facing event context or a separately verified, bounded label. | It is namespace-independent, race-free, or a primary authorization identity. [22] |

**Recommended default:** build a stable *in-session* key from a vetted superblock discriminator and `i_ino`; use the object’s current path only as diagnostic enrichment in user space. Treat overlay, FUSE, network, procfs/sysfs, and anonymous/in-memory filesystems as explicit policy classes. For an introductory capstone, deny policy eligibility for unknown filesystem types only after a measured rollout; otherwise emit `IDENTITY_UNSUPPORTED` and apply the declared degraded-mode rule. Never persist raw kernel addresses in a policy map or event schema.

Hard links are expected to resolve to the same inode on one filesystem. This is usually a security advantage for an inode-based policy: a protected object stays protected through another name. Conversely, renames change a pathname without changing the underlying inode. If the actual business requirement is “only permit access through this exact directory entry,” an inode-only rule is insufficient and the design must explicitly reason about dentries, mounts, namespaces, and races; do not hide that harder problem behind a path-prefix map.

### 3.3 Small, auditable decision algorithm

Keep the enforcement hot path short, bounded, and explainable.

1. Read and preserve the prior BPF-LSM return value. Return it if nonzero.
2. Read only the BTF fields needed to classify the `file` and inode. Null-check every optional pointer before dereferencing.
3. Reject or classify unsupported object classes explicitly: no implicit policy based on an untrusted pointer, unsupported filesystem, or a map lookup failure.
4. Build a fixed-size `FileKey`; look up a fixed-size policy value.
5. Apply a mode and action: **OFF**, **OBSERVE**, or **ENFORCE**. Separate `scope matched`, `rule matched`, and `action` in telemetry.
6. Emit a fixed-size decision record best-effort, incrementing a loss counter if transport is full.
7. Return `0` or the selected negative errno.

A policy value should be deliberately boring:

```text
FilePolicyValue = {
    generation: u64,        // control-plane version
    action: u8,             // allow or deny
    mode: u8,               // observe or enforce for this rule/scope
    reason_code: u16,       // stable taxonomy, not free-form text
    flags: u32,             // e.g., match-regular-file-only
}
```

Use an **allowlist** only for a small, enumerated protected scope that the operator can completely describe. Use a **denylist** only where the consequence of a missed rule is explicitly acceptable. Outside that scope, preserve normal Linux policy and create telemetry that tells the operator which cases were intentionally out of scope.

## 4. Audit, denial, telemetry, and fail-open design

### 4.1 Audit is a policy mode, not merely a log statement

An audit-only BPF LSM program evaluates the same object identity and rule match as enforcement, emits a decision event, and returns `0`. An enforcing program follows the same decision path but returns a negative errno for a deny. The two modes must share policy parsing, identity construction, reason codes, and test cases. Otherwise “audit success” does not demonstrate enforcement safety.

A robust event is **decision complete**: an operator can reconstruct why an operation was allowed or denied without requiring a kernel pointer or a best-effort pathname. Include a schema version, monotonic timestamp, current process identifiers, workload/cgroup selector where available, hook ID, file key, policy generation, mode, disposition, return errno, reason code, and telemetry status. Avoid command-line strings, paths, full credentials, secrets, or content in the kernel event unless the retention and privacy model explicitly permits them.

| Field group | Example | Purpose |
|---|---|---|
| Event framing | `schema_version`, timestamp, CPU | Safe evolution and ordering analysis. |
| Subject | `tgid`, `pid`, UID/GID representation, cgroup/workload key | Attribute an event to a workload, without treating PID alone as durable identity. |
| Object | filesystem discriminator, inode number, optional generation, object class | Explain the protected kernel object. |
| Decision | `mode`, `action`, `errno`, `reason_code`, `policy_generation` | Separate a match from its operational effect. |
| Telemetry health | `event_emitted`, per-CPU loss counter snapshot or separately exported metric | Detect silent observability degradation. |

A `BPF_MAP_TYPE_RINGBUF` is a sensible default event transport when a single shared multi-producer/single-consumer buffer and cross-CPU reservation ordering are useful. A ring buffer uses `max_entries` as a power-of-two byte size, and reserves fail rather than block when no space is available. `bpf_ringbuf_reserve()` requires a verifier-known constant size and every successful reservation must be committed or discarded; `bpf_ringbuf_output()` permits a verifier-unknown length at the cost of a copy. These facts imply a defensive event design: fixed-size records in the hot path, a bounded loss counter, and no conditional access decision based on whether logging succeeded. [25]

### 4.2 Ring buffer versus kernel audit

BPF LSM makes a policy decision; it does not automatically create a Linux Audit subsystem record. A book should call ring-buffer events **security telemetry** or **application audit events**, not claim they are equivalent to authenticated kernel audit records. If a deployment requires the Linux Audit trail, integrate it in user space through the organization’s approved logging/audit pipeline and correlate on the fixed decision identifiers. Do not add broad synchronous I/O or unbounded string construction to an LSM decision hook.

The kernel’s filesystem kfunc documentation also highlights recursion risk: `bpf_get_file_xattr()` and `bpf_get_fsverity_digest()` are restricted to BPF LSM and must avoid APIs that re-enter LSM hooks. This supports a general rule: **do not invoke a helper, kfunc, or policy lookup path whose implementation can re-enter the same security decision without understanding recursion and sleepability.** [21]

### 4.3 Explicit fail-open and fail-closed states

“Fail open” must name the failure and the bounded scope. It must not mean “return allow whenever something looks difficult.” Recommended modes are:

| Situation | Learning / availability-first disposition | Mature protected-scope disposition | Required signal |
|---|---|---|---|
| No policy rule for object outside declared scope | Allow. | Allow. | Optional sampled event. |
| No policy rule for object inside scope | Allow during explicitly timed learning window. | Policy-defined: deny only if scope inventory is complete and rollback is tested. | High-severity `MISSING_RULE`. |
| Unsupported filesystem/object identity | Allow during discovery. | Normally deny only for a narrow high-value scope, otherwise allow with alert. | `IDENTITY_UNSUPPORTED`. |
| Ring buffer full | Preserve already selected decision. | Preserve already selected decision. | Increment loss metric. |
| Policy map migration in progress | Keep old generation active. | Atomic/indirected swap; do not expose a half-populated map. | Generation metric and readiness gate. |
| Loader exits or link is detached | Policy may cease to apply unless attachment/link lifetime is retained. | Treat as a control-plane outage and monitor it. | Link health check and alert. |

The principle is **fail deterministically**, not necessarily always open or always closed. A protected secret-store file may be fail-closed during an identity failure. A general-purpose host OS should not suddenly deny all `/proc` or network filesystem access because an optional enrichment helper is unavailable. The design must list the condition, its disposition, its telemetry, the operator responsible, and the rollback action.

## 5. Cgroup-scoped BPF LSM

Cgroup attachment scopes a BPF LSM program to workloads associated with a cgroup instead of placing one global policy decision on every workload. Aya’s `#[lsm_cgroup]` macro emits an `lsm_cgroup/<hook>` section. Its userspace `LsmCgroup` loader uses `BPF_PROG_TYPE_LSM` with attachment type `BPF_LSM_CGROUP`, resolves `bpf_lsm_<hook>` through BTF, and attaches with a cgroup file descriptor via `bpf_link_create`. Aya documents Linux 6.0 as the minimum kernel version for this feature. [13] [26] [27]

**Important semantic difference:** ordinary BPF-LSM MAC hooks use errno-style decisions (`0` allow, negative errno deny). Current cgroup runner source starts with a return value, invokes every effective cgroup program, and for errno-returning LSM hooks changes the run-context return to `-EPERM` each time a program returns zero. A nonzero BPF program return acts as a grant in that aggregation; if no program grants, the result is denial. The program can access/adjust the cgroup run-context retval through `bpf_get_retval` / `bpf_set_retval` where allowed. Therefore, do not copy the ordinary MAC-hook return convention into a cgroup LSM program. Use the target kernel’s cgroup selftests/source or a feature-tested library abstraction, and make the boolean grant/errno decision model explicit in code review. [14] [28]

This has a practical safety consequence: **cgroup LSM is not simply an extra global deny layer.** Its aggregation model is designed around cgroup-delegated grants. Incorrectly returning `0` from a program because “zero means allow in MAC LSM” can deny every scoped operation. A beginner capstone should use global BPF LSM first unless per-workload isolation is a clear requirement and the team has tests for hierarchy, parent/child effective programs, migration between cgroups, and detachment.

Cgroup selection also depends on the hook context. The kernel chooses the current task’s default cgroup for general hooks; for hooks whose first argument is a socket or `struct sock`, it can use the socket’s associated cgroup. This is why a policy must state whether it protects **the actor currently executing** or **the socket’s associated workload**. [6] [14]

| Cgroup concern | Defensive design rule |
|---|---|
| Membership changes | Test move-in/move-out and child cgroup inheritance as explicit test cases. Aya’s integration test demonstrates that the decision disappears when the test process returns to root and reappears after moving back. [27] |
| Program return | Use cgroup-LSM boolean grant semantics plus return-value helpers where applicable; do not reuse MAC errno code verbatim. [14] [28] |
| Version support | Require kernel >= 6.0 as Aya’s documented baseline; test architecture-specific attachment support. Aya carries an aarch64 pre-6.4 attach caveat. [13] [27] |
| Cgroup v2 lifecycle | Attach against a durable cgroup FD owned by the control plane; monitor link and cgroup deletion. |
| Scope escape | Define whether descendant cgroups, root cgroup processes, service managers, and privileged maintenance processes are deliberately covered. |

## 6. Aya and Rust implementation notes

Aya provides two relevant program wrappers: `aya::programs::Lsm` for global MAC attachment and `aya::programs::LsmCgroup` for cgroup attachment. In the current source, `Lsm::load(hook, &btf)` finds the BTF function named `bpf_lsm_<hook>`, loads `BPF_PROG_TYPE_LSM` with `BPF_LSM_MAC`, then `attach()` returns an `LsmLinkId`. `LsmCgroup::load` uses `BPF_LSM_CGROUP`; `attach(cgroup_fd)` creates a managed link. The source also states that dropping a loaded `LsmCgroup` detaches managed links, while pinning can retain an object beyond the parent process. [11] [13]

| Aya surface | Correct use | Caveat |
|---|---|---|
| `#[lsm(hook = "file_open")]` | Global BPF-LSM MAC policy/audit hook. | Minimum documented kernel is 5.7; still feature-probe BTF, active `bpf` LSM, hook, and helpers. [7] [11] |
| `#[lsm(sleepable, hook = "…")]` | Request Aya’s `lsm.s/<hook>` section for a sleepable BPF LSM program. | The kernel has a whitelist of sleepable hooks. `sleepable` is not a permission to sleep at every hook. [6] [29] |
| `#[lsm_cgroup(hook = "…")]` | Per-cgroup LSM attachment. | Minimum documented kernel is 6.0 and semantics differ from MAC attachment. [7] [13] |
| `LsmContext::arg::<T>(n)` | Read native LSM arguments beginning at zero and the synthetic final prior result. | The exact index is hook-specific; generated `vmlinux`/CO-RE types must match target BTF. [12] |
| `Btf::from_sys_fs()` | Obtain target BTF for load-time hook resolution. | Make failure an installation/preflight error, never an unreported fallback. [11] |
| `Lsm::attach()` / `LsmCgroup::attach()` | Maintain the returned link ID and define ownership/detach. | A dropped link can alter enforcement. Persisting/pinning is a security lifecycle choice, not an implementation detail. [11] [13] |

Rust’s `Result<T, E>` encourages acknowledging recoverable failures. Apply that principle to the **user-space loader/control plane**: distinguish an unsupported kernel, missing `bpf` LSM activation, verifier rejection, map-schema incompatibility, and telemetry consumer failure. Do not use `unwrap()` in a production loader for BTF, map pins, link attachment, or configuration parsing. In BPF-side no-std code, avoid panics and loops that make an enforcement decision unavailable; turn expected lookup and transport failures into explicit reason codes and the selected fail-mode behavior. [30]

## 7. Policy-map lifecycle and rollback

BPF maps share policy data between user space and BPF programs. The `bpf()` API creates, looks up, updates, and deletes map elements. A program holds references to maps it uses; a map/object persists only while referenced by a file descriptor, attachment/program, or a bpffs pin. `BPF_OBJ_PIN` adds a filesystem reference in bpffs, and `BPF_OBJ_GET` reopens it. `BPF_LINK_CREATE` returns a manageable attachment link. [31] [32]

This lifecycle changes the security posture. An accidental pin can keep an old policy alive; an accidental unpin or dropped link can remove enforcement. Therefore, policy storage needs the same change control as firewall rules.

### 7.1 Recommended two-generation rollout

Use an outer selector (for example, a one-element array map) that identifies the active immutable policy generation. Populate and validate a new inner policy map before atomically switching the selector. Retain the prior generation long enough to roll back. Events must include the selected generation.

```text
control plane:
  validate signed/configured policy input
  build generation N+1 map off-path
  verify schema, capacity, and sample lookups
  atomically switch active_generation := N+1
  observe decision/telemetry health
  retire generation N only after rollback window

data plane:
  read active_generation once
  look up policy in selected map
  decide and emit event stamped with generation
```

This pattern avoids a partially populated map becoming the active policy. It also makes a telemetry event useful after the fact: the operator can retrieve the exact policy generation that made the decision.

### 7.2 Pin only named, versioned objects

If bpffs pinning is used, pin under a root-owned directory with restrictive permissions and names that encode environment, schema, and generation. Maintain a manifest containing map type, key/value layout version, program hash/build ID, intended hook, link, attach mode, cgroup target when applicable, and policy generation. Startup should refuse to reuse a pinned map whose schema or expected hook differs; it should not reinterpret bytes opportunistically.

A clean shutdown is not the only lifecycle event. Test reboot behavior, loader restart, service-manager restart, bpffs mount availability, upgrade with old pins, and emergency detach. Do not create “permanent” enforcement merely because an object is pinned; persistence, authorization to alter pins, upgrade, and recovery must be separately designed and approved.

## 8. Verifier and correctness traps

The verifier explores possible execution paths, tracks pointer and scalar types, bounds, stack initialization, helper argument constraints, and references. It resets R1–R5 after a helper call and preserves R6–R9; map lookup returns `PTR_TO_MAP_VALUE_OR_NULL` until a null check proves otherwise. It also rejects uninitialized stack reads, invalid pointer arithmetic, invalid context accesses, and unbalanced tracked references. These are security properties, not incidental compiler inconveniences. [33]

| Trap | Why it happens | Defensive pattern |
|---|---|---|
| Dereferencing a map lookup result before checking it | Lookup may return `NULL`; verifier labels it `map_value_or_null`. | `if let Some(rule) = lookup(...)` / null-check before any field access. [33] |
| Reading a kernel pointer after a helper without preserving it | R1–R5 are caller-saved/reset by verifier model. | Keep safe values in R6–R9 through compiler-friendly local structure, or reload/revalidate after helper. [33] |
| Uninitialized event/key stack bytes | BPF stack reads are permitted only after initialization. | Zero-initialize fixed-size keys/events before passing their address to helpers. [33] |
| Ring-buffer reservation leak | `reserve` returns a tracked reference. | Every successful reservation reaches exactly one commit or discard on all branches. [25] |
| Returning an invalid LSM value | Verifier limits ordinary int LSM returns to `[-MAX_ERRNO, 0]`; boolean hooks are `[0, 1]`. | Use `0` and named negative errno values; inspect exceptional hook types. [6] |
| Assuming every kernel field/helper is readable | BTF context access and helper allowlists are program/hook dependent. | Generate/load target BTF, use CO-RE/bindings, and retain verifier logs. [1] [6] |
| Calling a sleep-capable operation at a non-sleepable hook | Only an explicit kernel whitelist is sleepable. | Use `#[lsm(sleepable)]` only for a supported hook and measure its latency. [6] [29] |
| Complex unbounded policy parsing in BPF | Modern kernels support more loop forms than old documentation once implied, but verifier complexity and target support are still version-sensitive. | Parse/compile policy in user space; use fixed-size keys, bounded data, and simple branch structure. |
| Treating a user pointer as kernel data | Some hook arguments, such as an ioctl `arg`, may represent a userspace pointer. | Never dereference it as a kernel pointer; use a safer hook/context. [3] |
| Recursing through an LSM-visible API | Filesystem metadata retrieval can re-enter LSM paths. | Prefer documented BPF LSM kfuncs and understand their recursion constraints. [21] |

A production loader should capture the verifier log at a suitable log level and persist it with the build ID, kernel release, BTF ID/hash, enabled LSM list, and policy generation. The log is a deployment artifact and a debugging aid; do not silently retry a rejected program by loading a weaker policy.

## 9. Portability risks and cautious language for the book

### 9.1 Risk register

| Topic | Invariant | Version/distribution-sensitive aspect | Safe book wording |
|---|---|---|---|
| BPF LSM | A compiled/active BPF LSM is required. | Config prerequisites, BTF, lockdown, privileges, and hook availability vary. | “Require and verify BPF LSM on the target kernel.” |
| Base LSM support | Aya documents 5.7 minimum. | Backports may differ; a hook can still be disabled. | “Aya documents 5.7 as the minimum; feature-probe your hook.” [7] |
| Cgroup LSM | It is a separate attach type and uses cgroup aggregation. | Aya documents 6.0; aarch64 older than 6.4 has an Aya-tested attach caveat. | “Treat cgroup LSM as a separately tested feature.” [13] [27] |
| LSM order | Active list order matters to checks. | Boot configuration and distro defaults differ. | “Record `/sys/kernel/security/lsm` and treat it as policy input.” [2] [8] |
| `file_open` | It receives a `struct file *` and can deny the open. | Exact field layouts and surrounding VFS sequence can change. | “Use target BTF/CO-RE; do not hard-code offsets or broad coverage claims.” [15] [20] |
| File identity | Inode number is unique only within a filesystem. | Overlay, network, pseudo, FUSE, inode generation, device fields differ. | “Key by a verified filesystem/superblock discriminator plus inode; classify unsupported filesystems.” [23] [24] |
| Filesystem helpers/kfuncs | Some are restricted to BPF LSM and avoid recursion. | Availability and helper ABI are evolving. | “Feature-probe; provide an explicit degraded path.” [21] |
| Ring buffer | Full buffer makes reservation fail without blocking. | Buffer sizing and consumer scheduling are operational. | “Count drops and never change authorization because telemetry is full.” [25] |
| NixOS LSM setting | `security.lsm` constructs an ordered `lsm=` list in current Nixpkgs. | Defaults and ordering comments can change by channel. | “Pin/review the Nixpkgs revision and test the effective boot list.” [18] |

### 9.2 Exact claims that require qualification

Do **not** write any of the following without its qualification.

| Overbroad claim | Correct, cautious replacement |
|---|---|
| “BPF LSM works on Linux 5.7+.” | “Aya documents 5.7 as the minimum for its LSM feature, provided the kernel configuration, BTF, active LSM list, requested hook, privileges, and architecture support are sufficient.” [7] |
| “`file_open` protects the file.” | “`file_open` can gate the VFS open operation for the resolved `struct file`; analyze other access and execution paths for the stated asset.” [15] [20] |
| “Return zero to allow in every BPF LSM program.” | “For ordinary MAC-style LSM hooks, zero allows and a negative errno denies; cgroup LSM uses distinct boolean grant aggregation.” [6] [14] |
| “The previous `ret` contains every LSM’s verdict.” | “It carries the previous BPF-LSM program result in the BPF chain. An earlier non-default ordinary LSM result may prevent BPF LSM from running at all.” [1] [9] |
| “An inode number identifies a file.” | “An inode number is unique within a filesystem; pair it with a verified filesystem/superblock discriminator and define rename/hard-link/overlay behavior.” [24] |
| “A path is the file identity.” | “A path is resolved through process root, mount namespace, symlink, and mount topology; use it as context, not a primary authorization key.” [22] |
| “Pinning makes a policy safely persistent.” | “Pinning retains a BPF object reference. Safe persistence also requires access control, compatibility, monitoring, upgrade, and recovery design.” [32] |
| “Ring-buffer audit records are Linux Audit records.” | “Ring-buffer records are application-managed security telemetry unless separately integrated with the Linux Audit pipeline.” |

## 10. Capstone: workload-scoped protected-file opening policy

### 10.1 Threat model

The capstone defends a service workload against **accidental or unauthorized opens of a small set of high-value configuration, credential, or signing-material files**. The operator controls the host boot configuration, BPF loader, bpffs policy directory, and policy source. The workload may contain a compromised application process that tries to open protected host-visible objects through alternate pathnames, symlinks, or hard links. The capstone does not claim to defend against a host administrator, a kernel compromise, an attacker that can replace the BPF policy/link, or a filesystem implementation that cannot provide the selected identity fields.

| Asset | Adversary action | Control | Residual risk |
|---|---|---|---|
| Protected regular-file object | Open it using an alternate hard link or renamed pathname. | Inode/superblock-based `file_open` identity, not path matching. | Overlay/lower/upper semantics need a separate policy decision. |
| Service availability | Trigger an unintended broad deny through missing policy or noisy telemetry. | Observe-first rollout, fixed fail modes, bounded event transport, generation swap and rollback. | Incorrect scope inventory can still cause expected-but-undesired denial. |
| Decision evidence | Exhaust event buffer to hide individual events. | Ring-buffer drop counter, health alert, independent policy decision. | Individual event loss remains possible; authorization must not depend on logging. |
| Policy integrity | Reuse an incompatible or stale pinned map. | Schema/version manifest, generation field, restrictive bpffs permissions, startup refusal. | Privileged control-plane compromise is out of scope. |
| Workload isolation | Move a process outside cgroup scope. | Prefer global policy for the first capstone; if cgroup LSM is required, test cgroup migration and hierarchy. | Cgroup management is part of the trusted control plane. |

### 10.2 Capstone architecture and milestones

1. **Inventory.** Define exactly which regular-file objects are protected, permitted service identities/workloads, intended filesystems, expected operations, recovery owner, and denied-operation impact.
2. **Identity probe.** Build an audit-only `file_open` program that records object class plus the proposed non-pointer key. Validate hard-link and rename behavior in a disposable VM; explicitly record overlay/FUSE/network/pseudo outcomes.
3. **Policy compiler.** In user space, turn approved inventory into a versioned map generation. Validate fixed key/value sizes, policy key collisions, capacity, filesystem class, and schema version before loading.
4. **Observe mode.** Run normal workload and maintenance tests. Measure matching volume, missing-rule events, identity-unsupported events, ring-buffer drops, and startup/reload behavior. Do not enable enforcement while these signals are unexplained.
5. **Enforce a narrow deny.** Turn on enforcement for one protected object and one workload. Require a negative expected open test, an allowed service test, a hard-link/rename test, and a rollback drill.
6. **Lifecycle drill.** Test loader restart, link detach detection, reboot, bpffs pins, map-generation upgrade, policy rollback, and a full ring buffer. Verify that every condition produces the declared decision and telemetry health signal.
7. **Optional cgroup phase.** Only after global logic is proven, attach a cgroup LSM variant and add hierarchy/migration tests; retain a separate return-semantics test suite.

### 10.3 Acceptance criteria

The capstone is complete when it can demonstrate, in an isolated test environment, that: (a) an alternate pathname to the same inode receives the same policy result; (b) an unrelated inode on the same or another filesystem does not collide; (c) a prior BPF-LSM denial remains a denial; (d) missing policy and unsupported identity produce the documented fail mode and reason code; (e) telemetry loss never changes the enforcement return; (f) the active map generation is visible in every decision event; and (g) detach/rollback is observable and practiced.

## 11. Source audit and references

All numbered references below were opened and read during this research. Kernel documentation and source were prioritized; Aya Book/Aya source, NixOS manuals/options/source, Rust documentation, and Linux man-pages were also read. The two duplicate forms of a source (for example, a documentation page and its source file) are retained where each was used to verify an API or implementation detail.

[1]: https://docs.kernel.org/bpf/prog_lsm.html "LSM BPF Programs"
[2]: https://docs.kernel.org/security/lsm.html "Linux Security Modules: General Security Hooks for Linux"
[3]: https://docs.kernel.org/security/lsm-development.html "Linux Security Module Development"
[4]: https://man7.org/linux/man-pages/man7/path_resolution.7.html "path_resolution(7) — how a pathname is resolved"
[5]: https://man7.org/linux/man-pages/man7/inode.7.html "inode(7) — file inode information"
[6]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/bpf_lsm.c "Linux kernel source: kernel/bpf/bpf_lsm.c"
[7]: https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.lsm.html "Aya `#[lsm]` attribute macro"
[8]: https://docs.kernel.org/admin-guide/LSM/index.html "Linux Security Module Usage"
[9]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/security/security.c "Linux kernel source: security/security.c"
[10]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/Kconfig "Linux kernel source: kernel/bpf/Kconfig"
[11]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/programs/lsm.rs "Aya source: global LSM program loader"
[12]: https://raw.githubusercontent.com/aya-rs/aya/main/ebpf/aya-ebpf/src/programs/lsm.rs "Aya source: LsmContext"
[13]: https://raw.githubusercontent.com/aya-rs/aya/main/aya/src/programs/lsm_cgroup.rs "Aya source: cgroup LSM program loader"
[14]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/cgroup.c "Linux kernel source: kernel/bpf/cgroup.c"
[15]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/lsm_hook_defs.h "Linux kernel source: LSM hook definitions"
[16]: https://aya-rs.dev/book/programs/lsm.html "Aya Book: LSM"
[17]: https://man7.org/linux/man-pages/man7/capabilities.7.html "capabilities(7) — Linux capabilities"
[18]: https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/security/default.nix "Nixpkgs source: security.lsm configuration"
[19]: https://nixos.org/manual/nixos/stable/options.html#opt-boot.kernelParams "NixOS option: boot.kernelParams"
[20]: https://raw.githubusercontent.com/torvalds/linux/master/fs/open.c "Linux kernel source: fs/open.c"
[21]: https://docs.kernel.org/bpf/fs_kfuncs.html "BPF filesystem kfuncs"
[22]: https://man7.org/linux/man-pages/man7/path_resolution.7.html "path_resolution(7) — how a pathname is resolved"
[23]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/fs.h "Linux kernel source: struct inode fields"
[24]: https://man7.org/linux/man-pages/man7/inode.7.html "inode(7) — file inode information"
[25]: https://docs.kernel.org/bpf/ringbuf.html "BPF ring buffer"
[26]: https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.lsm_cgroup.html "Aya `#[lsm_cgroup]` attribute macro"
[27]: https://raw.githubusercontent.com/aya-rs/aya/main/test/integration-test/src/tests/lsm.rs "Aya integration tests: LSM and cgroup LSM"
[28]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/helpers.c "Linux kernel source: cgroup return-value helpers"
[29]: https://raw.githubusercontent.com/aya-rs/aya/main/aya-ebpf-macros/src/lsm.rs "Aya source: `#[lsm]` macro expansion"
[30]: https://doc.rust-lang.org/book/ch09-00-error-handling.html "The Rust Programming Language: Error Handling"
[31]: https://docs.kernel.org/bpf/maps.html "BPF maps"
[32]: https://docs.kernel.org/userspace-api/ebpf/syscall.html "eBPF syscall documentation"
[33]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier"
[34]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — perform a command on an extended BPF map or program"
[35]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) — list of eBPF helper functions"
[36]: https://man7.org/linux/man-pages/man2/stat.2.html "stat(2) — get file status"
[37]: https://codebrowser.dev/linux/linux/security/bpf/hooks.c.html "Linux kernel source: security/bpf/hooks.c"
[38]: https://codebrowser.dev/linux/linux/kernel/bpf/bpf_lsm.c.html "Linux kernel source browser: kernel/bpf/bpf_lsm.c"
[39]: https://codebrowser.dev/linux/linux/include/linux/lsm_hook_defs.h.html "Linux kernel source browser: include/linux/lsm_hook_defs.h"
[40]: https://codebrowser.dev/linux/linux/kernel/bpf/trampoline.c.html "Linux kernel source browser: kernel/bpf/trampoline.c"
[41]: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/security/apparmor.nix "Nixpkgs source: AppArmor module"
[42]: https://nixos.org/manual/nixos/stable/release-notes "NixOS stable release notes"
[43]: https://github.com/aya-rs/aya/blob/main/aya/src/programs/lsm.rs "Aya GitHub source: global LSM program loader"
[44]: https://raw.githubusercontent.com/aya-rs/aya/main/aya-ebpf-macros/src/lsm_cgroup.rs "Aya source: `#[lsm_cgroup]` macro expansion"
[45]: https://codebrowser.dev/linux/linux/include/linux/fs.h.html "Linux kernel source browser: include/linux/fs.h"
[46]: https://codebrowser.dev/linux/linux/security/security.c.html "Linux kernel source browser: security/security.c"

### Sources opened but not relied on for a unique chapter claim

For audit completeness, the following full sources were also opened and read during the research pass. They corroborate the references above or informed source navigation: [the `BPF_PROG_TYPE_LSM` Aya macro page][7], [Aya LSM Cgroup macro page][26], [the current Aya source macros][29] [44], [the current NixOS AppArmor module][41], [the NixOS release notes][42], [the Linux `bpf(2)` manual][34], [the BPF helper manual][35], [the current Linux source-browser views][37] [38] [39] [40] [45] [46], and [the `stat(2)` manual][36].

**Final defensive boundary:** This dossier intentionally excludes stealth, evasion, persistence, offensive deployment, and instructions to bypass platform controls. It is a guide to reviewed, observable, least-privilege enforcement on systems the operator is authorized to administer.
