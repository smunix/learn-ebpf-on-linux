# Verifier, BTF, CO-RE, and Portability

**Book-research dossier — Linux eBPF**
**Author:** Providence Salumu
**Research cut:** 10 September 2026
**Audience:** Advanced beginners who need a correct mental model before writing production eBPF in Rust/Aya or another loader.

## Executive position

An eBPF program is not accepted because it looks safe to its author. It is accepted only when the **target kernel’s verifier** can prove safety for every feasible control-flow path under that program type’s context, memory, helper, and resource rules. This is best introduced as **abstract interpretation**: the verifier executes an abstract model of the program, tracking possible types and value ranges rather than one concrete runtime input. The practical implication is that source-code intent is insufficient. The program must make bounds, nullness, initialization, ownership, and loop termination *provable in the bytecode and along every path*. [1] [2]

**BTF** is typed metadata. **CO-RE** (Compile Once—Run Everywhere) uses local object-file BTF plus the running kernel’s BTF to rewrite selected BPF instruction immediates or offsets before the program is loaded. It addresses a central portability problem—kernel type layout drift—but it is not a general compatibility guarantee. It cannot make an absent helper, attach point, program type, kernel configuration, permission, tracepoint field, or semantic contract appear. [3] [4] [5]

The book should make defensive engineering the default: start with a conservative program, probe the deployment host, select an explicitly supported capability tier, preserve diagnostics, and fall back to a less invasive telemetry path when requirements are absent. **Never treat a kernel version string, a successful build, or an unverified “CO-RE” label as a proof that a program can load and attach.** [2] [20]

> **Core rule for readers:** Write the evidence the verifier needs, then verify the host capabilities the loader needs. Those are separate jobs.

## 1. Scope, terminology, and evidence boundary

This dossier covers verifier reasoning, registers and pointers, scalar ranges, the 512-byte stack constraint, bounded loops, helper contracts by program type, verifier logs, BTF, CO-RE relocations, layout drift, tracepoint ABI risk, feature probing, and graceful fallback. It intentionally does **not** teach concealment, persistence, evasion, or offensive deployment. The worked design advice is for observable, fail-safe monitoring tools.

The **invariants** in this dossier are architectural or documented contracts that authors should design around. The **version-dependent** items are capabilities, limits, available helpers, program/attach types, kernel configuration, distribution policy, toolchain behavior, and public library APIs that must be tested on the actual target. Kernel documentation itself cautions that only an attempted load establishes acceptance for a particular program and host. [2]

The source cut included current upstream Linux documentation and source, Linux manual pages, Aya documentation and source, Rust documentation, and NixOS documentation. Upstream Aya was inspected at commit `0e353a7fddf80091ae2fb2dacc08ec1d861e67cc` (10 September 2026); the live crates.io query reported `aya` **0.14.0**. Exact Aya examples below are therefore labelled as source-cut-specific rather than timeless API promises. [13] [14]

## 2. The verifier as abstract interpretation

### 2.1 A usable model

At each instruction, the verifier maintains an **abstract state**. That state records what every register and relevant stack slot may be, not one exact runtime value. A useful beginner model is:

| Concrete question at runtime | Verifier’s abstract evidence | Why the program is accepted or rejected |
|---|---|---|
| “Is this register initialized?” | Register state such as `NOT_INIT` versus a scalar or pointer state | Reading an unwritten register is rejected. |
| “Could this integer be an unsafe offset?” | Signed and unsigned minima/maxima plus a bitwise tracked-number (`tnum`) representation | A pointer access is allowed only if every possible offset remains safe. |
| “Could this map lookup return null?” | `PTR_TO_MAP_VALUE_OR_NULL`, refined separately on each conditional branch | Dereference is allowed only in the proven non-null branch. |
| “Is this stack buffer real and initialized?” | Stack bounds and per-byte/slot initialization/provenance information | Helper input and stack reads require initialized, in-bounds memory. |
| “Does the loop terminate within analysis limits?” | State evolution across the back edge, branch/state exploration, and complexity limits | A loop with an unprovable or impractical bound is rejected. |

The verifier conducts control-flow and instruction/state analysis, visiting possible paths and pruning a new state only when a previously accepted state at the same instruction is at least as safe. Liveness tracking helps it ignore values that cannot affect later execution. This is why two source-level programs with the same apparent behavior can differ sharply: the version with clear control flow and explicit checks supplies more usable proof. [1]

Older verifier documentation describes an initial control-flow pass as rejecting loops. That must not be reproduced as a current universal rule. Bounded-loop verification was introduced by upstream commit `2589726d12a1`; contemporary kernels can simulate and validate eligible loops. The durable teaching claim is narrower: **infinite loops and loops whose termination or analysis cost cannot be established are rejected; write a simple, explicit finite bound.** [12] [2]

### 2.2 Registers: calling convention and state transitions

The portable BPF ABI defines ten 64-bit general-purpose registers and a read-only frame-pointer register. `R0` is the return/exit value, `R1`–`R5` carry call arguments and are caller-saved scratch registers, `R6`–`R9` are callee-saved, and `R10` is the read-only frame pointer used to address stack storage. An eBPF program must initialize `R0` before `EXIT`. [6] [2]

At entry, `R1` has the program type’s context pointer type, conventionally described as `PTR_TO_CTX`. The context’s accessible fields are not universal; program-type-specific verifier operations define the permitted accesses. A move copies a pointer’s abstract type. Invalid pointer algebra does not create a new safe pointer: for example, adding one pointer to another yields a scalar-like value rather than a pointer that can be dereferenced. [1]

A helper or other kernel function call is a major state boundary. The verifier checks each call against the helper prototype, then makes `R0` the documented abstract return type and marks `R1`–`R5` unreadable. Preserve a needed value or a valid pointer in `R6`–`R9`, or spill it correctly, before the call. This is both a stable ABI convention and a frequent load-time failure. [1] [6]

### 2.3 Pointers are capabilities, not integers

The verifier gives pointer values a base-specific type. Kernel documentation illustrates `PTR_TO_CTX`, constant map pointers, map-value pointers, stack pointers, packet pointers and packet-end pointers, plus nullable and reference-counted socket-related pointers. Current kernels have additional internal types, so the book should teach the **category and discipline**, not attempt to freeze a complete enum as a public API. [1]

Pointer state normally carries a base, a known fixed offset, possible variable offset information, alignment, an identity relationship to copies, and sometimes an accessible range. A pointer can be used only for operations the verifier recognizes for its category and only within the bound it has proved. A **scalar is never a dereferenceable pointer merely because its bit pattern might be an address**. [1]

For direct packet access, retain a data pointer and a packet-end pointer, form the candidate end of the intended read, compare it with packet end, and dereference only on the safe fall-through branch. The documented examples show that the verifier propagates a proved range to related packet pointers. It also shows why arithmetic with overly broad variable offsets can prevent a later packet-end comparison from establishing a safe range. [1]

### 2.4 Scalar ranges and branch refinement

A scalar state is not “unknown beyond use.” The verifier stores unsigned lower/upper bounds, signed lower/upper bounds, and a `tnum` that records known and unknown bits. A conditional comparison refines the range per branch. For example, after `x > 8`, the true branch has an unsigned minimum of 9 and the false branch an unsigned maximum of 8. Signed comparisons refine signed bounds; compatible signed and unsigned facts can combine. [1]

This explains a crucial coding rule: **sanitize once, branch, and use the sanitized value only in the branch whose predicate proves the intended property.** Do not cast or reorder arithmetic in a way that loses the relation between the checked scalar and the later pointer offset. For a variable index, explicitly establish a non-negative upper bound that leaves room for the entire access, then perform the access with that same value.

### 2.5 Null and reference discipline

`bpf_map_lookup_elem()` is the canonical example. Its return is a nullable map-value pointer. A null check refines the non-null path to a usable map-value pointer. Every dereference must be dominated by that check; the other branch must return or avoid the access. The verifier documentation includes the expected failure: `R0 invalid mem access 'map_value_or_null'`. [1] [21]

Some helpers return references that require release. The verifier tracks this ownership state, and a program exits only if all required references have been released along every path. The documented socket lookup example is rejected with `Unreleased reference`. The pedagogical point is broader than sockets: **pair every acquisition with its verifier-recognized release, and make both the failure path and every early return ownership-complete.** [1]

## 3. Memory and control-flow constraints

### 3.1 The 512-byte stack: use it as a strict budget

Upstream currently defines `MAX_BPF_STACK` as **512 bytes**, and the design Q&A states that all program types are limited to 512 bytes while the verifier computes actual use. Treat this as a small, hard eBPF stack budget, not as ordinary process stack memory. The verifier allows stack reads only after a write and requires each helper-visible input byte to be initialized. [9] [2] [1]

| Safe design choice | Reason |
|---|---|
| Put only small fixed keys, headers, and temporary scalars on the stack. | The verifier can see fixed, initialized regions easily. |
| Use a per-CPU map or another suitable map for a larger reusable scratch buffer. | It avoids exhausting the eBPF stack; Aya’s tracepoint example uses a per-CPU array for a 4096-byte filename buffer for this reason. [18] |
| Initialize the whole region a helper will read, including padding if the helper’s size covers it. | A pointer in bounds is insufficient when an indirect helper read reaches uninitialized bytes. [1] |
| Measure generated stack use in the object/disassembly and retain a verifier-log test. | Rust/C source size is not a reliable measure of emitted stack use. |

Do not promise readers that a nested BPF function gives a fresh, freely usable 512-byte application budget. The current verifier tracks combined stack depth and call frames internally; implementation limits and compiler allocation can change. Design well below 512 bytes and validate the emitted object on the oldest target kernel. [10] [9]

### 3.2 Loops: bounded is necessary, cheap to analyze is better

Bounded loops have been available in mainline since Linux 5.3 through the upstream verifier change cited above. This does **not** mean every syntactically finite Rust `for` loop will load everywhere. The verifier must establish termination while exploring paths, and the analysis itself is bounded. The current upstream source has a maximum pending jump-sequence limit of 8192 and a per-instruction explored-state heuristic limit of 64; other internal limits and heuristics may evolve. The BPF design Q&A identifies a one-million-instruction analysis ceiling and explicitly says a complex program can encounter limits even when its static source looks small. [12] [10] [2]

Teach the following loop pattern rather than a version-specific numeric maximum:

1. Use a **small, compile-time maximum** for work per event.
2. Maintain an obvious monotonic counter.
3. Gate the loop with a checked runtime length or count.
4. Avoid branches inside the loop whose independent states multiply with each iteration.
5. Stop safely when input is shorter, malformed, or exceeds the processing budget.

For example, a defensive packet parser can examine at most a small fixed number of extension records and record “truncated/too complex” rather than attempting unbounded parsing. A monitoring program should prefer a bounded incomplete observation to a verifier rejection or excessive event-path cost.

### 3.3 Complexity is not just instruction count

The verifier explores path states. A small static program with nested conditionals, variable offsets, and a loop can create many distinct register/stack states. Conversely, a larger straight-line program may verify quickly. The upstream source reports metrics such as processed instructions, maximum states per instruction, total states, and peak states, which are useful diagnostics but not a portable performance API. [10]

**Design advice:** split independent policy alternatives into separate small programs or capability tiers where the attachment model allows it. Use early returns after rejection conditions. Keep pointer checks close to their dereferences. Avoid a large “do everything” handler that combines parsing, filtering, aggregation, and optional features behind many branches.

## 4. Helpers: contracts depend on program type

Helpers are a kernel-provided, allow-listed interface rather than arbitrary kernel calls. The `prog_type` establishes both the context layout and the subset of helpers the verifier may permit. A tracing program and a socket-filter program can have different contexts and helper sets; the available set may grow on future kernels. The kernel Q&A is direct: programs may call only helpers or kfuncs exposed to their type, and the set is defined for each program type. [20] [21] [2]

A helper call must satisfy **all** of these conditions:

| Contract component | What the verifier requires | Defensive consequence |
|---|---|---|
| Program and attach type | The helper is available for that exact type/attach context on this kernel. | Probe or load a minimal variant; do not infer availability from another type. |
| Argument count and positions | BPF calling convention provides at most five register arguments. | Keep helper invocation layouts simple and use supported structures/maps for additional state. [21] [6] |
| Argument abstract type | A map pointer, initialized stack pointer, context pointer, map value, scalar, or other required category matches the prototype. | Keep typed pointers intact; do not cast them through integers. |
| Range/alignment/initialization | The whole helper-read or helper-write region is valid, aligned where required, and initialized before an indirect read. | Initialize keys and output buffers deliberately; size access exactly. |
| Return type and lifetime | Nullable values are checked; reference-bearing values are released on every exit path. | Code error branches first; keep resource lifetimes short. |

The Linux manual page is valuable for helper purpose and return contracts, but it is not a substitute for an on-target availability test. `bpftool feature probe` can report helpers and program types supported by the current kernel; its output must be collected using the same privileges as the eventual service. [21] [20]

**Cautious wording for the book:** say “the verifier may permit this helper for this program type on a kernel that implements it,” not “this helper is available to eBPF programs.” Kfuncs need even more caution: kernel documentation says they are not a stable API. [2]

## 5. Reading verifier logs as proof failures

### 5.1 What the log is and is not

`BPF_PROG_LOAD` can supply `log_level`, `log_size`, and `log_buf`. The kernel writes a multi-line verifier log explaining why it considered a program unsafe. `log_level = 0` disables it; an undersized buffer can produce `ENOSPC`. The bpf(2) page warns that log format can change as the verifier evolves. Therefore, diagnostics should be retained for humans and test artifacts, but parsers must not depend on exact message grammar. [20]

Current upstream UAPI also includes `log_true_size` in the program-load attributes, which can report the actual total log content size including a terminating zero even if the supplied buffer was truncated. This is a current source fact, not a promise that every deployed loader exposes it. [11]

A good diagnostic protocol is:

1. In CI and staging, request verbose verifier output and verifier statistics.
2. Preserve the kernel release, architecture, loader version, object SHA-256, BTF availability, program/attach type, effective privilege context, and full log.
3. Reduce a failure to the first invalid instruction and reconstruct the proof obligation from its incoming register state.
4. Fix the program’s proof, not the log string. Re-run on the oldest supported kernel and the target distribution configuration.

### 5.2 Common messages and the underlying repair

| Representative verifier result | Likely violated proof | Safer repair |
|---|---|---|
| `R2 !read_ok` or `R0 !read_ok` | An unwritten register was read, or the program exits without a defined return value. | Initialize before reading and return a defined program-type-appropriate value. [1] |
| `invalid stack off=...` | Access is above `R10`, outside `[-MAX_BPF_STACK, 0)`, or otherwise not a valid stack region. | Recompute the fixed offset; reduce local storage; move large state to a map. [1] |
| `invalid indirect read from stack` | A helper would read stack bytes not proved initialized. | Write every byte of the key/buffer the helper may read. [1] |
| `map_value_or_null` | A nullable map lookup result was dereferenced without a path-dominating null check. | Check for null and dereference only in the non-null path. [1] |
| `misaligned access` | The pointer’s proven alignment does not satisfy the access width. | Use an aligned local, byte-wise access where allowed, or reshape arithmetic so alignment is provable. [1] |
| `Unreleased reference` | A reference-returning helper’s result reaches an exit path without its required release. | Null-check, release on all non-null paths, and structure clean-up before each return. [1] |
| “too complex” or processed-instruction limit failure | State/path exploration is too expensive, commonly from a large bound or branchy loop. | Lower the bound; simplify branches; split the work; retain a safe truncation result. [2] [10] |

The log is especially useful because it prints abstract register states such as `ctx`, `fp`, `map_value_or_null`, scalar ranges, pointer offsets, and safe packet ranges. Teach readers to read it as a state snapshot immediately *before* the rejected instruction, not as a compiler error location alone. [1]

### 5.3 Aya-specific diagnostic control

At the September 2026 source cut, Aya’s current public loader is `aya::EbpfLoader`; the historical `BpfLoader` type alias is deprecated. `EbpfLoader::verifier_log_level` accepts `VerifierLogLevel`. Public flags include `DISABLE`, `DEBUG`, `VERBOSE`, and `STATS`; current Aya source defines `VERBOSE` as verbose logging plus debug and defaults the loader to `DEBUG | STATS`. The documented usage is:

```rust
use aya::{EbpfLoader, VerifierLogLevel};

let mut loader = EbpfLoader::new();
loader.verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS);
let mut ebpf = loader.load_file("observer.bpf.o")?;
```

This configures Aya’s request to the kernel; it does not guarantee the host accepts the program. Pin the Aya version in the book’s companion project and check that version’s API documentation. [13] [17] [15]

## 6. BTF: typed metadata for observability and relocation

### 6.1 What BTF contains

**BPF Type Format (BTF)** is compact metadata for BPF programs and maps. It began as type information and was extended with function and source line information. Kernel documentation notes that BTF supports map pretty-printing, function signatures, source-annotated translated/JIT code, and source-aware verifier logs. BTF has a kernel API and an ELF-file interface; the kernel validates BTF data it receives. [3]

An object’s `.BTF` section contains type and string data. Its `.BTF.ext` section contains function information, line information, and—when present—CO-RE relocation records that require loader manipulation before program load. The current extensible `.BTF.ext` header has function-info, line-info, and optional CO-RE-relocation subsections. [3]

This distinction is important:

| BTF role | Producer/consumer | What it solves | What it does **not** solve |
|---|---|---|---|
| Local object BTF | BPF compiler → loader/kernel | Describes types associated with the object and enables source/function information. | It is not a description of the target kernel. |
| Target kernel BTF | Running kernel → loader | Describes that specific kernel’s types, commonly at `/sys/kernel/btf/vmlinux`. | It does not guarantee a relevant event/helper/attachment exists. [4] |
| BTF-aware maps/programs | Loader/kernel/tools | Allows typed map key/value and program metadata to be loaded and inspected. | It does not itself make a custom Rust type ABI-compatible without `repr(C)`/layout care. [3] [13] |

### 6.2 Aya BTF loading facts

Aya exposes `Btf::from_sys_fs()` to read `/sys/kernel/btf/vmlinux`, `Btf::parse_file(path, Endianness)`, and `Btf::parse(data, Endianness)`. In the inspected current Aya source, `EbpfLoader::new()` defaults to a system target-BTF source. It loads target BTF only when the object contains CO-RE relocations or typed kernel symbols. The public `btf(&Btf)` method sets explicitly supplied target BTF, while `btf_source` supplies a lazy parser callback that Aya caches after successful use. [16] [13]

A documentation-version trap deserves an explicit callout. A retrieved docs.rs page displays an `EbpfLoader::btf(Option<&Btf>)` signature and says `None` disables relocations, but the checked upstream 0.14.0 source at this research cut exposes `btf(&Btf)` and a default `System` target-BTF configuration. **Do not paste `.btf(None)` into a book example without pinning and compiling the exact Aya release used by that example.** The relevant loader source, not a floating “latest” page, is the authority for the pinned companion version. [15] [13]

If an object has CO-RE relocations, Aya’s current loader returns an error when target BTF cannot be obtained or relocations cannot be resolved. It does not silently convert such an object into a non-CO-RE program. Weak typed kernel symbols have distinct fallback handling, but that narrow behavior must not be represented as general CO-RE fallback. [13]

When embedding an object, `EbpfLoader::load(&[u8])` requires a four-byte-aligned buffer; Aya documents `include_bytes_aligned!` for static embedding. `load_file` reads the object then delegates to that loading path. [15] [13]

## 7. CO-RE: what relocation really changes

### 7.1 The layout-drift problem

Kernel internal structures can change field offsets, nesting, padding, field sizes, signedness, or existence across kernels and configurations. A program that embeds an offset compiled from one kernel’s headers may load on another but read the wrong bytes, or fail verification. Libbpf’s documented CO-RE model uses BTF recorded in the BPF object and BTF for the running kernel to match types and fields and patch relocatable data. The same fundamental mechanism is implemented by other loaders, including Aya’s object relocator. [4] [13] [14]

The appropriate claim is not “compile once, run everywhere.” State it as: **CO-RE can make supported BTF-described type accesses portable across compatible target layouts, provided the loader can obtain target BTF and resolve the object’s relocation requirements.** Aya’s project overview uses the broader phrase when paired with BTF and musl; readers must understand its operational prerequisites. [19] [14]

### 7.2 Where records live and what can be patched

CO-RE relocation records are **not ordinary ELF relocations**. They are encoded in `.BTF.ext`. A `bpf_core_relo` identifies an instruction offset, root local BTF type ID, string-table access description, and relocation kind. Field relocations patch an instruction offset; type and enum relocations patch an instruction immediate. Jump instructions should not be patched by CO-RE. [5] [3]

The current relocation kinds include field byte offset, size, existence, signedness, bitfield shifts; local/target type IDs, type existence, size, and match; and enum-value existence/value. This enables an object to ask factual target questions such as “does this field exist?” but only if the source and compiler emitted a corresponding relocation and the program is structured so the result controls a safe branch. [5]

A complete cross-version design has three layers:

1. **Local intent:** compile with correct BTF and CO-RE-aware accesses so the object records what it meant to read.
2. **Target reconciliation:** the loader reads the target BTF, matches types/fields, applies relocations, and reports failures rather than guessing.
3. **Feature behavior:** optional fields/enums are guarded; absent facilities route to a designed reduced-capability behavior.

### 7.3 What CO-RE cannot promise

| Risk outside CO-RE’s guarantee | Why BTF offset relocation is insufficient | Defensive response |
|---|---|---|
| Missing or disabled BTF | The loader has no target type graph to reconcile. | Select a BTF-free baseline object or a userspace telemetry fallback. Do not load the CO-RE object and hope. |
| Missing helper/map/program/attach type | This is an API/configuration capability, not a structure offset. | Probe and select a capability tier; use an alternative data path. [20] [21] |
| Changed kernel semantics | The same-named field can retain a compatible layout yet change meaning or lifetime assumptions. | Minimize reliance on internal fields; test behavior on each supported kernel family. |
| Absent trace event or changed event fields | An attachment and event-format contract is separate from `vmlinux` struct layout. | Discover the event and its live format before loading/attaching. [2] [18] |
| Raw tracepoint arguments | The UAPI explicitly makes no ABI guarantee for raw tracepoint arguments. | Avoid making raw argument layout a portable primary interface. [11] |
| Architecture/endianness/toolchain difference | BPF byte order, context conventions, emitted instructions, and host ABI details are not fixed by a field relocation. | Build/test appropriate `bpfel`/`bpfeb` artifacts as needed; run an architecture matrix. [8] |
| Privilege or resource policy | The BPF syscall, required capability/policy, memlock/memcg accounting, and LSM policy may deny loading. | Preflight with the production service identity and fail closed to a non-eBPF option. [20] [18] |

## 8. Tracepoints and ABI discipline

Tracepoints are static kernel instrumentation points. They are appealing for defensive observability because they avoid dynamic code-location selection and are discoverable under tracefs, commonly `/sys/kernel/tracing/events`. The kernel tracepoint documentation describes them as hooks with declared parameter prototypes. Aya’s tracepoint guide attaches a loaded `TracePoint` using `program.attach("category", "event")`. [7] [18]

However, the book must correct a tempting oversimplification. Aya’s tutorial calls tracepoints “stable,” whereas the Linux BPF Design Q&A explicitly answers **“NO”** to whether tracepoints are part of the stable ABI, because they are tied to implementation details and can change. The primary-kernel statement should control portability claims. Describe tracepoints as often more maintainable than kprobes for a chosen event interface, **not as a permanent ABI guarantee**. [18] [2]

The risk is strongest for raw tracepoints: the current BPF UAPI documentation says no ABI guarantees are made for the content of arguments exposed to a raw-tracepoint program. [11]

**Practical rule:** Never copy a tracepoint context offset from a tutorial into a portable tool. Aya’s own `sys_enter_execve` example marks filename offset 16 as a value to obtain from that event’s `format` file. At installation or startup, confirm the named category/event exists and examine the target’s tracefs format before enabling a layout-dependent variant. A missing event or incompatible field should select a documented reduced feature, not cause a crash or guessed read. [18]

Use `TracePointContext::read_at` only with a target-validated offset and a properly represented data type; preserve every `Result` error. For fields that are naturally represented as kernel types rather than event-data offsets, prefer an available BTF/CO-RE-aware design, but remember that it does not validate tracepoint existence or semantics.

## 9. Feature probing and capability tiers

### 9.1 Probe facts, not labels

`uname -r` is useful diagnostic metadata. It is a poor feature predicate because vendor kernels backport features, disable configuration options, and carry patches independently. Probe the executing kernel and deployment identity.

`bpftool feature probe [kernel]` inspects BPF syscall availability, JIT status, program types, helpers, and other eBPF parameters. `-j` emits JSON. `full` also probes helpers that may emit kernel warnings, so routine automated preflight should omit `full` unless there is a specific controlled diagnostic reason. `unprivileged` asks for the feature subset available to an unprivileged caller; the manual warns that using the wrong privilege context can misdetect support. `list_builtins` lists what *bpftool itself* knew when built, not what the running kernel supports. [22]

Suggested non-invasive preflight command:

```sh
bpftool -j feature probe kernel > /var/lib/my-observer/bpf-feature-report.json
```

The command can itself require access not granted to the production service. Treat a probe failure as data. A deployment check should execute the smallest safe load/attach test under the actual service account/capability/policy context, retain errors, detach immediately if it attached, and never assume the interactive administrator’s privileges match the service’s.

### 9.2 A deterministic startup decision tree

| Step | Test | If successful | If unsuccessful |
|---|---|---|---|
| 1 | Identify kernel, architecture, effective privilege/policy, and `bpftool` version for diagnostics. | Continue. | Report unsupported environment; do not elevate privileges automatically. |
| 2 | Run an on-target BPF capability probe where authorized. | Choose only reported candidate facilities. | Continue to a no-eBPF mode if that is a product requirement. |
| 3 | Read and parse `/sys/kernel/btf/vmlinux` if the selected object requires CO-RE. | Use target BTF with the CO-RE object. | Select a BTF-free baseline object or no-eBPF mode. [4] [16] |
| 4 | Verify the requested trace event exists and inspect its active `format` for required fields. | Enable its program variant. | Select an alternate event or omit this metric. [18] |
| 5 | Load the smallest selected object with preserved verifier diagnostics. | Attach only after load succeeds. | Categorize: verifier proof, missing helper/type, BTF relocation, permissions, memory/resource, or loader error. |
| 6 | Attach and conduct a bounded smoke observation. | Mark the feature active and export the chosen tier. | Detach/close the failed path and select its fallback. |

Cargo features help compile optional code into a binary, but they are **compile-time configuration**, not discovery of a running kernel capability. Cargo documents that features drive conditional compilation and optional dependencies, and its build scripts can emit checked custom `cfg` values. Use them to package `core`, `baseline`, and optional feature implementations; use runtime probes to select among them. [24] [23]

### 9.3 Graceful fallback means an intentional reduced service

A fallback is correct only when it is explicit, observable, and safe. It must not bypass the verifier, weaken bounds checks, infer unknown tracepoint layouts, or keep retrying privileged operations. A practical defensive telemetry product can have these tiers:

| Tier | Preconditions | What it collects | Failure behavior |
|---|---|---|---|
| A: CO-RE enriched | Target BTF, required program/helper/attach support, tested event format | Rich per-event metadata using CO-RE-safe kernel-type reads | Fall through to B if any prerequisite fails. |
| B: baseline eBPF | BPF support and a selected stable-enough event interface, but no target BTF-dependent object | Small fixed event record with no layout-dependent kernel-struct traversal | Fall through to C when load/attach is unavailable. |
| C: userspace observation | No eBPF prerequisite | Reduced aggregate counters or documented OS interfaces appropriate to the product | Clearly report coverage limitations. |
| D: unavailable | No safe telemetry path | Health status and an actionable administrative diagnosis | Remain inactive; never fabricate data. |

Log the selected tier once at startup and expose it as a machine-readable status/metric. Include why richer tiers were declined: `no-target-btf`, `event-missing`, `helper-unavailable`, `verifier-rejected`, `permission-denied`, or `resource-limit`. That lets operations distinguish an expected compatibility reduction from a regression.

## 10. Portable example design: bounded scheduler-event counter

A book example should demonstrate portability without promising it can observe every kernel. Consider a defensive **scheduler-event counter** that records only a small fixed record—timestamp, current PID/TGID, CPU, and a compile-time-selected event field—into a map consumed by userspace. It does not read arbitrary task fields, does not dynamically attach to symbols, and does not keep persistent kernel state beyond its process lifetime.

The design sequence is:

1. At startup, inspect `bpftool` feature output and tracefs for the selected scheduler event.
2. Prefer a CO-RE object only when target BTF is readable and relocation succeeds.
3. Keep the eBPF handler small: initialize `R0` through the Rust macro’s return path, extract only checked context data, zero-initialize its fixed output record, update the map, and return.
4. Use a small compile-time cap for any per-event iteration. Record a truncation counter instead of performing more work.
5. Load with verbose/stats logs in CI and a configurable diagnostic mode in staging; retain the full failure context.
6. If target BTF, event, attach, helper, or verifier requirements fail, select a baseline event-only object. If that fails, report the userspace tier rather than silently dropping data.

For a larger temporary string or byte buffer, use a map-owned per-CPU buffer rather than a stack array. The Aya tracepoint guide demonstrates this exact shape with `PerCpuArray<Buf>` for a 4096-byte filename buffer because available stack is limited. The example also shows the `TracePoint` user-space flow: get a named program, convert it to `TracePoint`, call `load()`, then `attach(category, event)`. Treat that specific API as pinned-Aya-version sample code, and treat its hard-coded event offset as an intentionally nonportable value to be validated rather than a universal constant. [18]

### Current Aya loader pattern, with an explicit BTF decision

The following outlines source-cut-specific user-space control flow. It deliberately separates a BTF availability test from selection of the object variant:

```rust
use aya::{Btf, EbpfLoader, VerifierLogLevel};

let target_btf = Btf::from_sys_fs();

let object_path = match &target_btf {
    Ok(_) => "observer-core.bpf.o",
    Err(_) => "observer-baseline.bpf.o",
};

let mut loader = EbpfLoader::new();
loader.verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS);
if let Ok(ref btf) = target_btf {
    loader.btf(btf);
}
let ebpf = loader.load_file(object_path)?;
```

The program must still handle a failed CO-RE load, because readable BTF is not proof that every type or relocation required by `observer-core.bpf.o` resolves. The fallback object must genuinely contain no unresolved CO-RE requirement. At the source cut, Aya’s loader deliberately returns an error if the object has CO-RE relocations but target BTF cannot be resolved. [13] [16] [17]

## 11. NixOS and reproducible deployment considerations

NixOS makes kernel selection explicit through `boot.kernelPackages`; this selects the kernel **and kernel-version-specific packages** together. The manual recommends current aliases such as `pkgs.linuxPackages_latest` when appropriate and warns that non-long-term versions can disappear after maintenance ends, making a pinned configuration fail evaluation. This is a reproducibility and lifecycle concern, not merely package naming. [25] [26]

For a supported NixOS fleet, put the eBPF compatibility contract under version control:

- Pin or otherwise record the Nixpkgs revision, the selected `boot.kernelPackages`, the Aya and Rust toolchain versions, and BPF object hashes.
- Test the actual generated kernel configuration. The NixOS manual suggests `zcat /proc/config.gz`, but availability of that file is itself configuration-dependent; `bpftool` and a safe trial load remain the runtime truth. [25]
- Install the diagnostic tooling intentionally in the image or a controlled support profile. Do not make production correctness depend on an administrator having a newer, unrelated `bpftool` package.
- Test upgrades before rollout against the selected kernel package family and the actual tracefs/BTF contents. A Nix expression that evaluates is not proof that a trace event, helper, or target BTF is present at runtime.

## 12. Publisher-ready chapter claims and wording discipline

| Chapter claim | Classification | Recommended wording | Citation basis |
|---|---|---|---|
| The verifier reasons about all feasible paths using register and stack abstract states. | Invariant teaching model | “The verifier uses abstract states—types, ranges, initialization, and provenance—to prove each possible path safe.” | [1] |
| A pointer is a capability with a verifier-tracked base and range. | Invariant teaching model | “Keep pointers typed and prove their bounds; an integer-like scalar cannot be dereferenced as a pointer.” | [1] |
| The BPF stack is 512 bytes. | Current upstream/kernel contract; validate legacy targets | “Design to a 512-byte eBPF stack budget and leave margin; the verifier also requires initialization before reads.” | [9] [2] |
| Loops are forbidden. | **Do not use** | Replace with: “Modern kernels can verify bounded loops, but the bound and analysis cost must be provable.” | [12] [2] |
| Any finite loop will load. | **Do not use** | “A finite-looking loop can still exceed verifier complexity; use small explicit bounds and test the object.” | [10] [2] |
| A helper works in any eBPF program. | **Do not use** | “Helper availability and context contracts depend on the program type and running kernel.” | [20] [21] |
| Verifier logs are a stable machine interface. | **Do not use** | “Keep logs for diagnosis; their format can change.” | [20] |
| CO-RE solves kernel compatibility. | Overbroad | “CO-RE relocates BTF-described type accesses; it does not supply missing capabilities or preserve semantics.” | [4] [5] |
| Tracepoints are a stable ABI. | **Do not use** | “Tracepoints are often preferable to kprobes for a named event, but upstream gives no blanket stable-ABI promise.” | [2] [11] |
| Kernel version determines support. | **Do not use** | “Use versions as diagnostics; probe the executing kernel and attempt the selected load under deployment privileges.” | [2] [22] |
| Aya automatically makes any object portable. | **Do not use** | “Aya can load target BTF and resolve supported BTF relocations; CO-RE objects fail if needed target BTF/relocations cannot be resolved.” | [13] [14] |

## 13. Review checklist for every book sample

Before publishing an example, verify that it answers every question below.

| Review question | Required evidence |
|---|---|
| Does every exit path define an `R0`-equivalent return? | Source review plus successful verifier load. |
| Are helper arguments of the required abstract type, initialized over the full size, in bounds, and aligned? | Verifier log test and program-type documentation. |
| Is every nullable pointer checked before use on the same control-flow path? | Branch-dominance review and negative verifier test. |
| Are acquired references released along all non-null/error/early-return paths? | A verifier-negative test that intentionally omits release, then a positive load. |
| Is stack usage comfortably below 512 bytes in generated output? | Object/disassembly and verifier output from the oldest target. |
| Is every loop compile-time capped and safe to truncate? | Code review and a hostile-input test. |
| Is every CO-RE access BTF/relocation aware and guarded if optional? | Object inspection and target-BTF matrix. |
| Is each trace event and its required field layout discovered on target? | Tracefs preflight and a missing-event fallback test. |
| Does the service export selected feature tier and reason for downgrade? | Integration test of each failure mode. |
| Has the selected object been loaded under the real deployment identity on each supported kernel family/configuration/architecture? | Recorded CI/integration matrix and retained logs. |

## 14. Exact facts that require cautious wording

1. **“All program types are limited to 512 bytes of stack”** is documented by upstream and represented by current `MAX_BPF_STACK`, but book examples must still be tested on the oldest supported kernel and compiler output. Do not turn it into a promise about how each function frame is independently budgeted. [2] [9]
2. **Bounded loops** were introduced in upstream Linux 5.3, yet a numeric kernel version is not sufficient for product support because distro backports, verifier complexity, privilege policy, and generated code matter. [12] [2]
3. **One million** is the documented verifier instruction-analysis ceiling, but there are other internal numeric and heuristic limits. Do not advertise it as a usable per-event execution budget or a stable product interface. [2] [10]
4. **Helper, map, program, attach, and link availability** is a matrix over kernel build, program/attach type, and privileges. The helpers manual explains contracts; `bpftool feature probe` and a controlled load establish host support. [21] [22]
5. **Verifier logs** are free-form diagnostics whose format can change. Key on error category and preserve raw logs rather than parsing English phrases into product logic. [20]
6. **`/sys/kernel/btf/vmlinux`** is the conventional running-kernel BTF path used by libbpf/Aya, but it may be unavailable or unreadable in a target environment. A CO-RE object should have a distinct deliberate fallback, not an implicit one. [4] [16] [13]
7. **CO-RE relocation kinds and BTF formats** evolve. The current upstream list is useful for understanding, but loaders/toolchains should be version-pinned and validated against target BTF. [5] [3]
8. **Tracepoints** have no blanket stable-ABI guarantee in the Linux BPF Design Q&A. The raw-tracepoint UAPI is stricter: it makes no ABI guarantee about exposed arguments. Avoid categorical stability claims, including those repeated in secondary tutorials. [2] [11] [18]
9. **Aya APIs are versioned.** At this source cut, use `EbpfLoader`, not the deprecated `BpfLoader` alias; verify `btf` signatures in the pinned crate/source. Floating documentation can disagree with current upstream source. [13] [15]
10. **NixOS kernel aliases and retention** are channel/revision policy, not a permanent contract. Keep a tested flake/revision and validate the booted kernel’s BPF facilities. [25] [26]

## 15. Source audit: every source read

The following table records all unique external documents and source artifacts read for this dossier. Citations in the body point to the same numbered references.

| Ref. | Source read | Authority and use |
|---|---|---|
| [1] | Linux kernel, *eBPF verifier* | Primary verifier state, ranges, pointer, packet, pruning, and diagnostic examples. |
| [2] | Linux kernel, *BPF Design Q&A* | Primary ABI, stack, compatibility, helper, tracepoint, and version-caution statements. |
| [3] | Linux kernel, *BPF Type Format (BTF)* | Primary BTF, kernel API, `.BTF`, `.BTF.ext`, func/line info facts. |
| [4] | Linux kernel, *libbpf Overview* | Primary explanation of target BTF path and CO-RE loader reconciliation. |
| [5] | Linux kernel, *BPF LLVM Relocations* | Primary CO-RE relocation layout, patching and relocation-kind definition. |
| [6] | Linux kernel, *BPF ABI Recommended Conventions and Guidelines* | Primary register/calling convention. |
| [7] | Linux kernel, *Using the Linux Kernel Tracepoints* | Primary tracepoint implementation/prototype context. |
| [8] | Linux kernel, *HOWTO interact with BPF subsystem* | LLVM BPF target/toolchain and `-mcpu=probe` caveats. |
| [9] | Linux source, `include/linux/filter.h` | Current upstream `MAX_BPF_STACK 512` definition. |
| [10] | Linux source, `kernel/bpf/verifier.c` and `include/linux/bpf_verifier.h` | Current internal verifier state/complexity context; version-sensitive implementation evidence. |
| [11] | Linux source, `include/uapi/linux/bpf.h` | Current UAPI load fields and raw-tracepoint ABI statement. |
| [12] | Linux upstream commit `2589726d12a1` | Primary history/algorithm evidence for bounded-loop introduction. |
| [13] | Aya source, `aya/src/bpf.rs`, commit `0e353…` | Exact current loader, BTF, diagnostics, and unresolved-relocation behavior. |
| [14] | Aya source, `aya-obj/src/btf/relocation.rs`, commit `0e353…` | Exact object-level BTF relocation implementation evidence. |
| [15] | docs.rs, *EbpfLoader* | Public Aya loader docs and documentation-version mismatch comparison. |
| [16] | docs.rs, *Btf* | Public `Btf::from_sys_fs`, parse, and parse-file APIs. |
| [17] | docs.rs, *VerifierLogLevel* | Public log-level flag names. |
| [18] | Aya Book, *Tracepoints* | Aya tracepoint program/attach sample and stack-buffer design example. |
| [19] | Aya project site/repository overview | Maintainer capability and portability positioning. |
| [20] | Linux `bpf(2)` manual | Program-load log behavior, context/helper dependence, and BTF syscall details. |
| [21] | Linux `bpf-helpers(7)` manual | Helper whitelist, five-argument, return, and program-type scope facts. |
| [22] | `bpftool-feature(8)` manual | On-target probe syntax, privilege, JSON, full, and built-ins distinctions. |
| [23] | Rust Cargo Book, *Build Scripts* | `rustc-cfg`, checked configuration, and host/target distinction. |
| [24] | Rust Cargo Book, *Features* | Compile-time feature conditional-compilation boundary. |
| [25] | NixOS Manual, *Linux Kernel* | `boot.kernelPackages`, aliases, maintenance, and configuration inspection. |
| [26] | NixOS Options search, `boot.kernelPackages` | Live option-index confirmation for the current NixOS channel. |

## References

[1]: https://docs.kernel.org/bpf/verifier.html "eBPF verifier — Linux kernel documentation"
[2]: https://docs.kernel.org/bpf/bpf_design_QA.html "BPF Design Q&A — Linux kernel documentation"
[3]: https://docs.kernel.org/bpf/btf.html "BPF Type Format (BTF) — Linux kernel documentation"
[4]: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html "libbpf Overview — Linux kernel documentation"
[5]: https://docs.kernel.org/bpf/llvm_reloc.html "BPF LLVM Relocations — Linux kernel documentation"
[6]: https://docs.kernel.org/bpf/standardization/abi.html "BPF ABI Recommended Conventions and Guidelines v1.0 — Linux kernel documentation"
[7]: https://docs.kernel.org/trace/tracepoints.html "Using the Linux Kernel Tracepoints — Linux kernel documentation"
[8]: https://docs.kernel.org/bpf/bpf_devel_QA.html "HOWTO interact with BPF subsystem — Linux kernel documentation"
[9]: https://raw.githubusercontent.com/torvalds/linux/master/include/linux/filter.h "Linux source: include/linux/filter.h"
[10]: https://raw.githubusercontent.com/torvalds/linux/master/kernel/bpf/verifier.c "Linux source: kernel/bpf/verifier.c"
[11]: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h "Linux source: UAPI BPF header"
[12]: https://github.com/torvalds/linux/commit/2589726d12a1 "bpf: introduce bounded loops — Linux upstream commit"
[13]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya/src/bpf.rs "Aya source: EbpfLoader implementation at research-cut revision"
[14]: https://github.com/aya-rs/aya/blob/0e353a7fddf80091ae2fb2dacc08ec1d861e67cc/aya-obj/src/btf/relocation.rs "Aya source: BTF relocation implementation at research-cut revision"
[15]: https://docs.rs/aya/latest/aya/struct.EbpfLoader.html "Aya EbpfLoader API documentation"
[16]: https://docs.rs/aya/latest/aya/struct.Btf.html "Aya Btf API documentation"
[17]: https://docs.rs/aya/latest/aya/struct.VerifierLogLevel.html "Aya VerifierLogLevel API documentation"
[18]: https://aya-rs.dev/book/programs/tracepoints.html "Building eBPF Programs with Aya: Tracepoints"
[19]: https://aya-rs.dev/ "Building eBPF Programs with Aya: Home"
[20]: https://man7.org/linux/man-pages/man2/bpf.2.html "bpf(2) — Linux manual page"
[21]: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html "bpf-helpers(7) — Linux manual page"
[22]: https://www.mankier.com/8/bpftool-feature "bpftool-feature(8) — manual page"
[23]: https://doc.rust-lang.org/cargo/reference/build-scripts.html "Build Scripts — The Cargo Book"
[24]: https://doc.rust-lang.org/cargo/reference/features.html "Features — The Cargo Book"
[25]: https://nixos.org/manual/nixos/stable/#sec-boot-kernel "Linux Kernel — NixOS Manual"
[26]: https://search.nixos.org/options?show=boot.kernelPackages "boot.kernelPackages — NixOS Options search"
