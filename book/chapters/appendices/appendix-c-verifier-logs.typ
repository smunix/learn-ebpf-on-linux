// Appendix C is deliberately self-contained so it can be included from book/main.typ.
#import "../../components/callouts.typ": kernel-detail, portability-note, security-note, verifier-note

= Appendix C: Verifier Log Field Guide <appendix-c>

A verifier log explains why the target kernel could not prove one eBPF object safe for its program and attachment contract. It is not a verdict on the source language or eBPF as a whole. The verifier explores feasible paths with abstract register, pointer, scalar-range, stack, and resource states. A rejection means that an instruction can arrive without a required fact: a pointer may be null, an offset too large, a byte unwritten, or a resource still live. Read that incoming state, then make the missing fact visible in emitted control flow. Kernel documentation is the source of record; message wording and heuristics can change. #cite(<bpf-verifier>) #cite(<bpf-design-q-and-a>)

Use this guide only for a reviewed object in a disposable NixOS lab or other authorized non-production target. A successful load says only that the selected bytecode was accepted for that target's program type, configuration, privilege context, and verifier. It does not prove hook portability, Rust safety, or policy safety. Retain the raw log for humans; do not build product behavior around its English phrases. #cite(<bpf-verifier>)

#security-note(title: [Audit before any load attempt])[This repository's `just check`, `just kernel-audit`, and `./scripts/smoke-tests.sh --audit` paths do not load or attach an eBPF program. They are the first diagnostic step. A rejected fixture is deliberately outside the default workspace. Do not use a verifier failure as a reason to grant broad privileges, change host sysctls, loosen LSM policy, raise limits indiscriminately, or run Cargo as root. If a target lacks an authorized, narrow test path, record the feature as unavailable.]

== What a log line is describing

A verbose log interleaves instruction numbers, abstract-state snapshots, control flow, and a rejection explanation. The state immediately before the failing instruction is normally more useful than a compiler source line. LLVM may have moved or spilled the operation, so use line information to locate a candidate but reconstruct the proof from the BPF instruction and its predecessors. Logs may be disabled or truncated by the supplied buffer; retain that fact with the raw log. #cite(<bpf-verifier>)

#figure(
  table(
    columns: (1.18fr, 1.72fr, 2.35fr),
    inset: 5pt,
    align: left,
    table.header(
      [*Log form*], [*Reading rule*], [*Actionable interpretation*],
    ),
    [`42: (61) r2 = *(u32 *)(r1 +0)`], [Instruction 42 is the operation currently under examination; opcode text is a disassembly, not source syntax.], [Find the source operation that generated it, then inspect the state and branches that reach instruction 42. Do not repair the opcode in isolation.],
    [`R1=ctx R10=fp R0=map_value_or_null`], [Each assignment is the verifier's abstract type/value knowledge immediately before the next instruction.], [A dereference of `R0` needs a branch that makes the non-null path explicit. `ctx` and `fp` identify typed bases, not ordinary integers.],
    [`R3_w=scalar(umin=0, umax=63)`], [The `_w` suffix denotes a value written in this instruction; scalar bounds summarize possibilities, not one observed value.], [Use the same checked scalar as the later offset, and prove enough room for the full access. A new cast or arithmetic expression can lose the useful relation.],
    [`from 18 to 42: R2=...`], [A branch/state trail identifies one incoming path. Other feasible paths may still reach the same instruction.], [Check that every predecessor establishes the claimed invariant. A check on only one arm or after the access does not dominate the use.],
    [`invalid access to packet, off=12 size=2`], [The intended dereference is outside the range currently proved for that packet pointer.], [Compute the candidate end, compare it with `data_end`, and dereference only on the safe fall-through path; repeat after an invalidating helper.],
  ),
  caption: [How to read common fragments of a verifier log. Exact spellings are diagnostic details, not a stable parser interface.],
)

A state is deliberately conservative. `scalar` is an integer-like value, never a pointer created by casting. `ctx` is the program-type-specific context supplied in `R1`; `fp` is `R10`, the read-only frame pointer. Labels can name packet data/end, map values, map definitions, and reference-bearing objects, with offset, range, alignment, or identity. Treat them as proof vocabulary, not an exhaustive public enum; internal state names evolve. #cite(<bpf-verifier>)

== Register notation and helper boundaries

The BPF calling convention supplies writable 64-bit `R0`–`R9` and read-only frame pointer `R10`. `R0` carries a helper result and the exit value; `R1`–`R5` are caller-saved helper arguments; `R6`–`R9` are callee-saved. Entry `R1` is a typed context pointer, not a generic address. A helper assigns `R0` its documented result type and makes `R1`–`R5` unreadable. Preserve needed state in `R6`–`R9`, spill safely, or reacquire it; every exit needs the exact program-type result in `R0`. #cite(<bpf-verifier>) #cite(<bpf-design-q-and-a>)

#kernel-detail(title: [Registers explain generated Rust too])[Aya source usually does not name `R1` or `R6`, but compiled Rust still obeys this ABI. A log such as `R2 !read_ok` is a request to inspect code generation and helper boundaries, not an invitation to force a register assignment in Rust. Preserve a small source-level value across the call, or reload and revalidate the required context/packet state afterwards. Helper availability and argument types are also specific to the program type; a call accepted in tracing code is not thereby available to XDP or cgroup code.]

The following table translates frequent register-shaped diagnostics into proof obligations. These are representative forms, not assertions that every kernel will print the same message.

#figure(
  table(
    columns: (1.32fr, 1.86fr, 2.07fr),
    inset: 5pt,
    align: left,
    table.header(
      [*Representative form*], [*Missing proof*], [*Repair pattern*],
    ),
    [`R0 !read_ok` at exit], [A reachable return path has no defined result.], [Return the documented neutral/pass/error value for this exact program and attach type on every branch; do not assume that zero has the same meaning across program types.],
    [`R2 !read_ok` after call], [A caller-saved helper argument register was reused after the call.], [Move durable scalar state to a callee-saved local before the call, or reconstruct it afterward. Reacquire typed pointers rather than preserving stale raw addresses.],
    [`R1 type=scalar expected=ctx`], [A helper or context access received a value whose pointer provenance was lost.], [Keep typed bases separate from indices. Avoid pointer-to-integer-to-pointer round trips and consult the helper contract for the selected program type.],
    [`invalid func ...` or an argument-type rejection], [The helper contract, map type, argument count, or program-type allowlist is not satisfied.], [Check the target helper documentation and feature probe under the deployment identity; choose a deliberately supported object variant instead of substituting an arbitrary kernel-memory read.],
  ),
  caption: [Register and helper failures: classify the violated contract before editing source.],
)

== Stack initializedness: bounds are not enough

The eBPF stack is a small verifier-tracked region below `R10`; design to a 512-byte total budget with margin. A valid address is only half the proof: the verifier also tracks initialized bytes and the helper-read extent. An in-bounds, partially initialized key or event can therefore fail as an indirect stack read. Padding matters whenever the helper size covers it. Build records from a complete literal or zeroed value before overwriting fields, and move large reusable scratch storage to a map with an explicit concurrency contract. #cite(<bpf-verifier>) #cite(<bpf-design-q-and-a>) #cite(<bpf-map>)

#verifier-note(title: [Diagnose the byte range, not merely the variable])[For `invalid stack off=...`, determine whether the offset is below `R10`, lies within the total frame, and belongs to the intended local. For `invalid indirect read from stack`, identify the helper's size argument and prove that every byte in that exact interval was written on every path. Initializing one named field does not initialize adjacent padding or another conditional field. Keep local keys and headers compact, fixed-size, and visibly initialized before the call.]

A stack rejection can be a compiler-shape issue. Large arrays, nested helpers, and aggregate temporaries may consume more stack than source suggests. Inspect optimized BPF output and retain verifier evidence on the oldest claimed target. Nested BPF functions do not receive independent 512-byte budgets; apply any stricter target/toolchain tail-call or call-frame rule. #cite(<bpf-design-q-and-a>)

== Nullable map values and tracked references

A map lookup is not a proof that an entry exists. Its successful abstract result is commonly rendered as `map_value_or_null`; dereferencing it before a path-dominating null check produces a representative `invalid mem access 'map_value_or_null'` diagnostic. Check immediately, make the missing branch return or avoid the access, and use the pointer only in the proven non-null branch. Array-like maps may have stronger operational expectations, but code should still follow the API's actual optional result rather than encode an assumption that defeats a future map/type change. #cite(<bpf-verifier>) #cite(<bpf-map>)

The same discipline applies to reference-bearing helper or kfunc results. A non-null result can carry a verifier-tracked acquisition that needs the recognized release. `Unreleased reference` means an exit path retains it. Keep acquisition, null branch, brief use, release, and return adjacent; re-audit all exits when adding an early return. Never store raw task, file, socket, credential, or other kernel pointers in a map for later dereference: acceptance at one hook neither creates durable identity nor extends lifetime. #cite(<bpf-verifier>) #cite(<bpf-design-q-and-a>)

#figure(
  table(
    columns: (1.42fr, 1.78fr, 2.05fr),
    inset: 5pt,
    align: left,
    table.header(
      [*Failure family*], [*State to seek in the log*], [*Source-level proof shape*],
    ),
    [Nullable lookup], [`map_value_or_null` at the dereference or at a copy derived from it.], [Branch on the lookup result immediately. In the null arm, return or choose a safe fallback; keep the dereference syntactically and control-flow-wise inside the non-null arm.],
    [Reference leak], [A reference-bearing pointer and a path to `EXIT`; often reported as `Unreleased reference`.], [Null-check first, then release or transfer exactly once on every non-null path before any exit. Simplify control flow rather than duplicating cleanup ambiguously.],
    [Map update failure], [A helper error return or an ignored failure where the data-quality contract requires accounting.], [Check and count the failure if the write matters. BPF work must not retry or block; define a bounded loss/degradation metric instead.],
  ),
  caption: [Map and resource diagnostics are lifetime and data-quality contracts, not only pointer errors.],
)

== Pointer bounds, alignment, and the separate Rust proof

Direct packet access needs typed packet-data and packet-end bases plus a check that the full read lies before the end. Compute the candidate end for the width, compare it with `data_end`, take a safe failure action, then access only after the guard. Keep check and access adjacent. A variable offset needs a non-negative upper bound leaving room for the whole read; mixed bases or broad arithmetic can destroy the typed relation. #cite(<bpf-verifier>)

Some helpers can alter packet storage. After a documented packet-changing helper, previously proved data/data-end ranges may no longer describe the object; reload both bases and repeat the range check. A verifier log that shows a safe range before one call but rejects a later dereference is therefore often a stale-proof problem, not an argument for moving the original check farther away. #cite(<bpf-verifier>)

#portability-note(title: [Verifier-safe is not automatically Rust-safe])[A packet range proof does not establish that `*(ptr as *const u16)`, `&*ptr`, or a fabricated slice meets Rust's alignment, validity, aliasing, and lifetime rules. The repository's `05-verifier-lab/corrected` fixture demonstrates the missing `data_end` relation, but its aligned `u16` dereference is not a general packet-parser pattern and should not be promoted as a passing result. Prefer a narrowly scoped `*const u8` after the verifier-visible range check and decode bytes explicitly unless a separate Rust representation/alignment review proves a wider access sound.]

For XDP, an unknown, malformed, or short frame should normally take the explicit safe default `XDP_PASS` in an observational exercise; `XDP_ABORTED` is an exception path rather than a routine parser outcome. Validate a parser only on an isolated interface, beginning with the deliberately requested mode, and retain parse-failure counters. The verifier proof, Rust proof, action semantics, driver mode, and detach plan are separate obligations. #cite(<bpf-verifier>)

== Loops and complexity: finite is not automatically cheap

Modern kernels can verify bounded loops, but a finite-looking Rust loop can still fail when termination or analysis cost is not provable. The verifier explores states, not only static instructions. Nested branches, independent ranges, variable offsets, and large bounds multiply back-edge states, producing representative `too complex` or processed-instruction-limit results. Such counters are target-specific clues, not a portable performance API or execution allowance. #cite(<bpf-design-q-and-a>) #cite(<bpf-verifier>)

Use a small compile-time ceiling, an obvious monotonic counter, and a checked runtime length. Stop safely at the lesser of the input length and the ceiling, and record truncation when that matters. Early exits for malformed input and a narrow supported grammar are usually easier to verify than a general parser with many overlapping alternatives. When the hook model permits it, split independent optional features into small programs or capability tiers instead of one branch-heavy handler. This is not merely a way to placate a heuristic: it makes the work and failure mode reviewable. #cite(<bpf-verifier>)

== An audit-first diagnosis workflow

Begin with evidence that does not change kernel state. From the repository root, enter the pinned shell and run the read-only checks below. `just check` validates project foundations; it does not establish eBPF compilation, load, or attachment. Audit results for unavailable BTF, configuration, or LSM are observations, not reasons to alter the host. Use `--require-btf --require-bpf-lsm` only for a feature that genuinely needs both.

```sh
nix develop
just check
just kernel-audit
./scripts/smoke-tests.sh --audit
./scripts/check-kernel.sh --require-btf --require-bpf-lsm
```

Build review precedes privileged runtime work. In `samples/`, `cargo xtask check` formats/checks the ordinary workspace and `cargo xtask build-ebpf` builds the object with `bpf-linker`. `cargo run -p sample-runner -- lab-check` is read-only, not an attach test. None establishes verifier acceptance; the project CI and NixOS VM test do not load or attach repository eBPF programs. #cite(<aya-book>)

```sh
cd samples
cargo xtask check
cargo xtask build-ebpf
cargo run -p sample-runner -- lab-check
```

Only after an authorized review approves a disposable target should a loader request verbose/stats diagnostics for one selected object and program type. Record the object SHA-256, exact Aya/Cargo lock and Rust toolchain, `uname -r`, architecture, program and attach type, target BTF status, tracefs event/format where relevant, effective service authority, and the full log. The Aya loader API offers verifier-log levels, but API details must match the pinned release; do not copy a floating `latest` snippet into a release procedure. #cite(<aya-book>) #cite(<bpf-verifier>)

When a load fails, classify it before changing code. First separate an unavailable feature, denied authority, BTF/relocation failure, object/loader error, or resource limit from a genuine verifier proof failure. For a proof failure, select the first rejected instruction, copy its incoming state and the control-flow path into the issue record, and name the violated invariant: defined return, initialized bytes, nullness, pointer range/alignment, helper contract, reference release, or bounded complexity. Then make one minimal source change that supplies that invariant, rebuild the reviewed object, and repeat the same bounded test. Avoid fixing a later cascade first; a single early pointer or initialization defect can create many downstream messages.

The intentionally rejected `samples/05-verifier-lab/rejected` crate is a teaching negative control, not a default exercise or a claim of a recorded rejection on this host. Its `unchecked-xdp` function reads packet data without establishing the `data + 2 <= data_end` relation. Keep it outside the workspace, read its local README, and compare it with the adjacent corrected fixture during source review. Any explicit load to collect a log still requires a separately approved BPF-capable disposable target and an explicit cleanup plan. Never attach it to a production interface or infer that the corrected fixture has passed merely because its guard is conceptually better.

#security-note(title: [Close the diagnostic loop without broadening risk])[After a successful bounded load/attach test, detach or drop the owned object, confirm that no unplanned pin or attachment remains, and preserve the evidence with the target matrix. A failure should select an explicit reduced capability tier or an unavailable status. It should not trigger automatic retries, privilege escalation, a guessed tracepoint layout, or a substitution that changes policy scope.]

A verifier log becomes most valuable when paired with disciplined claims. State “the target verifier accepted this object under the recorded contract,” not “the program is safe everywhere.” Keep rejected logs and negative fixtures so later toolchain, kernel, or source changes can be diagnosed against an explicit proof obligation. That practice turns an opaque load-time error into a small, testable engineering question while preserving the repository's observe-first, least-authority boundary.

#bibliography("../../references.yml", style: "ieee")
