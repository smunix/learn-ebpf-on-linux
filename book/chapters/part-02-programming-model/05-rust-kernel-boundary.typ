#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing
#import "../../components/crossrefs.typ": xref, chapter-ref, section-ref, figure-ref, table-ref, listing-ref, definition-target
#import "../../components/terms.typ": acronym
#set heading(numbering: "1.1")

#let source-ref(key, url) = cite(label(key))
#let canonical-slice(path, title, source-path, first, last, language: "rust") = {
  let lines = read(path).split("\n")
  code-listing(
    title,
    lines.slice(first - 1, last).join("\n"),
    language: language,
    source-path: source-path,
  )
}

#chapter-opener(part: "II", chapter: "05")
= Rust on the Kernel Boundary <ch-05>

Rust makes a useful promise: many classes of ordinary memory and ownership mistakes can be ruled out before a program runs. An #acronym("ebpf") program changes neither the Linux kernel’s calling convention nor the kernel verifier’s authority. It changes the setting in which Rust is compiled and the proofs the author must supply. This chapter develops a practical model for that boundary using the repository’s three crates: `sentinel-common`, `samples-ebpf`, and `sample-runner`. The goal is not to make kernel code feel like ordinary Rust. It is to make the boundary—between two compilation targets, two memory domains, and two owners—explicit and reviewable.

== Prerequisites <sec-05-prerequisites>

This chapter assumes that you can distinguish user space from kernel space, can read a small Rust function, and understand the earlier lifecycle vocabulary: an object is parsed, a program is loaded and verified, then it is attached to a hook. You should also be comfortable running commands in a disposable virtual machine (VM), reading a command’s failure rather than working around it, and stopping an experiment whose target-kernel preflight fails. The hook used by this repository’s event demonstration is the static `sched/sched_process_exec` tracepoint; its presence and its operational meaning are target facts, not a book-wide promise.

== Learning objectives <sec-05-objectives>

After this chapter, you should be able to:

- explain why one source workspace builds a host loader and a separate BPF-target object;
- identify what `#![no_std]` and `#![no_main]` remove, and what they do *not* prove;
- treat a `#[repr(C)]` record as an owned in-host #acronym("abi"), rather than as a network protocol;
- state the proof obligations behind an `unsafe impl aya::Pod` and a raw event decode;
- trace map, program, ring-buffer, and attachment ownership through the loader; and
- run the audit-only event sample reproducibly, with its runtime gates and loss limitations clearly separated from a successful build.

== One application, two targets, three crates <sec-05-two-targets>

Aya is a Rust ecosystem for building and loading eBPF programs without a libbpf runtime dependency. In this workspace, `aya` belongs to the ordinary host process and `aya-ebpf` belongs to the BPF-target object. The split is architectural, not cosmetic. `sample-runner` can use the Rust standard library, allocate, parse command-line arguments, sleep, and print. `samples-ebpf` is invoked by the kernel at a selected hook, receives a verifier-typed context, can use only helpers and map operations permitted for that program type, and must return promptly. The kernel accepts the generated object only if its verifier can prove every reachable path satisfies the relevant rules. #source-ref("aya-book", "https://aya-rs.dev/book/") #source-ref("bpf-verifier", "https://docs.kernel.org/bpf/verifier.html")

#figure(
  image("../../assets/diagrams/generated/05-rust-aya-boundary.svg", width: 100%),
  caption: [The source boundary in this repository. `common` is deliberately small so that it can compile into both artifacts; Aya’s host and eBPF crates serve different execution environments.]
) <fig-05-rust-crate-flow>

#figure-ref(<fig-05-rust-crate-flow>, title: "crate and data flow") is the mental model to retain. The first arrow is a *build* relationship: `sentinel-common` is linked into both the BPF object and the user-space binary. The second is an object-loading relationship: the host loader opens the #acronym("elf") object, turns selected maps and programs into typed Aya handles, and asks the kernel to load and attach them. The final arrow is a data relationship: the kernel writes fixed records into a ring buffer and the host reads them. Similar arrows do not mean similar ownership or safety conditions.

The actual workspace manifest pins `aya = 0.14.0` and `aya-ebpf = 0.2.1`. Its `xtask` requests Rust `1.98.1` for an eBPF build and drives `aya_build::build_ebpf`; the checked-in toolchain file requests the same channel plus `rust-src`, `rustfmt`, and `clippy`. The BPF build also needs `bpf-linker`. Those are reproducibility inputs, not evidence that an object will load on the current kernel. Keep the lockfile, toolchain, object hash, target architecture, and verifier result together in any serious test record. Aya APIs and kernel availability must be pinned and re-tested after upgrades. #source-ref("aya-book", "https://aya-rs.dev/book/")

=== The shared crate is a boundary, not a convenience module <sec-05-common-crate>

The `sentinel-common` crate has one source file, but it is intentionally compiled in two modes. Its first line makes it `no_std` when the `user` feature is absent. The eBPF crate depends on it with `default-features = false`, whereas the runner enables `user`; only the latter obtains the optional `aya` dependency and the `Pod` implementations. That is a good dependency direction: the kernel-side crate may depend on schemas and constants, but it must not inherit a command-line parser, asynchronous runtime, allocator, or host-only map wrapper merely because they are convenient elsewhere.

#canonical-slice(
  "../../../samples/common/src/lib.rs",
  "The shared in-host ABI and its feature-gated host integration",
  "samples/common/src/lib.rs",
  1,
  85,
) <lst-05-common-abi>

#listing-ref(<lst-05-common-abi>, title: "shared ABI source") deserves a slow read. `FileIdentity`, `EnforcementConfig`, `Event`, and `ConnectEvent` use fixed-width integer fields and `#[repr(C)]`. `EnforcementConfig` includes a named `reserved` field; the other current records do not define a schema version, record length, or reserved-field policy. The four `unsafe impl aya::Pod` declarations occur only under `feature = "user"`, so the BPF-target dependency never needs `aya` merely to name the records. This is a clean *crate* boundary, but its ABI is still an application responsibility.

`#[repr(C)]` tells Rust to use C-layout field ordering and alignment rules. It prevents the default Rust representation from freely reordering fields, but it does not erase padding, select an interchange byte order, turn an arbitrary byte pattern into a valid value, or promise the same layout across every target ABI. The Rust Reference specifically distinguishes representation from validity; reading or constructing an invalid value, using misaligned typed access, or exposing uninitialized bytes can be undefined behavior. #source-ref("bpf-design-q-and-a", "https://docs.kernel.org/bpf/bpf_design_QA.html")

#definition-target("def-05-in-host-abi", "In-host ABI", [A deliberately bounded record contract used by the BPF object and its matching host loader on a stated architecture, toolchain, and release. It is not automatically a durable file, network, or cross-machine format.])

The current `Event` contains only unsigned integers and `[u8; 16]`, which are friendlier than pointers, references, `usize`, `bool`, Rust enums, or `Option<T>` for a raw record. That is a design advantage, not a completed proof. A reviewer must establish the layout and alignment for every compilation target, account for all padding bytes, and ensure writers initialize each field before bytes cross the boundary. The current unit test checks that `Event` is eight-byte aligned and that its size is a multiple of eight on the host test target. It does not assert host-and-BPF sizes together, prove that every potential padding byte is initialized, version the record, or establish an endian policy.

For a long-lived or cross-machine format, use a byte-level codec: define field widths, byte order, version, kind, maximum record length, and handling for reserved values, then decode after length checks. Do not transmit the in-memory Rust representation. For this repository, call the existing records *same-host, fixed-record data* until such an explicit schema and target matrix exist.

== `no_std`, `no_main`, and the BPF compilation target <sec-05-no-std>

The `samples-ebpf` binary begins with `#![no_std]` and `#![no_main]`. `no_std` prevents automatic linkage of Rust’s standard library and uses the `core` prelude instead. It does not, by itself, prove that no dependency has smuggled in unsupported facilities, guarantee an allocator-free program, or make panic paths safe. `no_main` says that this binary has no conventional process entry point. The kernel calls program functions selected from the object; Aya macros and map statics make the relevant sections discoverable to the loader. #source-ref("aya-book", "https://aya-rs.dev/book/")

This environment should be read as a restriction on design. There is no normal operating-system process around the program invocation: no filesystem interface, no thread creation, no blocking queue, and no general heap story to reach for. The program’s usable inputs are the hook context, permitted BPF helpers, and maps. Its output is the program-type-specific return value plus any map changes it makes. Its stack is small—design to a 512-byte eBPF stack budget with generous margin, and apply stricter tail-call constraints when the actual target/toolchain requires them. The BPF calling convention gives the return value in `R0`, passes helper arguments in `R1` through `R5`, preserves `R6` through `R9` across calls, and reserves `R10` as the read-only frame pointer. Aya source normally hides these registers, but generated code still obeys them. #source-ref("bpf-design-q-and-a", "https://docs.kernel.org/bpf/bpf_design_QA.html") #source-ref("bpf-verifier", "https://docs.kernel.org/bpf/verifier.html")

#kernel-detail(title: "A Rust local is not a verifier exemption")[A helper call changes the verifier’s register state. Pointer class, nullable map lookup, scalar range, stack initialization, alignment, and resource lifetime remain kernel proof obligations even when the source reads like ordinary Rust. Keep checked base pointers, bounds, and their use close together; do not treat a successful Rust borrow as proof that a kernel-derived address is a valid Rust reference.]

The actual program also supplies a `#[panic_handler]` that loops forever. Its presence satisfies a no-std binary requirement; it must not be used as a recovery plan. In the BPF data path, avoid `unwrap`, unchecked indexing, assertions, hidden formatting, and branches that could lead to panic. Prefer full struct literals, `Option` matches, explicit error branches, and early return. A successfully verified object is not proof of semantic correctness, bounded event loss, or a safe application policy. It establishes only that this object passed the target verifier under the relevant program, helper, and map contracts. #source-ref("bpf-verifier", "https://docs.kernel.org/bpf/verifier.html")

=== The kernel program: bounded production, explicit loss <sec-05-kernel-program>

The following canonical source extract shows the maps and common event path used by the repository. The map macro describes kernel objects; `EVENTS` is a ring buffer sized by the shared `RING_BYTES` constant, and `DROPPED` is a one-entry per-central-processing-unit (per-CPU) array. `base` gathers selected task attributes and constructs `Event` with `..Event::default()`, while `emit` either reserves a typed record, writes it, and submits it, or increments the per-CPU drop counter.

#canonical-slice(
  "../../../samples/ebpf-programs/src/main.rs",
  "Kernel-side map declarations and event reservation path",
  "samples/ebpf-programs/src/main.rs",
  1,
  70,
) <lst-05-ebpf-producer>

The reservation pattern in #listing-ref(<lst-05-ebpf-producer>, title: "the producer") is better understood as resource ownership than as queue syntax. `EVENTS.reserve::<Event>(0)` yields `Some(slot)` only if a fixed-size record can be reserved. That `slot` is a verifier-tracked obligation: write a fully formed record and submit it, or discard it on every path. This source keeps the successful path linear—`write`, then `submit`—and keeps the failure path outside the reservation. It never waits or retries in the hook. Ring-buffer reservation is non-blocking, and a failed reservation means that this observation is lost; an observer should return rather than create latency or a loop at a kernel hook. BPF ring buffers use bounded shared storage and are available only on kernels that support the map type; Aya documents Linux 5.8 as its ring-buffer floor. #source-ref("bpf-ringbuf", "https://docs.kernel.org/bpf/ringbuf.html") #source-ref("aya-book", "https://aya-rs.dev/book/")

`emit` increments the per-CPU `DROPPED` map after a reservation failure, and the runner sums and prints it as `producer_reserve_dropped`. It separately reports parse rejection, userspace queue loss, and intentional sampling; the latter two are zero in this synchronous teaching runner. A quiet display is still not proof of absent kernel activity, and a fixed capacity cannot make an unbounded producer rate lossless. #source-ref("bpf-ringbuf", "https://docs.kernel.org/bpf/ringbuf.html") #source-ref("bpf-map", "https://docs.kernel.org/bpf/maps.html")

For `03-exec-ringbuf`, the attached function itself is intentionally small: `exec_ringbuf` calls `emit(base(kind::EXEC, 1))` and returns zero. The runner attaches it to `sched/sched_process_exec`. Because this is a tracing program, the return does not implement a deny/pass policy; it is not an authorization decision. The source contains denial-capable Linux Security Module (LSM) programs elsewhere, but that fact does not give this selected tracepoint program an enforcement action. In particular, passing `--enforce` to the runner with `03-exec-ringbuf` does not change this match arm’s behavior.

== Unsafe at the byte boundary <sec-05-unsafe>

Rust’s `unsafe` is concentrated at this boundary because one side owns kernel-created bytes and the other wants typed values. The correct question is not “can I make this cast compile?” It is “which statement, checked where, makes this conversion sound?” `aya::Pod` is an unsafe trait because its implementation author promises that the type may participate in byte-oriented map APIs. It is not a serialization derive and it cannot state your protocol version, endian choice, padding policy, or upgrade semantics.

A defensible `Pod` review has at least five parts. First, the type must be `Copy` and `'static` as Aya requires. Second, every bit pattern delivered through the API must be valid for every field; this rules out many types that carry Rust validity invariants. Third, all bytes that might cross the boundary—including layout padding—must have a defined initialization policy. Fourth, the expected size and alignment need compile-time or test assertions on *both* host and BPF targets. Fifth, map key/value sizes and Aya conversion paths must be tied to the exact locked dependency version. The `unsafe impl` in #listing-ref(<lst-05-common-abi>, title: "the common crate") asserts these conditions only for host-side uses; the surrounding tests and schema must supply the evidence.

The runner’s ring-buffer decoder deliberately avoids constructing an `Event` reference from untrusted bytes. It reads fixed-width fields byte-wise, validates the leading schema version, declared length, kind, flags, and reserved-zero fields, and only then renders the record. This keeps alignment and validity obligations local. It is still a native-endian same-host protocol rather than a durable cross-machine format.

#verifier-note(title: "Make proof obligations local")[For an eBPF pointer, prove origin, non-nullness, bounds, and alignment before access. For a map lookup, match `Some` before dereference. For a ring reservation, submit or discard exactly once on every successful-reservation path. For host bytes, validate a bounded length before decoding and never retain a borrowed ring item across asynchronous work. Each proof belongs next to the operation it justifies, where a verifier log and a human reviewer can find it.]

The same discipline applies to “safe-looking” methods. `get_ptr_mut` is used by this source inside `unsafe` dereferences; the kernel verifier must still accept the map-value pointer and the program must respect concurrency semantics. Helper return types, allowed helpers, and map compatibility are program-type and kernel dependent. A null check that Rust forces via `Option` is useful, but it cannot add a helper that the target kernel does not allow. The verifier tracks types, initialization, bounded offsets, alignment, and certain reference lifetimes along all reachable paths; simplifying control flow reduces both review burden and rejection risk. #source-ref("bpf-verifier", "https://docs.kernel.org/bpf/verifier.html") #source-ref("bpf-map", "https://docs.kernel.org/bpf/maps.html")

== Loader ownership is operational correctness <sec-05-loader-ownership>

The host loader decides when bytecode becomes active and how long each kernel object remains reachable. This is why `Ebpf` should be thought of as an owner, not a bag of names. `Ebpf::load_file` parses the object and constructs its maps/programs in the host process. A typed conversion from an opaque program to `TracePoint`, followed by `load()` and `attach()`, performs the type-specific activation. Configuration maps should be initialized before attachment when a program needs them; consumers should be ready before a high-rate producer starts. Aya exposes typed program and map handles, but the kernel remains the authority that validates the object and attachment. #source-ref("aya-book", "https://aya-rs.dev/book/") #source-ref("bpf-map", "https://docs.kernel.org/bpf/maps.html")

#figure(
  table(
    columns: (1.18fr, 1.48fr, 1.6fr),
  inset: 6pt,
  align: (left, left, left),
  table.header([*Thing*], [*Owner in this sample*], [*Boundary rule*]),
  [BPF ELF object], [The ordinary-user build output, then `Ebpf` while loading], [Build as an ordinary user; do not treat a built object as proof of runtime support.],
  [`EVENTS` map], [Initially `Ebpf`; then `take_map("EVENTS")` transfers the host handle to `RingBuf`], [Drain borrowed items promptly; the map remains a kernel object only while kernel/host references exist.],
  [Program attachment], [Aya’s typed `TracePoint` held inside `Ebpf`], [The runner does not pin it; normal scoped teardown relies on dropping the owner.],
  [Event bytes], [A `RingBufItem` borrowed during `next()`], [Decode or copy only bounded bytes before the item is dropped and consumer progress advances.],
    [Schema and policy], [Application author], [Define version, validation, loss, and cleanup; the kernel does not infer them from `repr(C)` or `Pod`.],
  ),
  caption: [Ownership and lifetime boundaries in the repository’s bounded ring-buffer loader.],
) <tab-05-ownership>

#table-ref(<tab-05-ownership>, title: "ownership boundaries") explains the otherwise easy-to-miss `take_map` call. The runner removes `EVENTS` from the `Ebpf` object and converts that map handle to `RingBuf`. In its timed loop, it calls `next()` until it returns no item, passes the item bytes immediately to `print_event`, then lets the item drop at the end of the loop body. That lifetime is appropriate for the current synchronous printer: it does not send the borrowed slice to a thread, queue, or asynchronous task. The loop sleeps for 50 milliseconds only after draining the currently available items.

The attachment lifetime is equally deliberate but limited. The runner retains `Ebpf` for the entire run; it does not pin a BPF map, program, or link in the BPF filesystem (bpffs), and its own sample documentation states that normal timeout/drop detaches and closes the ring buffer. This is a useful laboratory property. If another file descriptor, a pin, or an attachment held by another process remains, process exit alone is not a universal cleanup proof. Production services need named link/map owners, a reconciliation policy, stale-pin removal rules, and a tested rollback path. BPF objects are freed only after their final reference disappears. #source-ref("bpf-map", "https://docs.kernel.org/bpf/maps.html")

#canonical-slice(
  "../../../samples/runner/src/main.rs",
  "The typed tracepoint load/attach path in the host loader",
  "samples/runner/src/main.rs",
  152,
  170,
) <lst-05-runner-attach>

#canonical-slice(
  "../../../samples/runner/src/main.rs",
  "The selected sample and bounded ring-buffer consumption loop",
  "samples/runner/src/main.rs",
  241,
  365,
) <lst-05-runner-consume>

#listing-ref(<lst-05-runner-attach>, title: "the attach helper") reveals a practical limitation worth testing rather than glossing over. `require_root` literally compares the effective user identifier (EUID) to zero before loading; its error text mentions equivalent BPF/performance-monitoring capabilities, but this implementation does not test or accept a non-root capability-only deployment. That is the runner’s conservative implementation gate, not a statement that Linux always requires root. Privilege requirements depend on the operation, program type, kernel, Linux security policy, and namespace context. Test under the intended service identity, and request the narrowest authority justified by that operation. #source-ref("bpf-design-q-and-a", "https://docs.kernel.org/bpf/bpf_design_QA.html")

#listing-ref(<lst-05-runner-consume>, title: "the dispatch and consumer loop") also keeps runtime behavior honest. Selecting `03-exec-ringbuf` loads `exec_ringbuf` and attaches category `sched`, event `sched_process_exec`; the runner caps observation at 60 seconds, validates each item, and prints transport metrics after draining. An unsuccessful load or attach returns an error rather than an event. A successfully attached program with no matching execution can legitimately print no event records.

== A safe, reproducible audit procedure <sec-05-procedure>

Use this procedure only in a disposable virtual machine where observing process-exec metadata is authorized. It is audit-only: do not add a denial-capable sample to this exercise, do not pin objects, and do not use a production cgroup. The procedure builds first as your ordinary account; only the reviewed finished runner binary is invoked with the authority that its current EUID gate requires. This avoids executing Cargo build scripts as root.

#terminal-listing(
  title: "Build and read-only preflight from the samples workspace",
  "cd /home/ubuntu/learn-eBPF-00/samples\n\ncargo xtask check\ncargo xtask build-ebpf\ncargo build -p sample-runner\n./target/debug/sample-runner lab-check\nuname -r\nuname -m\nsudo bpftool feature probe",
) <lst-05-preflight>

Treat these steps as separate evidence. `cargo xtask check` formats/checks the workspace while excluding `samples-ebpf`; `cargo xtask build-ebpf` drives the BPF build and needs the pinned toolchain and `bpf-linker`. The runner’s `lab-check` is read-only and reports whether it sees Linux, the BTF file, active BPF LSM text, cgroup-v2 support in `/proc/filesystems`, bpffs, tracefs directories, and EUID zero. It does *not* verify that `sched/sched_process_exec` exists, that its exact tracepoint format is usable, that ring buffers are permitted, or that a load will pass. `bpftool feature probe` adds kernel-side feature evidence; an administrator should record its output rather than changing system policy to make a failure disappear. Feature probes and a trial load are more reliable than release-string gates. #source-ref("bpf-design-q-and-a", "https://docs.kernel.org/bpf/bpf_design_QA.html") #source-ref("bpf-ringbuf", "https://docs.kernel.org/bpf/ringbuf.html")

Before attaching, confirm the actual event is exposed on the target, using whichever tracefs mount the system provides. A missing file is a stop condition, not a reason to substitute an arbitrary kprobe.

#terminal-listing(
  title: "Target-local tracepoint discovery and a bounded audit-only run",
  "test -r /sys/kernel/tracing/events/sched/sched_process_exec/format \\\n  || test -r /sys/kernel/debug/tracing/events/sched/sched_process_exec/format\n\nsudo ./target/debug/sample-runner run 03-exec-ringbuf --duration 10",
) <lst-05-audit-run>

The second command is environment-gated runtime behavior. It can fail because the object was not built, the event or ring-buffer map type is unavailable, the BPF verifier rejects the object, the process lacks the needed authority, resource accounting refuses the map, or a security policy blocks the operation. Those outcomes say something useful about this VM; none license a broader capability grant, a relaxed global sysctl, or an attempt to run the lab outside the VM.

== Expected output and how to interpret it <sec-05-expected-output>

#expected-output(title: "Conditional output shape, not a success guarantee")[On a target where the object loads, the tracepoint attaches, and an execution occurs during the ten-second window, the runner first reports `attached 03-exec-ringbuf; observing for 10s (drop detaches)`. For each fixed-size `Event`, it then prints fields beginning `event kind=3` and includes process identifier (PID), thread identifier (TID), user identifier (UID), cgroup identifier, action, value, device, inode, and command bytes rendered as text. The source does not promise a particular PID, command, count, ordering interpretation, or nonzero result. With no matching execution, no event line is expected.]

The output is a diagnostic rendering of the current same-host ABI. `kind=3` follows the shared `kind::EXEC` constant. The `comm` field comes from `bpf_get_current_comm`, not pathname reconstruction. The runner prints producer reservation loss and consumer rejection after the interval. An empty event display therefore remains bounded evidence, not proof of absent kernel activity or end-to-end completeness.

=== Verifier reasoning for this path <sec-05-verifier-reasoning>

A verifier explanation should be an argument over every path, not a celebratory summary of the success path. In `base`, helpers supply scalar task metadata and `bpf_get_current_comm` returns an `Option`; `unwrap_or([0; 16])` makes the event field defined even if that helper fails. The struct update with `Event::default()` supplies values for fields the function does not explicitly set. In `emit`, only the `Some(slot)` arm owns a ring reservation, and it writes before submission. The `None` arm owns no reservation and merely tries to update `DROPPED`. The tracepoint function returns zero after `emit`; it does not branch into a policy decision.

The hidden proof limits are as important as this favorable reading. The verifier decides whether Aya-generated helper calls, map access, alignment, stack use, and control flow are valid for the selected target. It may reject a source change that feels harmless if it introduces an uninitialized stack read, an illegal helper, a too-large stack frame, an unsupported operation, or state explosion. Obtain the verifier log from the failed `BPF_PROG_LOAD`, begin with the first rejected state transition, and make the source proof simpler rather than trying to silence the diagnostic. The verifier’s exact acceptance behavior evolves, so preserve its raw log as target-specific evidence rather than parsing it as a stable API. #source-ref("bpf-verifier", "https://docs.kernel.org/bpf/verifier.html")

== Portability caveats <sec-05-portability>

This chapter has deliberately narrow portability claims. Aya documents a Linux 5.8 floor for its ring buffer wrapper, but that is only one predicate. The target still needs the BPF map feature, an authorized tracepoint attachment, sufficient resource limits, compatible Aya/Rust output, and a privilege/security-policy context that permits the load. The tracepoint is discoverable through tracefs, but static tracepoints are not a blanket stable kernel ABI; event existence, fields, offsets, and semantics belong in a per-target fixture when you decode them. This sample does not use its tracepoint payload, which keeps it less coupled than a layout-reading observer. #source-ref("bpf-ringbuf", "https://docs.kernel.org/bpf/ringbuf.html") #source-ref("bpf-design-q-and-a", "https://docs.kernel.org/bpf/bpf_design_QA.html")

BPF Type Format (BTF) is also not a universal requirement or cure here. The runner’s `lab-check` reports whether `/sys/kernel/btf/vmlinux` exists, and other programs in the shared BPF object use BTF-dependent mechanisms. `03-exec-ringbuf` itself uses a normal tracepoint attachment and does not read a BTF-described kernel structure. Compile Once – Run Everywhere (CO-RE) can adapt eligible type/field accesses when appropriate BTF and relocations exist; it cannot provide an absent hook, helper, map type, configuration, or privilege. #source-ref("aya-book", "https://aya-rs.dev/book/")

The runner’s host ABI makes a further portability boundary visible. It classifies incoming bytes only by exact `Event` or `ConnectEvent` size and uses the current host’s endianness conversions for the connect fields. Do not point a differently compiled object, a future schema, or another architecture at this decoder and infer compatibility from `repr(C)`. Add explicit schema metadata and a byte codec before records leave the tightly pinned host/object pairing described in the earlier in-host ABI definition .

== Cleanup, exercises, and summary <sec-05-close>

When the bounded runner returns normally, its local `RingBuf` and `Ebpf` owners drop; this sample creates no bpffs pins, and its README documents timeout/drop as the detach route. Confirm that the process has exited before re-running the experiment. If you interrupted a changed or future loader, do not assume cleanup: inspect the explicit ownership design and any pins/links it introduced. In this unpinned lab, there is no cleanup command to run and no state to delete. Do not create persistent bpffs state merely to demonstrate that cleanup is necessary.

#security-note(title: "Keep enforcement out of this exercise")[`03-exec-ringbuf` is an observer. It has no denial return path, and this chapter’s procedure never supplies `--enforce`. If a later policy experiment is authorized, begin in audit mode, require a separate explicit opt-in, scope it to a dedicated disposable cgroup and VM, and retain a tested recovery path. A successful tracepoint observer is not a justification to enable LSM enforcement.]

#exercise(title: "Audit the ABI claim")[Without changing source, list every field in `Event` from #listing-ref(<lst-05-common-abi>, title: "the shared ABI") and classify it as fixed-width scalar, byte array, configuration/policy field, or candidate for future schema metadata. Then explain why the existing `Pod` implementation does not answer endianness, versioning, or cross-target layout questions.]

#exercise(title: "Trace ownership")[Starting with `Ebpf::load_file`, draw the ownership transfer that ends at `RingBuf::next()`. Mark the point at which `EVENTS` leaves `Ebpf`, the lifetime of a ring item, and the condition under which dropping the loader is insufficient to prove removal. Compare your diagram with #table-ref(<tab-05-ownership>, title: "the ownership table").]

#exercise(title: "Explain an empty screen")[In a disposable VM, do not run an exec workload during the observation interval. Record the attachment line and absence of event lines. Then list at least four distinct explanations for an empty result, including no matching hook invocation, attach failure, producer loss, and consumer-side filtering/validation. Identify which are observable in the current runner and which need additional metrics.]

The chapter’s main lesson is that Rust is most helpful at the kernel boundary when it makes the contract visible. Aya separates host ergonomics from BPF-target code; `no_std` and `no_main` expose the restricted execution setting; `repr(C)` creates a controlled layout rather than a protocol; `Pod` focuses attention on unsafe byte promises; and RAII-style ownership gives a small laboratory a natural teardown path. None of those tools erases kernel contracts. A robust design names the program type and hook, pins its toolchain, initializes every boundary byte, checks loss and feature gates, validates consumer input, and can identify the owner that will detach or remove each kernel object.

== Next steps <sec-05-next-steps>

Continue with #chapter-ref(<ch-06>, title: "Moving Events to User Space"). It builds directly on this boundary: choose a map for data semantics, specify concurrent update behavior, validate the event ABI, and treat transport capacity and loss as measurable properties rather than incidental details. Revisit #section-ref(<sec-05-unsafe>, title: "Unsafe at the byte boundary") and #section-ref(<sec-05-loader-ownership>, title: "Loader ownership") before making a record durable or a loader persistent.
