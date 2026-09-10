#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, security-note, expected-output, exercise
#import "../../components/code.typ": code-listing, terminal-listing

// Canonical source is read at render time. `lines` is inclusive and avoids
// duplicating sample code in this chapter.
#let imported-code-file(path, title: none, language: "text", lines: none, source-path: none) = {
  let text = read(path)
  let selected = if lines == none { text } else {
    let all = text.split("\n")
    all.slice(lines.first() - 1, lines.last()).join("\n")
  }
  code-listing(title, selected, language: language, source-path: if source-path == none { path } else { source-path })
}
#import "../../components/crossrefs.typ": chapter-ref, figure-ref, listing-ref, table-ref

#chapter-opener(part: "III", chapter: "09")
= Memory Management <ch-09>

A memory access looks immediate in source code: dereference a pointer, index an array, or write through a mapping. Linux must make that illusion true for each process. This chapter builds the mental model behind that work, then applies it to the repository's audit-only page-fault sample. The durable lesson is deliberately modest: an observed page-fault trace event says that the kernel took a fault path. It does *not* by itself say that a storage device was used, that an application crashed, or that a particular byte was read from disk.

== Prerequisites <sec-ch09-prerequisites>

This chapter assumes that you can distinguish user space from kernel space, can read a Rust eBPF program and its user-space loader, and understand the lifecycle introduced in earlier tracepoint work: load, attach, observe, and drop. You should also be comfortable with a map lookup that may fail and with the idea that an eBPF program runs under a verifier-defined execution contract. Read the preceding discussion of maps and event transports before treating the sample's ring-buffer records as measurements. A disposable NixOS virtual machine (VM), rather than a production machine, is the required environment for the optional attachment procedure.

== Learning objectives <sec-ch09-objectives>

After completing this chapter, you should be able to:

- distinguish a *virtual memory area* (VMA), which describes a range and its permissions, from the page-table entries that translate individual virtual pages;
- explain demand allocation, file-backed faults, copy-on-write (COW), swap, allocation, and reclaim without collapsing them into one “fault equals disk” story;
- state why page-table depth, page size, and fault tracepoint availability are target properties rather than portable eBPF constants;
- audit the actual behavior, loss boundaries, and portability limits of `08-page-fault-profiler`; and
- design a bounded, per-central-processing-unit (per-CPU) aggregation plan that is safer than emitting one user-space event for every fault.

== The address-space contract <sec-ch09-mental-model>

A process does not normally name physical random-access-memory locations. It issues loads and stores to *virtual addresses*. The processor's *memory management unit* (MMU) translates each usable virtual address to a physical page frame, subject to permissions. A process can therefore see a broad, sparse address space even when only a small fraction has physical memory behind it.

#concept(title: "Two complementary descriptions")[
A VMA is the kernel's range-level promise: this span is anonymous or file-backed, private or shared, and readable, writable, and/or executable under stated rules. Page tables are the fine-grained translation machinery: their entries say how a particular virtual page is presently translated and protected. A VMA can exist before every page in its range has a resident translation. That gap is where ordinary demand paging begins.
]

The distinction prevents a common mistake. A successful `mmap`, heap growth, or stack expansion can establish an address-space *policy* without allocating every physical frame at once. Conversely, a page-table entry can be installed or replaced as memory comes and goes while the enclosing VMA remains valid. The VMA answers questions such as “is this range permitted to be written?” and “which file mapping backs it?” A present page-table entry answers the much narrower question “how should this virtual page translate now?”

Linux documentation commonly names a software hierarchy of Page Global Directory (PGD), Page 4th Directory (P4D), Page Upper Directory (PUD), Page Middle Directory (PMD), and Page Table Entry (PTE). This is a useful vocabulary, not a fixed physical drawing. An architecture may fold a level, use different page sizes, use a different number of levels, or employ large mappings at a higher level. A PTE is the useful conceptual leaf for this chapter: it holds a translation and relevant permission/state bits for one base-page-sized region. Do not encode “five levels” or a particular page size into eBPF logic merely because it appeared on one machine.

#figure(
  kind: "table",
  supplement: [Table],
  table(
    columns: (1.2fr, 1.55fr, 1.45fr, 1.85fr),
    inset: 5pt,
    stroke: 0.35pt + rgb("#B8CDD2"),
    table.header(
      [*Layer*], [*Question answered*], [*Typical contents*], [*What an observer must not infer*],
    ),
    [VMA], [Which range and access policy?], [Start/end addresses, protection, backing and sharing policy], [That every page is allocated or resident],
    [Page tables], [How does this virtual page translate now?], [Translation, permissions, accessed/dirty state], [That the mapping identifies a durable file or workload],
    [Physical frame], [Where can bytes reside?], [A frame from a memory zone; possibly cache, anonymous data, or page-table memory], [That a frame remains assigned indefinitely],
    [Fault handling], [How can this access become valid or fail?], [VMA check, allocation/reclaim, page-cache lookup or input/output (I/O), PTE installation], [That a trace event records the eventual outcome or storage cost],
  ),
  caption: [Memory-management layers answer different questions.],
) <tab-ch09-layers>

#table-ref(<tab-ch09-layers>, title: "memory-management layers") is organized as questions because a fault profiler is otherwise tempted to answer more than the event supplies. The reported address is virtual, not physical. A count of fault-handler entries is not a count of allocated frames, filesystem reads, or failed application requests.

== From an access to a resumed instruction <sec-ch09-fault-flow>

A page fault begins when the MMU cannot complete an attempted access with the current translation and permissions. “Cannot complete” includes a missing translation, a permission condition that requires a special transition, and an invalid access. The processor transfers control into architecture-specific exception handling with an address and architecture-defined status information. From there, Linux commonly reaches high-level memory-management handling such as `handle_mm_fault()`, but the early route and detailed work are architecture dependent.

#figure(
  image("../../assets/diagrams/generated/09-page-fault-flow.svg", width: 100%),
  caption: [A fault is a decision-and-recovery path, not a storage-operation counter. The eBPF observer receives only tracepoint fields and must aggregate them without assigning a cause.],
) <fig-ch09-page-fault-flow>

#figure-ref(<fig-ch09-page-fault-flow>, title: "page-fault flow") follows the useful high-level sequence. The fault handler first interprets the reported access and finds the VMA governing the address. An absent VMA, or an access incompatible with its permissions, may lead to failure handling; a tracepoint at fault time does not necessarily tell an eBPF program what user-visible signal or recovery followed. If the VMA permits progress, the kernel determines whether a suitable page is already resident or can be made available. It may then allocate or reclaim a frame, obtain content from the page cache or a backing store, install or adjust a PTE, and retry the instruction. The instruction that faulted normally resumes only after a valid mapping is established.

The important word is *may*. On a write to a COW mapping, the old physical page can already be present but not safely writable by this process. The kernel can allocate a new frame and copy data before installing a writable mapping. On first access to anonymous memory, the kernel can provide zero-filled memory or arrange a zero-page transition without a filesystem read. On a file-backed mapping, the required bytes can already be in the page cache. A swapped-out anonymous page or a file-cache miss can require I/O. An invalid access can instead become the segmentation-violation signal, `SIGSEGV`, for a user process. All are compatible with the broad phrase “page fault.”

#kernel-detail(title: "A page table is not a stable probe context")[
The page-table hierarchy, fault dispatch, allocator state, and locking are internal, architecture- and configuration-sensitive kernel machinery. A tracing program should observe a locally exposed event rather than walk page tables or dereference a reported address. eBPF program types and helper contracts are documented interfaces; tracepoint names and formats remain target-local interfaces rather than a general stable application binary interface (ABI). #cite(<bpf-design-q-and-a>)
]

Use narrow vocabulary: *observed user-fault event rate*, not “memory pressure”; *observed kernel-fault events*, not “kernel bugs”; and *correlated I/O evidence*, not “disk faults.” It prompts investigation instead of turning an exception into a diagnosis.

== Allocators, reclaim, and the cost of making room <sec-ch09-alloc-reclaim>

When fault handling needs a physical page, it cannot simply mint one. Linux maintains free memory in page-oriented allocator structures, commonly described through zones and a buddy allocator. The allocator must satisfy appropriately sized contiguous requests despite fragmentation. Zone layout and allocation paths vary with architecture, topology, configuration, and request flags. On a Non-Uniform Memory Access (NUMA) machine, locality can also matter.

If an appropriate free page is unavailable, the kernel may reclaim memory. Reclaim scans candidates that are no longer actively useful, attempts to write back dirty file-backed data when required, and returns reclaimable pages to the free pool. It may also invoke filesystem or backing-store work, and severe pressure can escalate toward an out-of-memory (OOM) decision. Reclaim is therefore a system-wide resource-management activity, not a direct property of one faulting instruction. A fault can happen with abundant free memory, and reclaim can occur for reasons that a simple fault counter cannot attribute to a particular process.

The page cache makes the relationship still more subtle. File-backed mappings and ordinary file I/O can share cached pages. A process may fault on a mapped file page that another process has already brought into memory; installing this process's PTE needs no storage read. Conversely, a regular `read` system call can initiate I/O without a page-fault trace event. Swap introduces another backing-store path for anonymous pages, but a fault event alone does not state whether the page was swapped, how much data moved, or how long the wait was.

A useful operating model separates four questions:

1. *Was there a fault-path event?* A tracepoint can sometimes answer this.
2. *What mapping transition was needed?* The VMA, PTE state, COW, and page-cache state determine this, but the repository sample does not inspect them.
3. *Was a physical frame available immediately?* Allocation and reclaim data can help, but are not emitted by this sample.
4. *Did backing storage perform I/O?* Storage, filesystem, writeback, swap, and page-cache telemetry are separate evidence streams.

The questions form an investigation funnel. Start with an aggregate observation and time window, then add one independently meaningful source of evidence. Do not respond to a transient rise by probing private structures or treating a page address as a file identifier.

== Why a fault is not disk I/O <sec-ch09-not-disk-io>

The slogan “a page fault means disk I/O” is attractive because it feels concrete. It is also wrong often enough to mislead capacity work. A fault means the current translation and access state could not satisfy an instruction immediately. I/O is only one possible later consequence.

Consider four short scenarios. First, a program grows an anonymous vector and touches a previously untouched page. The kernel can satisfy the access by allocating zero-filled memory; storage is not required. Second, a parent and child share a private anonymous page after `fork`. When one writes, COW can allocate and copy a page already in RAM; again, no disk transfer is implied. Third, a program maps a file whose needed page is already in the page cache. The page can become mapped without a device read. Fourth, a file cache miss or swapped-out anonymous page *can* require I/O, but the wait time, device, bytes, and completion outcome reside in additional telemetry, not in the fault event itself.

An invalid access is the opposite error: it can produce a user-fault event and terminate or signal the process without reading a byte of storage. Kernel-side faults similarly require careful interpretation; they are not a generic crash counter. The correct conclusion from an event spike is: “This workload entered an observed fault path more frequently during this window.” The next question is whether independent measurements show memory pressure, page-cache misses, swap activity, filesystem delays, or workload behavior that explains it.

#security-note(title: "Observation never justifies automatic memory policy")[
This chapter's sample has no memory-reclaim control or denial hook. Treat its data as audit evidence only. If a future experiment combines a memory signal with an enforcement action, keep audit as the default and make any denial an explicit, time-bounded opt-in confined to a disposable VM and dedicated control group (cgroup), with a tested rollback path. Never let lost telemetry decide whether a workload may run.
]

== Inspecting `08-page-fault-profiler` honestly <sec-ch09-sample>

The primary sample is a bounded aggregate rather than a per-fault event stream. The runner first discovers the local `exceptions/page_fault_user` format, then attaches only `page_fault_user`. It does not attach a kernel-fault event. This reduced mode is still environment-gated: the named event must exist and be readable, the target verifier must accept the object, and the loader identity must have authority.

#imported-code-file(
  "../../../samples/ebpf-programs/src/main.rs",
  title: [Page-fault tracepoint handlers],
  language: "rust",
  lines: (142, 151),
  source-path: "samples/ebpf-programs/src/main.rs",
) <lst-ch09-fault-handlers>

#listing-ref(<lst-ch09-fault-handlers>, title: "the canonical fault handler") shows the entire BPF-side behavior. The handler increments key `0` in `PAGE_FAULTS`, a true `PerCpuArray<u64>`, and returns zero. It reads no tracepoint context and emits no ring record. In particular, it does not inspect fault address, instruction pointer, error code, VMA, page-table level, major/minor classification, allocator state, or I/O result.

The omission of context reads is a good verifier and portability choice for a first observer: no hard-coded tracepoint offset has to be justified. It also means the sample cannot make categories based on error-code bits despite a tempting description in a design sketch. It measures only the selected hook invocations and their coarse user/kernel label.

The map declaration is a one-entry per-CPU array. Each CPU updates its own aligned `u64`; after the bounded interval, user space sums all possible-CPU values and prints one snapshot. There is no fixed 32-CPU cap, shared read-modify-write race, ring capacity, or per-event consumer lag in this path.

#imported-code-file(
  "../../../samples/runner/src/main.rs",
  title: [Runner user-fault aggregation and output],
  language: "rust",
  lines: (578, 590),
  source-path: "samples/runner/src/main.rs",
) <lst-ch09-runner-output>

#listing-ref(<lst-ch09-runner-output>, title: "the canonical runner branch") requires the exact local user-fault event and prints the selected scope. After observation it reads `PAGE_FAULTS`, sums the per-CPU values, and prints `user_page_faults=<n>`. The number remains a non-transactional same-host observation.

== Safe aggregation and verifier reasoning <sec-ch09-aggregation>

A fault can be high frequency. One event per fault multiplies work at precisely the time the machine may be short of memory or contending for CPU. The safer primary design is aggregate-first: a true `PerCpuArray<u64>` with one or a small fixed number of counters; a bounded sampling rule; a user-space sum taken only after a short interval; and an explicit statement that the sum is a non-atomic snapshot. This avoids a shared hot counter and usually removes the ring buffer from the fast path. If categories are required, keep them few, define them only from locally validated fields, and bound every index before map access.

A second design is a small histogram keyed by a predeclared category. It must define what each category means, how overflow is represented, and whether every CPU participates. A third design is sampled fixed-size event telemetry for diagnosis, with a separate dropped-event counter exposed to the consumer. None of these designs can recover an event the kernel did not expose or infer whether a fault incurred I/O.

#verifier-note(title: "Why the current handler is straightforward to verify")[
The literal key `0` is in range for a one-entry array. `get_ptr_mut` is treated as optional, the pointer is dereferenced only in the successful branch, and every path returns the tracepoint value `0`. There is no context read or reservation lifetime. Exact helper and map availability still belong to the selected program type and target kernel. #cite(<bpf-verifier>)
]

Verifier acceptance is not a measurement guarantee. The verifier can prove the safety properties it models for reachable BPF execution; it cannot prove that a shared counter has the desired statistical interpretation, that ring loss is visible to an operator, that tracepoint semantics are stable across kernels, or that a metric answers a capacity question. Map semantics and concurrency design remain part of the application contract. #cite(<bpf-map>)

== A safe, reproducible procedure <sec-ch09-procedure>

Perform the following only in a disposable x86_64 NixOS VM or another explicitly authorized disposable target. The repository's continuous integration does not load or attach eBPF programs, so a successful syntax or package check is not runtime evidence. Build as an ordinary user. The current runner itself rejects any effective user identifier other than zero, making its root check an implementation limitation rather than a general statement that every tracepoint loader must run as root.

#terminal-listing(
  title: "Read-only preflight and ordinary-user build",
  "cd /home/ubuntu/learn-eBPF-00\nnix develop\njust check\ncd samples\n./target/debug/sample-runner lab-check\ntest -r /sys/kernel/tracing/events/exceptions/page_fault_user/id\ntest -r /sys/kernel/tracing/events/exceptions/page_fault_user/format\nsed -n '1,120p' /sys/kernel/tracing/events/exceptions/page_fault_user/format\ncargo xtask build-ebpf\ncargo build -p sample-runner",
) <lst-ch09-preflight>

The `lab-check` subcommand is read-only. The exact `test` commands are the gate because the runner attaches only the local user-fault event. Read the format even though this sample does not decode it: it identifies the target contract you are choosing not to parse. If the event is absent, stop rather than substituting another hook.

Only after a successful build and preflight, invoke the already built loader for a short bounded interval from the `samples` directory:

#terminal-listing(
  title: "Time-bounded audit-only attachment in the disposable VM",
  "cd /home/ubuntu/learn-eBPF-00/samples\nsudo ./target/debug/sample-runner run 08-page-fault-profiler --duration 10",
) <lst-ch09-run>

The runner caps actual observation at 60 seconds, keeps its `Ebpf` owner in scope during the loop, and relies on unpinned object lifetime when it returns. It takes no sample-specific action for `--enforce`; that generic argument is irrelevant to the `08-page-fault-profiler` match arm and does not create a memory-policy mode. Do not use `sudo cargo run`: compiling Cargo build scripts as root unnecessarily joins the ordinary build and privileged attach steps.

== Expected output and interpretation <sec-ch09-output>

#expected-output(title: "Exact format, not a fabricated measurement")[
On a target where load and attachment succeed, the runner prints `page-fault scope=user only; kernel faults are not attached`, the bounded attachment-status line, and finally `user_page_faults=<n>`. The repository provides no authoritative numeric fixture because its reviewed CI does not attach the object and normal VM activity varies.
]

The aggregate reports neither page-cache state, reclaim, swap, major/minor classification, fault outcome, nor storage I/O. Interpret it as a clue for a bounded time window, then corroborate it with a separately selected memory or I/O tool. Never calculate “disk operations per second” from this count.

== Portability boundaries and cleanup <sec-ch09-portability>

Event names, fields, availability, and permissions are properties of the booted target. Static tracepoints are discoverable and often less coupled than function probes, but the kernel makes no blanket stable-ABI promise for their names or formats. #cite(<bpf-design-q-and-a>) This sample intentionally selects the reduced user-only mode and refuses to run when that event is absent.

Authority is also target-specific. Linux capability and policy requirements depend on operation, kernel, namespace, Linux Security Module policy, and tracing configuration; use the least authority that the actual disposable target requires rather than granting broad administrative power. #cite(<capabilities>) The current runner's effective-user-ID check makes it unsuitable as evidence for a capability-only deployment. Its use of Aya 0.14.0 is pinned by the workspace, but a successful build still does not establish that a particular target will verify or attach the object. #cite(<aya-book>)

Cleanup is intentionally simple. Let the short command end normally; object drop detaches the one tracepoint, and the code creates no bpffs pins. Record the exit status and verify that the owned attachment is gone before reusing the VM.

== Exercises <sec-ch09-exercises>

#exercise(title: "Audit the truthful aggregate")[Inspect the `PAGE_FAULTS` declaration and summation path. State the exact map value type, what a concurrent read means, how possible CPU slots are handled, and why the design does not need a ring-buffer event for every fault.]

#exercise(title: "Separate causes from symptoms")[Choose one workload that performs anonymous allocation and one that accesses a memory-mapped file. Before running either, write three explanations for a fault-rate increase that do *not* involve disk I/O. Then list the independent observations you would need before claiming a storage bottleneck.]

#exercise(title: "Bound the aggregation contract")[Describe what can happen when a fault occurs while user space reads per-CPU slots, when a `u64` wraps, or when the event hook is unavailable. Propose metadata that distinguishes an observed snapshot from a target that never attached.]

#exercise(title: "Make the environment gate explicit")[Write a preflight result format with the statuses `event-missing`, `tracefs-inaccessible`, `permission-denied`, `verifier-rejected`, `loader-error`, and `cleanup-failed`. Explain why substituting a differently named fault hook would change the measurement contract.]

== Chapter summary <sec-ch09-summary>

Virtual memory separates an address-space promise from present translation state. VMAs describe ranges and permissions; page tables map individual virtual pages to physical frames under architecture-dependent rules. A page fault is the mechanism that reconciles an attempted access with those rules. It can represent routine demand allocation, a COW transition, a page-cache mapping, swap-related work, file-backed I/O, or an invalid access. Therefore, a fault tracepoint is an observation of a control path, not a disk-I/O counter or a crash detector.

The repository's `08-page-fault-profiler` demonstrates one context-free user-fault handler and a true per-CPU aggregate, conditional on the target exposing the exact event and permitting the runner. It does not read addresses, emit per-fault records, attach a kernel-fault hook, or identify a storage cause. That small boundary is the feature: aggregate first, stay explicit about what the event means, and verify the exact target.

== Next steps <sec-ch09-next>

Carry the same discipline into #chapter-ref(<ch-10>, title: "network hook selection and packet parsing"): begin with the documented context, prove each bounded access, aggregate before streaming where possible, and name the safe default before considering any action that can affect traffic.

#bibliography("../../references.yml", style: "ieee", title: "Chapter references")
