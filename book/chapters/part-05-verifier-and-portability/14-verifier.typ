#import "../../theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, kernel-detail, verifier-note, portability-note, expected-output, exercise
#import "../../components/code.typ": code-file, terminal-listing
#import "../../components/crossrefs.typ": section-ref, figure-ref, table-ref, listing-ref, chapter-ref, definition-target
#import "../../components/terms.typ": acronym

#chapter-opener(part: "V", chapter: "14")

= Reading the Verifier <ch-14>

== Prerequisites and learning objectives <ch14-sec-prerequisites>

This chapter assumes that you can distinguish a program type from its attachment point, can read a small Rust/Aya eBPF program, and understand that a loader asks the kernel to load an object before it can attach it. You should also be comfortable using a disposable virtual machine (VM) for kernel-facing experiments. No packet interface is attached in the default procedure here. The intentionally failing fixture is a diagnostic artifact, not a program to add to a normal workspace or deployment.

By the end of the chapter, you should be able to explain the verifier as an abstract interpreter; read the important parts of a verifier state; distinguish a typed pointer from a scalar that merely contains bits; predict why a stack byte, nullable result, or helper argument is rejected; and design a small bounded loop whose termination is visible to the verifier. You should also be able to turn a load failure into a specific missing proof rather than treating the verifier as an opaque compiler error.

The Linux #acronym("bpf") subsystem accepts an #acronym("ebpf") program only after the target kernel proves the program safe for its program type and every feasible path. That statement is intentionally narrower than “the source looks safe,” “the object built,” or “another kernel loaded it.” Verification is a target-kernel decision that depends on the emitted instructions, context contract, allowed helpers, kernel configuration, resource limits, and the authority of the loader. The kernel documentation describes this instruction- and state-based reasoning; a successful load is the relevant evidence for one object on one target. @bpf-verifier @bpf-design-q-and-a

#concept(title: [A proof obligation, not a test run])[The verifier does not execute the program once with a friendly packet and infer safety from that outcome. It symbolically follows possible branches while keeping conservative facts about registers, memory, and resources. Your job is to arrange the bytecode so that the necessary fact—for example, “this two-byte read ends before packet end”—is true on the exact path that performs the read.]

== The mental model: abstract execution over states <sec-abstract-model>

#definition-target(
  "def-abstract-state",
  [Abstract state],
  [A conservative summary of what a program value or memory location may be at one instruction: its register category, range, initialization status, pointer relationship, and any tracked lifetime facts.]
)

A concrete processor run has one packet, one branch outcome, and one register value at each instruction. The verifier cannot rely on one run: an input may be short, an integer may be large, and a map lookup may return no value. Instead, it interprets the instruction stream using the abstract state defined above. A state has enough information to prove an access safe for #strong[all] concrete values it represents; when it lacks that proof, rejection is the safe outcome. This is #strong[abstract interpretation] in practical form.

At a conditional jump, the verifier usually forks its understanding. On a branch that proves `offset + width <= data_end`, the candidate packet pointer gains an accessible range. On the other branch, that fact is absent; an access there remains invalid unless a different proof appears. States that arrive at the same instruction can sometimes be pruned when an earlier state is at least as general and safe. This pruning is why deliberately simple control flow helps, but it does not turn the analysis into ordinary source-level reasoning. The verifier works on the generated eBPF instructions and their reachable states. @bpf-verifier

#figure(
  image("../../assets/diagrams/generated/14-verifier-state-exploration.svg", width: 100%),
  caption: [Verifier state exploration for a packet read. The bounds check creates a branch with a proven range and another in which dereference is unsafe; helper compatibility is a separate proof at the call site.]
) <fig-verifier-state-tree>

The actual generated verifier diagram is named `14-verifier-state-exploration.svg`; the requested `verifier-state-tree.svg` filename is not present in this repository. #figure-ref(<fig-verifier-state-tree>, title: [the verifier state exploration]) is therefore the repository’s concrete visual aid for this chapter.

The most useful way to read a diagnostic is as a snapshot immediately #emph[before] an instruction the verifier refused. Do not begin by asking “what source line is wrong?” Begin by asking: “What did the verifier know about each operand at this instruction, and what proof did this instruction require?” A packet load needs an in-range packet pointer. A map value load may need a non-null map-value pointer. A helper needs arguments in precisely the categories its prototype declares. An exit needs a defined return value. The category changes; the method does not.

#figure(
  table(
    columns: (1.25fr, 1.7fr, 2.25fr),
    inset: 5pt,
    align: (left, left, left),
    table.header([Concrete question], [Abstract evidence], [Conservative conclusion]),
    [Was a register written?], [A readable scalar or typed pointer rather than an uninitialized state.], [A read of an unwritten register, including an undefined return register at exit, is rejected.],
    [Can an offset address this byte range?], [Signed and unsigned bounds, known bits, pointer base, offset, alignment, and a proven accessible range.], [The access is allowed only if every represented offset stays in the permitted object.],
    [Can a lookup be dereferenced?], [A nullable map-value pointer refined by a path-dominating null check.], [Only the non-null branch may dereference it.],
    [May a helper inspect this buffer?], [An in-bounds stack or other allowed pointer, with every helper-read byte initialized.], [In-bounds storage alone is not sufficient.],
    [Does iteration finish?], [A state evolution across the back edge with an understandable finite bound.], [A finite-looking source loop can still be rejected if termination or analysis cost is not provable.]
  ),
  caption: [Proof obligations the verifier tracks rather than guesses.]
) <tab-proof-obligations>

#table-ref(<tab-proof-obligations>, title: [Proof obligations the verifier tracks]) is a practical review checklist. It also explains why two programs that appear equivalent to a human can differ at load time: one may preserve a relation between a check and a use, while the other destroys it through casts, arithmetic, a helper boundary, or a different branch.

== Registers, provenance, and ranges <sec-registers-and-provenance>

The eBPF calling convention supplies ten 64-bit general-purpose registers plus the read-only frame pointer `R10`. `R0` is the return value. `R1` through `R5` carry call arguments and are caller-saved; `R6` through `R9` are callee-saved. At program entry, `R1` conventionally holds the program-type-specific context pointer. An eBPF program must define `R0` before `EXIT`. These are both execution conventions and verifier facts. @bpf-design-q-and-a

The state display may describe a value as a scalar, context pointer, stack pointer, map pointer, map value, nullable map value, packet pointer, or packet-end pointer. Treat those names as #strong[capabilities], not cosmetic type annotations. A packet pointer is usable only for verifier-recognized packet arithmetic and only within its proved range. A scalar is not dereferenceable merely because an arithmetic operation leaves it with the same machine bits as an address. Similarly, adding two pointers does not create a meaningful pointer provenance that the verifier can trust. Preserve the typed value, derive offsets from checked scalars, and keep the check close to its use. @bpf-verifier

Provenance is the verifier’s answer to “what object does this pointer originate from, and what operations may reach it?” In addition to a base category, a pointer state can carry a fixed offset, a possible variable offset, alignment, identity relationships to copies, and a safe range. Copying a pointer to another register preserves that relationship. Recasting it through an integer or combining unrelated values may lose the relationship. That is why “I checked an equivalent expression earlier” is often not enough: the verifier needs a recognizable relationship in the path it has reached.

Scalar facts are richer than “known” and “unknown.” For an uncertain integer, the verifier tracks signed minimum and maximum, unsigned minimum and maximum, and a #strong[tracked number (tnum)]: a bitwise representation that says which bits are known and which may vary. If `x > 8` on the true branch, unsigned reasoning can establish `x >= 9`; on the false branch it can establish `x <= 8`. Signed comparisons establish signed facts. Arithmetic, masking, and casts can preserve, tighten, or discard these facts depending on the instruction sequence. @bpf-verifier

This leads to a durable coding rule: validate the #emph[same scalar] that will become an offset, and perform the access only in the branch whose predicate gives it a safe range. A signed index needs a non-negative proof as well as an upper bound. An access of width `width` needs space for all `width` bytes, not merely proof that the starting byte exists. Do not hide the relation in a general-purpose abstraction before you have established the low-level invariant.

#verifier-note(title: [Local proofs survive best])[For packet parsing, make a candidate end pointer, compare it with the packet end, and dereference only after the successful comparison. For a map lookup, return or otherwise avoid use on the null branch, then dereference on the non-null branch. The closer the check is to the use and the fewer transformations separate them, the easier it is to preserve provenance and range information.]

== Stack bytes, loops, and helper boundaries <sec-memory-loops-helpers>

`R10` addresses the eBPF stack. The documented eBPF stack budget is 512 bytes, and the verifier computes actual use. This is a deliberately small execution resource, not a normal process stack. Leave substantial room below the ceiling: compiler decisions, nested calls, and target restrictions mean that 512 bytes is not an independently reusable allowance for every source function. Inspect the emitted object and test it on the oldest kernel that the project claims to support. @bpf-design-q-and-a

The stack carries more than an address range. The verifier records whether relevant bytes were initialized and, where necessary, what pointer or scalar kind was spilled. Reading a local before writing it is invalid. More subtly, passing a pointer to a helper can cause an #strong[indirect read]: the verifier must prove that every byte the helper may consume has been initialized. Initializing named fields but leaving structure padding untouched can therefore fail when the helper’s size covers the padding. A zero-initialized small key or record is often the clearest starting point; write the exact fields afterward. Move large transient buffers to a suitable map, such as a per-central-processing-unit (per-CPU) scratch buffer, rather than trying to place a large filename or packet copy on the 512-byte stack. @bpf-verifier @bpf-design-q-and-a

Modern kernels can verify bounded loops; the old blanket advice that “loops are forbidden” is wrong. It is equally wrong to infer that every Rust `for` loop will load. The verifier must establish a finite, understandable back edge while keeping its own path exploration within implementation limits. A branchy body with a large runtime-derived count can create many distinct states even when the static instruction count is modest. The kernel’s documented design discussion describes a bounded instruction-analysis limit, but that number is not a per-event work budget or a portable capacity promise. @bpf-design-q-and-a

A verifier-friendly loop has a small compile-time maximum, an obvious monotonically advancing counter, and a checked runtime limit that can only reduce work. It stops safely when the input is shorter than expected or the budget is exhausted. For example, a defensive parser might inspect a small capped number of headers and mark an observation truncated rather than chasing arbitrary linked records. Avoid independent branches in each iteration where a small straight-line calculation will do. If work is naturally complex, split it across appropriately scoped programs or report reduced telemetry instead of making an unbounded kernel path.

A BPF helper is an allow-listed kernel function with a prototype, not an ordinary Rust or C call. The program type and target kernel determine whether the verifier may permit it. The call may have at most five register arguments under the BPF convention, and each argument must have the requested abstract type, range, alignment, and initialization. Helper availability is therefore not established by seeing a helper name in documentation or by a successful load of another program type. Probe the target and attempt the selected program under the intended service identity. @bpf-design-q-and-a

A helper call is also a state boundary. After a call, `R0` receives the documented abstract return type, while `R1` through `R5` become unreadable caller-saved registers. Preserve a needed value in `R6` through `R9` or in correctly initialized stack storage before the call, and reload or revalidate any state whose lifetime the helper contract can affect. A map lookup return is the familiar case: it is a nullable map-value pointer until the program branches on null. Some resource-returning interfaces also require a verifier-recognized release on #strong[every] exit path. The exact pointer and reference categories evolve, so learn the discipline rather than hard-coding an internal enum of all possible names. @bpf-verifier

#kernel-detail(title: [Read helper failures as contract failures])[Messages such as `map_value_or_null`, invalid indirect stack read, unreadable register, misaligned access, or unreleased reference describe an unmet contract at the incoming state. The wording is diagnostic rather than a stable machine interface. Preserve the complete raw log, kernel release, architecture, object digest, program and attachment type, and loader authority; fix the proof, not a string match.]

== The verifier lab: a deliberately missing packet proof <sec-verifier-lab>

The repository’s `05-verifier-lab` contains two tiny standalone crates rather than default workspace members. Its README explicitly calls the negative fixture intentionally rejected and says that loading it requires BPF authority. It does #emph[not] provide a normal attached workload, event stream, or denial policy. The generic safety paragraph in the README is not a description of code in these two XDP fixtures: neither fixture implements an `--enforce` flag, a pathname policy, cgroup matching, a map, or a helper call. Their only teaching purpose is packet-bound proof shape.

#code-file(
  "../../samples/05-verifier-lab/rejected/src/main.rs",
  title: [Rejected XDP fixture: packet dereference without an end proof],
  language: "rust",
  source-path: [samples/05-verifier-lab/rejected/src/main.rs],
) <lst-rejected-xdp>

In #listing-ref(<lst-rejected-xdp>, title: [the rejected fixture]), `ctx.data()` is cast to a `u16` pointer and dereferenced before the program compares any candidate end with `ctx.data_end()`. At runtime, a short packet can make the two-byte read extend beyond accessible packet data. Abstractly, the verifier has a packet base but no established safe range for this load. The program’s `XDP_PASS` return after the read cannot repair an invalid access that has already occurred, so an attempted load should be rejected with an invalid packet-memory-access category of diagnostic.

#code-file(
  "../../samples/05-verifier-lab/corrected/src/main.rs",
  title: [Corrected fixture: a path-local two-byte bounds proof],
  language: "rust",
  source-path: [samples/05-verifier-lab/corrected/src/main.rs],
) <lst-corrected-xdp>

#listing-ref(<lst-corrected-xdp>, title: [the corrected fixture]) adds the key condition: `data + size_of::<u16>()` must not exceed `data_end()`. The early return makes the unsafe path avoid the load. On the fall-through path, the verifier can associate the candidate end check with the dereference and establish a two-byte range. This repairs the specific missing #emph[verifier] proof shown by the negative control.

Do not overgeneralize the corrected fixture. It is still a minimal verifier laboratory program, not a production Ethernet decoder. In particular, it returns `XDP_ABORTED` for a short packet and performs a raw `u16` dereference. If attached, `XDP_ABORTED` is not an appropriate default action for unfamiliar or malformed traffic; a defensive observer/parser should normally make an explicit safe-pass decision such as `XDP_PASS` after it has recorded any permitted diagnostic. Moreover, an in-range verifier proof does not itself establish all Rust alignment and validity assumptions for a fabricated typed reference or load. Use byte-wise or demonstrably unaligned-safe decoding for real packet formats, and test a complete program on an isolated interface. The source shown here only proves the lab’s packet-end condition.

== A safe, reproducible diagnostic procedure <ch14-sec-procedure>

Run the following procedure only in a disposable Linux VM that you control. It is intentionally split into an audit-only default, an unprivileged build, and an explicit load experiment. The audit does not attach a program; the build does not need to run as root; and the load test does not attach the XDP program to a network interface. Keep the rejected crate outside the workspace as supplied. Do not convert its failure into a continuous integration (CI) gate that expects a particular English log sentence.

#terminal-listing(title: [Audit first, then build the isolated fixtures as an ordinary user], "cd /path/to/learn-eBPF-00\njust kernel-audit\njust smoke\n\ncd samples/05-verifier-lab/rejected\ncargo build --release --target bpfel-unknown-none\n\ncd ../corrected\ncargo build --release --target bpfel-unknown-none") <lst-audit-build>

#listing-ref(<lst-audit-build>, title: [the audit-and-build procedure]) uses repository commands whose audit mode is read-only. `just kernel-audit` inspects the running kernel without changing state; `just smoke` invokes the audit-only smoke harness by default. The two direct Cargo commands are environment-gated: they require the repository’s pinned Rust/BPF target and linker tooling. A missing target, linker, privilege, mounted BPF filesystem, or BPF feature is an observed prerequisite failure, not a reason to weaken host policy or run Cargo under `sudo`.

After a successful ordinary-user build, a person authorized to conduct the VM experiment may load the object with `bpftool` while requesting diagnostic output. The following is an explicit opt-in load only; it creates no attachment. Substitute the actual output locations if the pinned toolchain lays out its target directory differently, and inspect the binary before using it.

#terminal-listing(title: [Explicit VM-only verifier load; no network attachment], "cd /path/to/learn-eBPF-00/samples/05-verifier-lab\nREJECTED=rejected/target/bpfel-unknown-none/release/unchecked-xdp\nCORRECTED=corrected/target/bpfel-unknown-none/release/bounded-xdp\n\nsha256sum \"$REJECTED\" \"$CORRECTED\"\nsudo bpftool -d prog load \"$REJECTED\" /sys/fs/bpf/learn-ebpf-unchecked-xdp type xdp\n# The preceding command is expected to fail. Do not suppress or parse its raw log.\n\nsudo bpftool -d prog load \"$CORRECTED\" /sys/fs/bpf/learn-ebpf-bounded-xdp type xdp\nsudo bpftool prog show pinned /sys/fs/bpf/learn-ebpf-bounded-xdp") <lst-opt-in-load>

This step is #strong[environment-gated runtime behavior], not a promised result on every Linux host. The command needs an accessible `/sys/fs/bpf`, an XDP-capable BPF program type, an object that the installed target toolchain produced, and the authority permitted by the booted kernel and local policy. The repository’s general runner conservatively checks effective UID 0 before attachment; that implementation choice is not a universal kernel claim that only root can perform every BPF operation. Determine the exact authority and policy for the operation, and do not grant broad privileges simply to make the exercise pass. @capabilities @bpf-design-q-and-a

=== Expected outcome and how to interpret it <ch14-sec-expected-output>

#expected-output(title: [Expected categories, not fabricated log text])[The audit commands report only prerequisite observations and explicitly do not load or attach a repository program. If compilation succeeds, it produces the two named local binaries. An attempted rejected-fixture load should return nonzero and emit a verifier diagnostic whose category is an unproved packet access; because the program was rejected, its pin should not exist. If the corrected fixture is accepted on that VM, the second `bpftool` load returns successfully and its pin can be shown, but the program is still not attached to an interface. Verifier log grammar, acceptance details, and privilege failures are kernel- and loader-dependent; retain the raw results rather than substituting invented output.]

The contrast is diagnostic evidence, not a portability certification. A corrected bounds check can fail to load for a different reason on another kernel, and the negative object can fail earlier because the environment lacks a prerequisite. Record the booted kernel release, architecture, target triple, toolchain and `bpftool` versions, object hashes, effective authority, command status, and complete diagnostic output. Then reduce any failure to the first rejected instruction and compare its incoming state to #table-ref(<tab-proof-obligations>, title: [the proof-obligation table]).

=== Cleanup and non-attachment guarantee <ch14-sec-cleanup>

The rejected load normally leaves no pin because the verifier rejected it. If the corrected load succeeded, remove its explicit pin as soon as inspection is complete. The lab must not retain BPF objects across a VM snapshot, reboot, or unrelated test.

#terminal-listing(title: [Remove the optional corrected-fixture pin and verify cleanup], "sudo rm -f /sys/fs/bpf/learn-ebpf-bounded-xdp\nsudo bpftool prog show pinned /sys/fs/bpf/learn-ebpf-bounded-xdp") <lst-cleanup>

The final `bpftool` query should report that the pin is absent; that failure is the desired cleanup confirmation. No `bpftool net attach` command appears in this chapter. If you adapted this experiment to attach a program, detachment and restoration of the exact isolated interface configuration would be a mandatory separate procedure; do not improvise it on a production interface.

== Portability and diagnostic discipline <ch14-sec-portability>

The verifier’s core reasoning model is durable, but many details are target-sensitive. Kernel version strings are useful incident metadata, not a feature predicate: distributions backport, configure, and restrict BPF independently. A program type may be compiled into an object yet be unavailable, a helper may be disallowed for that type, a program may be denied by policy, or the verifier’s complexity heuristics may differ. `bpftool feature probe` can help identify supported program types and helpers, but its result must be gathered with the same authority as the intended loader, and a controlled load remains decisive. @bpf-design-q-and-a

The two lab fixtures do not depend on #acronym("btf") relocation or #acronym("core") access; they simply use the XDP context supplied by Aya. That narrow scope is valuable: it isolates one proof obligation. It does not make their loader, XDP availability, byte order, alignment handling, or return semantics portable. A future chapter can discuss BTF/CO-RE as a way to adapt eligible type accesses across compatible layouts, but it cannot create a missing helper, attachment facility, privilege, or unchanged kernel semantics. Treat a successful CO-RE relocation and a successful verifier load as separate facts.

Preserve verifier logs for humans and tests, but never make production behavior depend on matching their free-form text. For a failed load, classify evidence at a stable conceptual level: missing bounds proof, unreadable register, uninitialized indirect stack bytes, nullable pointer, helper contract, lifetime, complexity, privilege, or unavailable facility. Then make a small source change that supplies the missing evidence. The safest default for a monitoring tool is an observable reduced-capability mode, not repeated privileged retries and never an attempt to bypass the verifier.

#portability-note(title: [Acceptance is not a universal safety certificate])[“Verified” means that this target verifier accepted this emitted object under this program-type, policy, and loader context. It does not prove semantic portability, lossless telemetry, correct packet protocol parsing, or suitability for enforcement. For policy-related work, keep audit as the default. Make denial an explicit opt-in only inside a disposable, recovery-capable VM or cgroup with a documented rollback path.]

== Exercises <ch14-sec-exercises>

#exercise(title: [State-first reading])[Read #listing-ref(<lst-rejected-xdp>, title: [the rejected fixture]) without changing it. Write down the abstract category of `ctx.data()`, the range fact required by the `u16` load, and why the later `XDP_PASS` return is irrelevant. Then identify the one condition in #listing-ref(<lst-corrected-xdp>, title: [the corrected fixture]) that establishes the missing range on the fall-through branch.]

#exercise(title: [Design a stack proof])[Sketch, on paper, a helper call that takes a 16-byte stack key. Mark every byte initialized before the call, including any padding a structure representation might contain. Explain why writing only the field you happen to compare is not enough if the helper receives the whole 16-byte region. Do not add the sketch to the rejected fixture.]

#exercise(title: [Bounded parser contract])[Specify a packet parser that examines at most four optional records. State its compile-time cap, its runtime length check, its monotonic progress variable, and its safe outcome when there are more records or insufficient bytes. Count the independent branches in the loop body and simplify one before attempting any implementation.]

== Chapter summary and next steps <ch14-sec-summary>

The verifier accepts evidence, not intention. Its abstract states track register readability, pointer provenance, scalar bounds and tnums, stack initialization, helper contracts, resource lifetimes, and control-flow cost. A typed pointer is a constrained capability, while a scalar is not an address merely because its bits resemble one. A packet proof needs room for the whole access on the branch that makes it; a stack buffer passed to a helper needs every consumed byte initialized; a helper call invalidates caller-saved argument registers; and a loop must be both bounded and inexpensive to analyze.

The paired XDP fixtures made one proof failure visible. The rejected crate dereferences packet data without a `data_end` proof. The corrected crate first proves room for `size_of::<u16>()`, but it remains a narrow laboratory fixture rather than a deployment-ready parser. The safe workflow is audit first, build unprivileged, conduct any load only as an explicit disposable-VM experiment, preserve raw diagnostics, and remove the optional pin immediately.

Continue with #chapter-ref(<ch-15>, title: [BTF and CO-RE in Practice]). The focus shifts from proving one object safe to deciding how eligible typed accesses can be relocated for a target—and which missing capabilities still require a reduced tier or a clean stop.

== References <sec-references>

#bibliography("../../references.yml", style: "ieee")
