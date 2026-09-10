#import "../../report-theme.typ": chapter-opener
#import "../../components/callouts.typ": concept, expected-output, exercise, kernel-detail, portability-note, security-note, verifier-note
#import "../../components/code.typ": code-listing

// This local adapter reads the canonical repository source at the chapter path.
// It avoids copying code while retaining explicit one-based source line ranges.
#let canonical-code-file(path, title: none, language: "text", lines: none, source-path: none) = {
  let text = read(path)
  let selected = if lines == none {
    text
  } else {
    text.split("\n").slice(lines.first() - 1, lines.last()).join("\n")
  }
  code-listing(title, selected, language: language, source-path: source-path)
}

#let chapter-terminal(title: "Terminal", code: "") = code-listing(title, code, language: "bash", source-path: "expected command")

#import "../../components/crossrefs.typ": figure-ref, listing-ref, section-ref, table-ref
#import "../../components/terms.typ": acronym

#set heading(numbering: "1.1")

#chapter-opener(part: "III", chapter: "10")
= The Networking Stack <ch-10>

*Prerequisites.* You should have completed the map, verifier, and attachment-lifecycle material; be able to build the pinned Rust/Aya workspace as an ordinary user; and have access to a *disposable virtual machine (VM)* where you are authorized to create a virtual Ethernet pair and attach BPF programs. This chapter deliberately does not ask you to alter system-wide packet filtering, kernel tuning, or a production cgroup hierarchy.

*Learning objectives.* By the end of this chapter, you should be able to choose between an ingress packet hook, traffic control, and a cgroup socket hook; explain why an XDP program has bytes rather than a general socket buffer; state the two independent proofs needed for a Rust packet read; define a byte-order boundary for packet and socket fields; and run or decline the two supplied observations without turning either into a broad network policy.

Network code is often introduced as a choice between “fast” and “slow.” That is the wrong first distinction for a defensive eBPF design. The useful question is: *what decision is being made, for which scope, and what information exists at that point?* A frame arriving at an interface, a packet represented by the ordinary stack, and a process requesting a connection are related facts, but they are not interchangeable. They have different contexts, legal return values, parser obligations, failure modes, and operators who could safely own them.

This chapter follows one frame along that path, then reads two small companion programs as contracts rather than as generic networking templates. Sample 09 is an eXpress Data Path (XDP) Ethernet-type counter on an isolated interface. Sample 10 is an Internet Protocol version 4 (IPv4) connection observer attached to one control group (cgroup). Both are *environment-gated*: their repository source has not been demonstrated to load and attach by the reviewed project harness, so a successful build is not a runtime claim. The only honest result is the result obtained on the booted, authorized target.

== A packet is not always an `sk_buff` <sec-network-mental-model>

A Network Interface Card (NIC) receives a frame into a queue. Its driver can run XDP at this early receive boundary. If the program returns `XDP_PASS`, the driver can continue into ordinary networking work: polling through the New API (NAPI), construction of a socket buffer (`struct sk_buff`, commonly called an *SKB*), protocol parsing, routing, transport processing, and eventual delivery to a socket. Receive Side Scaling (RSS), Receive Packet Steering (RPS), and Receive Flow Steering (RFS) may distribute later receive processing, but they do not change the fundamental fact that native XDP is before ordinary SKB allocation. XDP is therefore an ingress hook, not a general egress hook and not a per-process callback. #cite(<aya-book>)

#figure(
  image("../../assets/diagrams/generated/10-network-hook-locations.svg", width: 100%),
  caption: [A receive-side hook map. XDP receives an explicitly bounded frame before an SKB exists; traffic control and socket/cgroup decisions occur later and answer different questions. The requested `packet-hook-path.svg` is not present in this repository, so this existing generated network-hook diagram is used.],
) <fig-packet-hook-path>

#concept(title: "Choose the object before the hook")[
  An XDP program can answer a small question about a frame entering one interface. A traffic-control program can answer a question about an SKB at a later point. A cgroup socket-address program can answer a question about a workload initiating a socket operation. None of these facts automatically supplies the other two: an early frame does not reliably name a process, and a `connect` request does not contain the final bytes of every packet.
]

The diagram in #figure-ref(<fig-packet-hook-path>, title: "receive-side hook map") is intentionally a simplification. An SKB is a kernel-owned, mutable packet representation with metadata and data pointers used by the ordinary networking stack. Its layout, allocation strategy, and the meaning and lifetime of individual members are kernel implementation details. Do not teach an XDP parser to manufacture an `sk_buff`, and do not treat a BPF Type Format (BTF) description as permission to walk an SKB casually. BTF can adapt eligible layout accesses; it does not make internal semantics a stable Application Binary Interface (ABI). #cite(<libbpf-core>) #cite(<bpf-design-q-and-a>)

Traffic Control (TC) sits later, after an SKB exists. A TC classifier or action is appropriate when the decision genuinely needs packet data and ordinary-stack placement rather than the earliest ingress position. For cgroup-associated traffic, cgroup SKB programs can also see packet data in an SKB-oriented context. These are different program types from XDP: their contexts, helpers, and return conventions must be read separately. Current kernel documentation prefers TCX forms over legacy `tc`, `classifier`, and `action` section conventions, but a distribution kernel may not provide TCX. Feature-gate it instead of silently rewriting a TC deployment. Neither primary sample in this chapter attaches a TC or cgroup-SKB program; no TC command below is implied by the XDP counter or the connection audit.

The table in #table-ref(<tbl-hook-selection>, title: "hook selection") turns the placement distinction into a design rule. “Safe first use” means a narrow, observable exercise, not an assurance that a target supports the hook.

#figure(
  kind: "table",
  supplement: [Table],
  caption: [Network hook selection by the fact being observed or decided.],
  table(
    columns: (1.2fr, 1.55fr, 1.75fr),
    inset: 5pt,
    align: (left, left, left),
    stroke: 0.35pt + luma(180),
    table.header(
      [*Question*], [*Context and layer*], [*Safe first use and non-claim*],
    ),
    [What arrives on this interface?],
    [XDP; raw ingress bytes in the range `data..data_end`, before a general SKB.],
    [Count or parse a small Layer 2 (L2) subset in generic/SKB mode. Do not claim egress coverage, socket ownership, or driver-mode performance.],
    [What packet data is associated with a workload?],
    [Cgroup SKB or TC; an SKB-oriented, later packet context.],
    [Use only after the scope and direction are explicit. Do not infer an original hostname from a packet destination.],
    [Which workload requested a connection?],
    [Cgroup socket address at `connect4` or `connect6`; request-time address and port fields.],
    [Audit the request for one cgroup. Do not claim that Domain Name System (DNS) names or post-routing packets are visible.],
    [May a listener be requested?],
    [Cgroup socket address at `bind4` or `bind6`.],
    [Observe first; any denial requires a separately tested, disposable scope and program-specific return contract.],
  ),
) <tbl-hook-selection>

== XDP: an ingress byte range, not a Rust packet object <sec-xdp>

#acronym("xdp") is a BPF program type whose context exposes packet bounds. The useful invariant is not “there is an Ethernet struct at this address.” It is *`data <= cursor <= data_end` for every read*. A parser proves that the bytes it needs lie within the current frame, then reads only those bytes. XDP actions include `XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT`, and `XDP_ABORTED`; return values outside the defined action set are not a spare error channel. `XDP_PASS` continues ordinary receive processing, while drop, transmit, and redirect deliberately change the frame’s fate. #cite(<aya-book>)

For a first observational deployment, `XDP_PASS` is the safe default for short, unknown, or unsupported frames. A malformed Ethernet frame is not a reason to transform a counter into a packet-loss mechanism. In particular, `XDP_ABORTED` is an exception-oriented action, not an ordinary parser result. The distinction matters even on a test interface: parser behavior is an outage policy once it leaves the lab.

The repository’s canonical implementation is short enough to inspect in full. #listing-ref(<lst-xdp-counter>, title: "XDP counter") reads the start and end addresses, checks that an Ethernet header is present, reads the EtherType at offset 12, increments one of two per-CPU slots, and passes a non-short frame. Bucket 0 is only EtherType `0x0800` (IPv4); bucket 1 is every other complete Ethernet frame. It does not parse IPv4 headers, Virtual Local Area Network (VLAN) encapsulation, Transmission Control Protocol (TCP), User Datagram Protocol (UDP), addresses, or payloads.

#canonical-code-file(
  "../../../samples/ebpf-programs/src/main.rs",
  title: "Canonical XDP packet counter",
  language: "rust",
  lines: (156, 175),
  source-path: "samples/ebpf-programs/src/main.rs:156–175",
) <lst-xdp-counter>

The repaired source proves each byte separately with `checked_add`, reads through `*const u8` whose alignment requirement is one, assembles the EtherType with `u16::from_be_bytes`, and returns `XDP_PASS` for a missing byte. It never creates a packet reference or performs an unaligned `u16` dereference. VLAN frames remain in the deliberately broad non-IPv4 bucket because this exercise parses only the outer EtherType. #cite(<bpf-verifier>)

#verifier-note(title: "Two proofs in the repaired sample")[
  The verifier sees that each one-byte address is derived from packet start and bounded by `data_end` before dereference. Rust separately permits the alignment-one `u8` raw-pointer read inside the documented unsafe block. The two bytes are then combined without an unaligned scalar load. Verifier acceptance still does not prove that the chosen protocol subset answers the operator's question.
]

This also illustrates why verifier acceptance is narrower than correctness. The verifier tracks the provenance and range of BPF pointers, initialized stack bytes, helper contracts, and reachable control flow. It does not decide whether a protocol subset is adequate, whether a packet classification is meaningful, or whether Rust’s source-level unsafe operation satisfied language rules. A helper that changes packet data can invalidate earlier direct-packet-access proofs; after such a helper, reacquire `data` and `data_end` and prove each new dereference again. Keep the supported protocol subset shallow, use early returns, and move complicated policy into user space or a map rather than multiplying parser branches. #cite(<bpf-verifier>)

The sample’s `PACKETS` map is a per-CPU array. Each CPU increments its own selected slot, and the runner later sums the values returned for every CPU. That avoids a shared increment in this counter, but the reported total is a non-atomic snapshot: packets can arrive while user space reads and sums the slots. It is a useful observation, not a lossless accounting ledger. #cite(<bpf-map>)

== Byte order and record boundaries <sec-byte-order>

Network protocols conventionally place multibyte fields in *network byte order*, conventionally big-endian. The host CPU may use a different order. An EtherType occupying bytes `08 00` must denote IPv4 everywhere. In #listing-ref(<lst-xdp-counter>, title: "XDP counter"), `u16::from_be_bytes([high, low])` makes the boundary explicit: the first wire byte is the high-order byte. Do not use an implicit host-order integer as a map key on one side and a network-order field on the other.

A second boundary appears in the cgroup audit. The `bpf_sock_addr` context documents IPv4 address and port fields in network byte order. The runner converts the event address with `u32::from_be` before creating an IPv4 display address, and it converts the displayed port from the stored field. That code is an implementation to validate against a known endpoint, not an abstract proof that every target represents the `u32` port field as the runner expects. The dossier specifically identifies socket-address port representation and byte order as a target test requirement. Keep a known local destination in the lab and compare the emitted address and port with the endpoint actually used.

The user-space event ABI deserves the same caution. The shared `ConnectEvent` is `#[repr(C)]`, contains fixed-width fields, begins with a version/kind/length header, and reserves zeroed fields. The consumer performs byte-wise native-endian reads and rejects unsupported schema, kind, length, flags, and reserved values. Those are sound same-host choices, but `repr(C)` plus an unsafe plain-old-data (POD) implementation is not a durable cross-machine protocol. A durable format must additionally specify byte order and compatibility independently of Rust layout.

== Socket and cgroup hooks: observe the request <sec-cgroup-socket>

A cgroup socket-address hook changes the question from “what frame entered an interface?” to “what socket operation did a member of this scope request?” Cgroup BPF attaches to a cgroup v2 hierarchy; a cgroup is a kernel resource/policy scope, not inherently a container name. Membership is inherited by `fork` and survives `execve`, which makes a deliberately managed service cgroup a better boundary than a mutable command name. It also means the mount location and the actual process membership must be established before attachment. #cite(<cgroups-v2>)

Sample 10 uses Aya’s `#[cgroup_sock_addr(connect4)]` program form. It has only IPv4 `connect` scope. It reads `user_ip4` and `user_port`, places them with a base event into the shared ring buffer, and returns exactly `1`. For this socket-address attach contract, `1` permits the operation. This return convention is not transferable to XDP, where a return is an XDP action, or to TC, where the decision contract is different. The program neither rewrites the destination nor contains a deny branch.

#canonical-code-file(
  "../../../samples/ebpf-programs/src/main.rs",
  title: "Canonical cgroup IPv4 connect audit program",
  language: "rust",
  lines: (171, 185),
  source-path: "samples/ebpf-programs/src/main.rs:171–185",
) <lst-cgroup-connect>

The loader branch is equally important because it states the attachment scope and mode. #listing-ref(<lst-network-attach>, title: "runner attachment branch") requires an explicit `--cgroup` path, opens that directory, loads the named `CgroupSockAddr` program, and attaches it with `CgroupAttachMode::Single`. It uses `XdpMode::Skb` rather than choosing the default XDP mode. The returned attachment identifier is retained by the Aya program object; when the owned `Ebpf` object drops at the end of the runner, the documented sample cleanup is detachment. The code does not pin maps, programs, or links.

#canonical-code-file(
  "../../../samples/runner/src/main.rs",
  title: "Canonical runner branches for XDP and cgroup attachment",
  language: "rust",
  lines: (297, 314),
  source-path: "samples/runner/src/main.rs:297–314",
) <lst-network-attach>

Audit must not be confused with complete evidence. The cgroup program reserves a ring-buffer slot directly. If reservation fails, it returns `1` without emitting an event and without incrementing the repository’s `DROPPED` counter. Consequently, a missing `connect` line proves neither that no connection was attempted nor that an address was allowed by a policy. The runner drains the ring every 50 milliseconds, decodes only exact known object sizes, and does not expose a producer-loss metric for this path. A production observer needs separately visible producer, parser, queue, and intentional-sampling loss metrics. #cite(<bpf-ringbuf>)

#security-note(title: "Audit is the only behavior implemented here")[
  Sample 10 always returns `1`; its command-line `--enforce` flag is not consulted in the sample-10 branch. Do not use it as a policy toggle. This chapter supplies no broad denial configuration. If a future, separately reviewed cgroup socket policy introduces denial, make it explicit opt-in, bind it to one disposable cgroup or VM, test DNS/proxy and bootstrap exceptions, measure decisions independently of telemetry, and rehearse detach/rollback before any use outside the lab.
]

== A safe, reproducible veth and cgroup lab <sec-safe-lab>

The following procedure is deliberately split into build, preflight, XDP observation, and cgroup observation. Build as an ordinary user; run only the reviewed loader artifact with the narrowly justified authority in a disposable VM. The runner currently rejects a nonzero effective user ID check, so its root requirement is a conservative implementation limitation rather than a universal kernel statement about BPF authority. Do not add file capabilities to Cargo, relax BPF sysctls, grant blanket `CAP_SYS_ADMIN`, or make a host-wide firewall change merely to force the exercise through. Capability requirements depend on the operation, kernel, namespace, Linux Security Module (LSM) policy, and network attachment. #cite(<capabilities>)

#chapter-terminal(
  title: "Build and read-only preflight (ordinary user)",
  code: "cd /home/ubuntu/learn-eBPF-00/samples
cargo xtask check
cargo xtask build-ebpf
cargo build -p sample-runner
./target/debug/sample-runner lab-check

test -d /sys/kernel/tracing || test -d /sys/kernel/debug/tracing
findmnt -rn -t cgroup2 -o TARGET
ip link show
",
) <lst-network-preflight>

`build-ebpf` requires `nightly-2026-07-15`, `rust-src`, and `bpf-linker`; user-space APIs are also checked with stable Rust. `lab-check` is deliberately read-only, but its cgroup-v2 check does not prove that the intended hierarchy is mounted or delegated. The `findmnt` result is therefore the relevant mount discovery step. The shared eBPF object also declares maps beyond the two selected programs, so source inspection does not replace an actual object load on the target.

For the XDP observation, create a pair that has no production traffic. The `198.18.0.0/15` range is reserved for benchmarking documentation and is used here only inside the VM. The commands use a `/30` slice and remove the entire pair during cleanup.

#chapter-terminal(
  title: "Create an isolated virtual Ethernet pair",
  code: "sudo ip link add veth-ebpf0 type veth peer name veth-ebpf1
sudo ip addr add 198.18.0.1/30 dev veth-ebpf0
sudo ip addr add 198.18.0.2/30 dev veth-ebpf1
sudo ip link set veth-ebpf0 up
sudo ip link set veth-ebpf1 up
",
) <lst-veth-create>

In the first terminal, start the compiled loader—not Cargo—against only `veth-ebpf0`. In the second terminal, send three Internet Control Message Protocol (ICMP) echo requests in the opposite direction. A frame transmitted through `veth-ebpf1` enters `veth-ebpf0`, which is the direction the XDP program observes. A complete review should also generate short, VLAN-tagged, unknown-EtherType, and ordinary frames and confirm that every path returns `XDP_PASS`.

#chapter-terminal(
  title: "Run the bounded XDP observation",
  code: "# terminal 1, from /home/ubuntu/learn-eBPF-00/samples
sudo ./target/debug/sample-runner run 09-xdp-packet-counter \
  --iface veth-ebpf0 --duration 15

# terminal 2, while terminal 1 is observing
ping -c 3 -I veth-ebpf1 198.18.0.1
",
) <lst-xdp-lab>

For the cgroup audit, keep the same veth pair and discover the actual cgroup-v2 mount. Make the target cgroup empty before attaching it. In a third terminal, start a local Hypertext Transfer Protocol (HTTP) server bound to `198.18.0.1`; it is merely a predictable local TCP listener. In a second terminal, run sample 10 for a bounded period. Finally, enter a temporary shell moved into the target cgroup and perform one local connection. A process outside the cgroup is the negative control and should not generate an event for this attachment.

#chapter-terminal(
  title: "Audit one IPv4 connect request from a disposable cgroup",
  code: "# terminal 1: discover and create the cgroup
CGROOT=$(findmnt -rn -t cgroup2 -o TARGET | head -n1)
test -n \"$CGROOT\"
sudo mkdir \"$CGROOT/learn-ebpf-demo\"

# terminal 2: local listener, outside the demo cgroup
python3 -m http.server 18080 --bind 198.18.0.1

# terminal 3: attach the audit program for 20 seconds
sudo ./target/debug/sample-runner run 10-cgroup-connect-audit \
  --cgroup \"$CGROOT/learn-ebpf-demo\" --duration 20

# terminal 4: enter the cgroup, then run the shown client command
sudo sh -c 'echo $$ > \"$1/learn-ebpf-demo/cgroup.procs\"; exec /bin/bash' sh \"$CGROOT\"
python3 -c 'import socket; s = socket.create_connection((\"198.18.0.1\", 18080), 2); s.close()'
exit
",
) <lst-cgroup-lab>

#expected-output(title: "Output shapes, not a fixed transcript")[
  After the XDP runner’s timed observation returns, it prints `bucket=0 packets=<sum>` and `bucket=1 packets=<sum>`. With the local client inside the demo cgroup, the cgroup runner may print a validated connect record and then transport-health counters. The displayed process field is populated from the high 32 bits of `bpf_get_current_pid_tgid()`—the thread-group identifier (TGID)—not necessarily an individual thread identifier. Verify the port against the known listener. No cgroup event is expected for the outside-cgroup negative control, but use `producer_reserve_dropped` before interpreting absence.
]

The procedure is *environment-gated* at several points. `XdpMode::Skb` needs generic XDP support and sufficient network/BPF authority on the veth device. The cgroup test needs a mounted cgroup v2 hierarchy, permission to create and use the chosen subtree, `BPF_CGROUP_INET4_CONNECT` support, and no incompatible `Single` attachment at the selected scope. The samples will fail honestly if these conditions, object-map support, or privileges are absent. Record the booted kernel release, architecture, interface name, cgroup mount, selected mode, exact object hash, and full verifier/load error before deciding whether the failure is a missing feature, policy refusal, or code defect.

== Cleanup, portability, and review questions <sec-cleanup-portability>

Once both bounded runners have returned, close the local listener and remove only the resources created for the lab. First confirm that the demo cgroup contains no processes; then remove it. Deleting the veth endpoint removes its peer as well. The runner owns no pins, so process exit is the intended attachment lifetime; nevertheless, perform cleanup only after the runner has finished rather than deleting an interface beneath an active experiment.

#chapter-terminal(
  title: "Explicit disposable-lab cleanup",
  code: "# after the bounded runners and local listener have exited
CGROOT=$(findmnt -rn -t cgroup2 -o TARGET | head -n1)
sudo rmdir \"$CGROOT/learn-ebpf-demo\"
sudo ip link del veth-ebpf0 2>/dev/null || true
",
) <lst-network-cleanup>

#portability-note(title: "Version numbers are not a support matrix")[
  A distribution kernel can backport, omit, or restrict a facility independently of its release string. Probe the booted target for the exact XDP mode, program/attach type, map support, cgroup-v2 mount and delegation, interface permissions, and effective LSM/capability policy. Native-driver and hardware XDP modes are explicit future experiments, not substitutes for `XdpMode::Skb`; neither is promised by the sample. The primary programs do not require a direct `sk_buff` read or a CO-RE relocation, but that does not make the shared object or attachment portable without a target load test.
]

A reviewer should also reject several seductive generalizations. The counters do not demonstrate line-rate capacity, traffic completeness, stable packet semantics, or a complete application audit. Short frames pass without incrementing either EtherType bucket. The cgroup observer is IPv4-only, observes a connection request rather than a hostname, and exposes ring reservation loss without making delivery lossless. A cgroup attachment is not proof of a container identity; the operator must establish membership. Finally, `CgroupAttachMode::Single` must be checked against existing policy before attachment.

== Exercises <ch10-sec-exercises>

#exercise(title: "Explain the boundary")[Without changing code, draw the receive path for a ping across the veth pair. Mark the point where the XDP program runs, the point at which an SKB becomes relevant, and why the counter cannot name the originating process. Then explain which later hook would be a candidate if the question changed to packet data associated with a service cgroup.]

#exercise(title: "Audit the repaired XDP parser")[Write a review checklist for #listing-ref(<lst-xdp-counter>, title: "the counter"). Confirm byte-wise access, the short/unknown-frame action, the VLAN classification, a per-outcome counter plan, and short/VLAN/unknown/ordinary-frame tests on an isolated veth. State both the verifier proof and the independent Rust proof for each read.]

#exercise(title: "Prove the socket display")[Repeat the cgroup lab with two known local IPv4 listener ports, one below and one above 255. Compare each emitted display with the endpoint. Document the observed `user_port` representation on your target and identify the exact conversion boundary. If the output is wrong or unavailable, stop at audit diagnosis; do not compensate by adding an enforcement rule.]

#exercise(title: "Specify a durable event")[Redesign `ConnectEvent` on paper for export across machines. Include a schema version, kind, record length, fixed-width fields, explicit reserved bytes, byte-order rules, and invalid-record behavior. Explain why `#[repr(C)]` and POD alone do not answer those protocol questions.]

== Chapter summary <sec-network-summary>

Network hook selection begins with the object and decision, not with a performance slogan. XDP is an early ingress byte-range program: it must prove bounds for every packet read, preserve an independent Rust alignment and validity argument, and pass unsupported input by default in a first exercise. An SKB belongs to later ordinary-stack and TC/cgroup-SKB contexts, where packet metadata is available but the program contract is different. A cgroup socket-address hook observes or mediates a workload’s request-time socket operation; it is neither a packet parser nor a container-identity oracle.

The canonical samples make these contracts concrete while exposing their limits. The XDP counter selects `XdpMode::Skb`, performs bounds-checked alignment-one byte reads, passes short or unsupported input, and counts complete Ethernet IPv4 versus other outer EtherTypes. The cgroup sample observes IPv4 `connect4`, always allows with return `1`, and reports transport loss. Both detach when their owning runner exits, neither pins state, and neither is a production policy.

== Next steps <ch10-sec-next-steps>

The repository currently contains no authored Chapter 11 target to cross-reference. In the next networking-focused chapter added to this manuscript, carry forward the contracts established here: select one precise hook, define its input subset and return semantics, version every exported record, account for loss, and make any enforcement separately opt-in with a recovery path. For the local logic in this chapter, revisit #section-ref(<sec-xdp>, title: "XDP parsing") before adding packet fields and #section-ref(<sec-cgroup-socket>, title: "cgroup socket observation") before extending workload scope.

#bibliography("../../references.yml", style: "ieee")
