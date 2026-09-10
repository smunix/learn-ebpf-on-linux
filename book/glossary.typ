// Glossary is local by design: no extra package and no second global style owner.
#let glossary-entries = (
  (key: "abi", term: "Application Binary Interface", short: "ABI", definition: "The binary-level contract governing data layout, calling conventions, and object compatibility across a boundary."),
  (key: "aya", term: "Aya", short: "Aya", definition: "A Rust library ecosystem for building, loading, and interacting with eBPF programs without requiring libbpf."),
  (key: "bpf", term: "Berkeley Packet Filter", short: "BPF", definition: "The original packet-filtering model; in modern Linux, the name used for the eBPF subsystem."),
  (key: "btf", term: "BPF Type Format", short: "BTF", definition: "Compact type metadata used by the kernel and eBPF toolchain, including CO-RE relocations."),
  (key: "bpffs", term: "BPF filesystem", short: "bpffs", definition: "A virtual filesystem used to pin BPF maps, programs, and links so they can outlive a loader process."),
  (key: "cgroup", term: "control group", short: "cgroup", definition: "A Linux mechanism for grouping processes and applying resource accounting or policy; this book uses cgroup v2 where required."),
  (key: "core", term: "Compile Once – Run Everywhere", short: "CO-RE", definition: "A portability strategy in which BTF-driven relocations adapt field and type access to a target kernel."),
  (key: "ebpf", term: "extended Berkeley Packet Filter", short: "eBPF", definition: "A constrained virtual-machine instruction set and Linux kernel subsystem for verified, event-driven programs."),
  (key: "elf", term: "Executable and Linkable Format", short: "ELF", definition: "The object-file format commonly used to carry compiled eBPF programs, maps, and metadata."),
  (key: "helper", term: "BPF helper", short: "helper", definition: "A verifier-described kernel function callable by eligible eBPF program types."),
  (key: "lsm", term: "Linux Security Module", short: "LSM", definition: "A kernel framework for security hooks and policy modules; BPF LSM programs can audit or, where allowed, deny an operation."),
  (key: "map", term: "BPF map", short: "map", definition: "A kernel-resident data structure shared among eBPF programs and, subject to access rules, user-space processes."),
  (key: "pod", term: "plain old data", short: "POD", definition: "A data type with a predictable representation suitable for exchange across an ABI boundary."),
  (key: "ringbuf", term: "ring buffer", short: "ring buffer", definition: "A shared producer-to-consumer event transport that preserves a global event order while bounding memory use."),
  (key: "seccomp", term: "secure computing mode", short: "seccomp", definition: "A Linux syscall-filtering facility, complementary to capabilities, LSMs, and eBPF observability."),
  (key: "vfs", term: "Virtual File System", short: "VFS", definition: "The Linux kernel abstraction layer that presents a common file-operation interface to many filesystem implementations."),
  (key: "xdp", term: "eXpress Data Path", short: "XDP", definition: "A high-performance packet-processing hook near the network driver receive path."),
)

#let glossary-entry(key) = {
  let matches = glossary-entries.filter(entry => entry.key == key)
  if matches.len() == 0 {
    panic("Unknown glossary key: " + key)
  }
  matches.first()
}

#let glossary(title: "Glossary") = [
  = #title
  #for entry in glossary-entries [
    #block(above: 0.7em, below: 0.42em)[
      #text(font: "Noto Sans", weight: 700)[#entry.term]
      #if entry.short != entry.term [ #text(fill: rgb("#007F8B"))[ (#entry.short)]]
      #linebreak()
      #entry.definition
    ]
  ]
]
