// Learning eBPF on Linux — book entry.
#import "theme.typ": book-theme, report-navy, report-blue, report-cyan, report-amber, report-paper, part-opener
#import "metadata.typ": book-meta
#import "components/callouts.typ": security-note, concept
#import "glossary.typ": glossary

#show: book-theme.with(
  title: book-meta.title,
  author: book-meta.author,
  rhythm: "longform",
  body-size: 10pt,
  running-header: true,
)

// ---------- Half title ----------
#page(numbering: none, header: none, footer: none, margin: (top: 2.2in, x: 0.82in))[
  #align(center)[
    #text(font: "Noto Sans", size: 10pt, weight: 700, tracking: 0.12em, fill: report-cyan)[THE KERNEL, MADE OBSERVABLE]
    #v(0.8em)
    #text(font: "Noto Sans", size: 30pt, weight: 700, fill: report-navy)[Learning eBPF on Linux]
    #v(0.75em)
    #line(length: 42%, stroke: 2pt + report-amber)
  ]
]

// ---------- Title page ----------
#page(numbering: none, header: none, footer: none, margin: (top: 1.15in, bottom: 0.85in, x: 0.82in), fill: report-navy)[
  #set text(fill: white)
  #set par(justify: false)
  #text(font: "Noto Sans", size: 9pt, weight: 700, tracking: 0.13em, fill: report-cyan.lighten(35%))[RUST · AYA · NIXOS · LINUX SECURITY]
  #v(1.0em)
  #text(font: "Noto Sans", size: 34pt, weight: 700)[Learning eBPF on Linux]
  #v(0.55em)
  #text(font: "Libertinus Serif", size: 16pt, fill: rgb("#D5EAF0"))[A reproducible, verifier-aware deep dive from first tracepoint to scoped BPF LSM enforcement]
  #v(1.15em)
  #line(length: 58%, stroke: 2.5pt + report-amber)
  #v(2.3em)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6in,
    [
      #text(font: "Noto Sans", size: 8pt, weight: 700, fill: report-cyan.lighten(35%))[BUILT FOR]
      #v(0.35em)
      #text(size: 11pt)[Linux engineers who want to understand both the program and the kernel contract that accepts it.]
    ],
    [
      #text(font: "Noto Sans", size: 8pt, weight: 700, fill: report-cyan.lighten(35%))[FIRST EDITION]
      #v(0.35em)
      #text(size: 11pt)[NixOS · x86_64-linux · September 2026]
    ],
  )
  #v(1fr)
  #text(font: "Noto Sans", size: 11pt, weight: 700)[#book-meta.author]
  #v(0.25em)
  #text(size: 9pt, fill: rgb("#B8CDD2"))[#book-meta.repository]
]

// ---------- Copyright and safety ----------
#page(numbering: none, header: none, footer: none, margin: (top: 1.0in, bottom: 0.9in, x: 0.84in))[
  #set text(size: 8.6pt)
  #text(font: "Noto Sans", size: 15pt, weight: 700, fill: report-navy)[Publication and licensing]
  #v(0.7em)
  This is the first edition of #emph[Learning eBPF on Linux]. The prose and original diagrams are licensed under Creative Commons Attribution-ShareAlike 4.0 International. The Rust, Nix, shell, and configuration code is available under your choice of the MIT License or Apache License 2.0. Third-party projects and quoted interfaces retain their own terms.

  The canonical, versioned source is the `learn-eBPF-00` repository. Examples in this book import or link to files in `samples/`; treat that source and its lockfiles as authoritative when a printed listing is abbreviated.

  #v(0.8em)
  #security-note(title: "Run kernel code only in a recovery-capable lab")[
    eBPF programs execute in kernel context after the verifier accepts their bytecode. Verification is not a proof of policy correctness, privacy, low overhead, or operational safety. Build as an ordinary user. Perform privileged loading only in the disposable NixOS virtual machine or another explicitly approved non-production host. All enforcement examples begin in audit mode and require an explicit flag, a dedicated control group, and a disposable protected file.
  ]

  #v(0.8em)
  #text(font: "Noto Sans", size: 11pt, weight: 700, fill: report-navy)[How to use this book]

  Read Parts I and II in order. They establish the program lifecycle, verifier vocabulary, shared data layout, and loss model used everywhere else. Parts III and IV connect those abstractions to Linux subsystems. Part V explains why a program can compile yet fail to load on another kernel. Part VI turns observation into a narrowly scoped defensive decision. Do not start with enforcement merely because that is your destination.

  Commands marked as read-only inspect files or build artifacts. Commands that attach a program are explicitly identified. Commands that can deny an operation carry a red security callout and include cleanup. “Supported” always means supported by the stated object, kernel, configuration, authority, and test evidence—not supported by a version number alone.
]

// ---------- Contents ----------
#page(numbering: none, header: none, footer: none)[
  #set text(size: 9pt)
  #outline(title: [Contents], indent: 1.25em, depth: 2)
]

#counter(page).update(1)

#concept(title: "The central discipline")[
  An eBPF program is not safe, correct, or portable merely because it is written in Rust or accepted by one verifier. Every example in this book names five contracts: the program type, the attachment point, the target kernel, the data boundary, and the object lifecycle. That habit is the shortest route from a successful demonstration to defensible systems engineering.
]

#part-opener("I", [Foundations], deck: [Build a precise mental model, establish a disposable NixOS laboratory, and observe the first kernel event without hiding the load–verify–attach lifecycle.])
#include "chapters/part-01-foundations/01-why-ebpf.typ"
#include "chapters/part-01-foundations/02-nixos-lab.typ"
#include "chapters/part-01-foundations/03-first-event.typ"

#part-opener("II", [The Programming Model], deck: [Learn the eBPF instruction and calling model, write `no_std` Rust at the kernel boundary, and move bounded records into user space without pretending the transport is lossless.])
#include "chapters/part-02-programming-model/04-instructions-helpers-maps.typ"
#include "chapters/part-02-programming-model/05-rust-kernel-boundary.typ"
#include "chapters/part-02-programming-model/06-events-user-space.typ"

#part-opener("III", [Inside the Linux Kernel], deck: [Connect hook contexts to system calls, tasks, the Virtual File System, scheduling, memory management, and the networking stack.])
#include "chapters/part-03-kernel-internals/07-syscalls-tasks-vfs.typ"
#include "chapters/part-03-kernel-internals/08-scheduling.typ"
#include "chapters/part-03-kernel-internals/09-memory.typ"
#include "chapters/part-03-kernel-internals/10-networking.typ"

#part-opener("IV", [Containers and Control], deck: [Reason about namespaces, control groups, seccomp, capabilities, stateful maps, ownership, and upgrades as layers rather than interchangeable security features.])
#include "chapters/part-04-containers-and-control/11-namespaces-cgroups.typ"
#include "chapters/part-04-containers-and-control/12-seccomp-capabilities.typ"
#include "chapters/part-04-containers-and-control/13-stateful-design.typ"

#part-opener("V", [Verifier and Portability], deck: [Read rejection logs as missing proof obligations, understand BPF Type Format relocations, and build explicit capability tiers for kernels that differ.])
#include "chapters/part-05-verifier-and-portability/14-verifier.typ"
#include "chapters/part-05-verifier-and-portability/15-btf-core.typ"
#include "chapters/part-05-verifier-and-portability/16-kernel-version-survival.typ"

#part-opener("VI", [Security with BPF LSM], deck: [Move from observation to a narrowly scoped Linux Security Module decision with audit-first rollout, explicit identity limits, health telemetry, and rollback.])
#include "chapters/part-06-security-with-lsm/17-lsm-framework.typ"
#include "chapters/part-06-security-with-lsm/18-audit-to-enforcement.typ"

#part-opener("A", [Field Reference], deck: [Configuration, commands, verifier diagnostics, compatibility evidence, and troubleshooting for repeatable lab work.])
#include "chapters/appendices/appendix-a-kernel-config.typ"
#include "chapters/appendices/appendix-b-command-reference.typ"
#include "chapters/appendices/appendix-c-verifier-logs.typ"
#include "chapters/appendices/appendix-d-compatibility.typ"
#include "chapters/appendices/appendix-e-troubleshooting-source-map.typ"

#pagebreak()
#glossary()

#pagebreak()
#bibliography("references.yml", title: "References", style: "ieee")
