// Bounded component/style specimen. It is intentionally self-contained and does
// not alter book/main.typ or chapter content.
#import "../report-theme.typ": report-theme, chapter-opener, part-opener
#import "../metadata.typ": book-meta
#import "callouts.typ": concept, verifier-note, security-note, expected-output
#import "code.typ": code-listing
#import "crossrefs.typ": section-ref, definition-target
#import "terms.typ": acronym
#import "../glossary.typ": glossary

#show: report-theme.with(
  title: book-meta.title,
  author: book-meta.author,
  rhythm: "longform",
  running-header: true,
)

#chapter-opener(part: "I", chapter: "1")
= Foundation specimen <spec-foundation>

This bounded proof uses #acronym("ebpf") with #acronym("btf") metadata and a
#section-ref(<spec-foundation>, title: "Foundation specimen"). A later mention
of #acronym("ebpf") remains compact.

#concept(title: "Keep the boundary visible")[An eBPF program executes in the kernel,
while a loader, policy tool, and event consumer execute in user space.]

#verifier-note(title: "Proof before attachment")[Every pointer dereference, helper
argument, and control-flow path must satisfy the verifier's model.]

#security-note(title: "Audit before enforcement")[Use an isolated demonstration cgroup
and explicit opt-in before any policy may return a denial.]

#expected-output(title: "A useful event")[The reader should see a structured event,
its cgroup attribution, and a clear cleanup path.]

#definition-target("spec-btf", "BPF Type Format")[Compact type metadata used
for kernel-aware eBPF development.]

#code-listing("A minimal boundary", "#[repr(C)]\nstruct Event { pid: u32 }", language: "rust", source-path: "specimen")

#glossary(title: "Selected glossary")
