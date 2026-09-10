// Central, editable publication metadata. Consumers can import `book-meta` or
// pass its title/author fields directly to `report-theme.with`.
#let book-meta = (
  title: "Learning eBPF on Linux",
  subtitle: "A reproducible Rust, Aya, NixOS, and kernel-security deep dive",
  author: "Providence Salumu",
  edition: "First edition",
  language: "en-US",
  format: "7 × 10 in technical book",
  license: "CC BY-SA 4.0 for prose and original diagrams",
  code-license: "MIT OR Apache-2.0",
  repository: "learn-eBPF-00",
  subject: "Linux eBPF, Rust, Aya, NixOS, and defensive kernel security",
)

#let title = book-meta.title
#let subtitle = book-meta.subtitle
#let author = book-meta.author
