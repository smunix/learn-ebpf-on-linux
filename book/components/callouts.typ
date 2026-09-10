// Semantic, accessible callout primitives. Each has a text label and a
// high-contrast foreground/background pair; color is never the only cue.
#import "../theme.typ": report-amber, report-blue, report-cyan, report-ink, report-mist, report-navy, report-paper

#let callout(kind, title, body, accent: report-blue, fill: report-mist) = block(
  width: 100%,
  breakable: true,
  above: 0.9em,
  below: 0.95em,
  fill: fill,
  stroke: (left: 3.1pt + accent, rest: 0.45pt + accent.lighten(68%)),
  radius: 3pt,
  inset: (left: 10pt, right: 10pt, top: 8pt, bottom: 8pt),
)[
  #text(font: "Noto Sans", size: 8.2pt, weight: 700, tracking: 0.045em, fill: accent)[#kind]
  #h(0.62em)
  #text(font: "Noto Sans", size: 9.2pt, weight: 700, fill: report-navy)[#title]
  #v(0.38em)
  #set par(justify: false, spacing: 0.25em)
  #body
]

#let concept(title: "Mental model", body) = callout("Concept", title, body, accent: report-blue, fill: rgb("#EAF3FB"))
#let kernel-detail(title: "Kernel detail", body) = callout("Kernel detail", title, body, accent: report-cyan, fill: rgb("#E7F6F5"))
#let verifier-note(title: "Verifier reasoning", body) = callout("Verifier note", title, body, accent: rgb("#6E4AA3"), fill: rgb("#F1ECF8"))
#let portability-note(title: "Portability", body) = callout("Portability note", title, body, accent: report-amber, fill: rgb("#FFF4DF"))
#let security-note(title: "Safety boundary", body) = callout("Security note", title, body, accent: rgb("#9D2A2A"), fill: rgb("#FCEBEC"))
#let exercise(title: "Try it", body) = callout("Exercise", title, body, accent: rgb("#4B6D1A"), fill: rgb("#EEF6E7"))
#let expected-output(title: "What success looks like", body) = callout("Expected output", title, body, accent: report-navy, fill: rgb("#EDF1F5"))
