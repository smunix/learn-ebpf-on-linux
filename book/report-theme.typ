// Shared visual theme for the skill-owned report entry.
// This file is the single global style owner for the book. Components are local
// content primitives and deliberately do not install competing global show rules.

#let report-navy = rgb("#0B1F33")
#let report-blue = rgb("#1769AA")
#let report-cyan = rgb("#007F8B")
#let report-amber = rgb("#B45309")
#let report-ink = rgb("#162433")
#let report-muted = rgb("#526577")
#let report-paper = rgb("#FFFDFC")
#let report-mist = rgb("#EAF4F6")
#let report-accent = report-blue

// Relative rhythm values use B = body size. The English book profile preserves
// the base's chapter-emphasis rhythm while fitting long technical prose on 7×10 in.
#let report-rhythms = (
  report: (
    paragraph-gap: 0.62,
    leading: 0.34,
    first-line-indent: none,
    levels: (
      h1: (size: 1.72, before: 2.05, after: 0.82, weight: 700),
      h2: (size: 1.34, before: 1.56, after: 0.56, weight: 700),
      h3: (size: 1.13, before: 1.14, after: 0.42, weight: 650),
      h4: (size: 1.00, before: 0.94, after: 0.32, weight: 650),
    ),
  ),
  longform: (
    paragraph-gap: 0.48,
    leading: 0.31,
    first-line-indent: none,
    levels: (
      h1: (size: 1.72, before: 1.88, after: 0.74, weight: 700),
      h2: (size: 1.31, before: 1.40, after: 0.48, weight: 700),
      h3: (size: 1.12, before: 1.05, after: 0.36, weight: 650),
      h4: (size: 1.00, before: 0.84, after: 0.28, weight: 650),
    ),
  ),
)

#let report-rule(fill: report-cyan) = line(length: 100%, stroke: 1.2pt + fill)

// Put this before a level-one heading when a chapter needs an intentional opener.
// The actual heading remains semantic, numbered, and available to the outline.
#let chapter-opener(part: none, chapter: none, eyebrow: "CHAPTER") = block(
  above: 1.2em,
  below: 0.35em,
  width: 100%,
)[
  #set text(font: "Noto Sans", size: 8.2pt, weight: 700, tracking: 0.08em, fill: report-cyan)
  #if part != none [PART #part]
  #if part != none and chapter != none [  ·  ]
  #if chapter != none [#eyebrow #chapter]
  #v(0.42em)
  #line(length: 34%, stroke: 1.6pt + report-amber)
]

// A deliberate recto-like visual reset for the six major book divisions.
#let part-opener(number, title, deck: none) = [
  #pagebreak()
  #block(width: 100%, inset: (top: 1.15in, bottom: 0.78in))[
    #set align(left)
    #text(font: "Noto Sans", size: 9pt, weight: 700, tracking: 0.11em, fill: report-cyan)[PART #number]
    #v(0.65em)
    #text(font: "Noto Sans", size: 29pt, weight: 700, fill: report-navy)[#title]
    #v(0.7em)
    #line(length: 48%, stroke: 2.1pt + report-amber)
    #if deck != none [
      #v(1.15em)
      #set text(font: "Libertinus Serif", size: 13pt, fill: report-ink)
      #block(width: 84%)[#deck]
    ]
  ]
  #pagebreak()
]

#let report-theme(
  title: none,
  author: none,
  rhythm: "longform",
  body-size: 10pt,
  first-line-indent: none,
  paragraph-spacing: none,
  running-header: true,
  body,
) = {
  if title != none or author != none {
    set document(title: title, author: author)
  }

  let p = report-rhythms.at(rhythm)
  let paragraph-gap = if paragraph-spacing == none {
    p.paragraph-gap * body-size
  } else {
    paragraph-spacing
  }
  let indent = if first-line-indent == none { p.first-line-indent } else { first-line-indent }
  let h1 = p.levels.h1
  let h2 = p.levels.h2
  let h3 = p.levels.h3
  let h4 = p.levels.h4

  set page(
    width: 7in,
    height: 10in,
    margin: (top: 0.76in, bottom: 0.72in, left: 0.84in, right: 0.66in),
    fill: report-paper,
    numbering: "1",
    header: if running-header {
      context {
        set text(font: "Noto Sans", size: 7.7pt, fill: report-muted)
        grid(
          columns: (1fr, auto),
          column-gutter: 0.7em,
          align: (left, right),
          [#title],
          [#author],
        )
        v(0.32em)
        line(length: 100%, stroke: 0.45pt + rgb("#B8CDD2"))
      }
    } else { none },
    footer: context {
      set text(font: "Noto Sans", size: 8pt, fill: report-muted)
      align(center)[
        #line(length: 1.4em, stroke: 0.8pt + report-amber)
        #h(0.65em)#counter(page).display()#h(0.65em)
        #line(length: 1.4em, stroke: 0.8pt + report-amber)
      ]
    },
  )

  set text(font: "Libertinus Serif", size: body-size, lang: "en", region: "us", fill: report-ink)
  set par(
    justify: true,
    leading: p.leading * body-size,
    spacing: paragraph-gap,
    first-line-indent: if indent == none { 0pt } else { (amount: indent, all: false) },
  )
  set heading(numbering: "1.1")
  show heading: set text(font: "Noto Sans", fill: report-navy)
  show heading.where(level: 1): set text(size: h1.size * body-size, weight: h1.weight)
  show heading.where(level: 1): set block(
    above: h1.before * body-size,
    below: h1.after * body-size,
    sticky: true,
    breakable: false,
  )
  show heading.where(level: 2): set text(size: h2.size * body-size, weight: h2.weight)
  show heading.where(level: 2): set block(
    above: h2.before * body-size,
    below: h2.after * body-size,
    sticky: true,
    breakable: false,
  )
  show heading.where(level: 3): set text(size: h3.size * body-size, weight: h3.weight)
  show heading.where(level: 3): set block(
    above: h3.before * body-size,
    below: h3.after * body-size,
    sticky: true,
    breakable: false,
  )
  show heading.where(level: 4): set text(size: h4.size * body-size, weight: h4.weight)
  show heading.where(level: 4): set block(
    above: h4.before * body-size,
    below: h4.after * body-size,
    sticky: true,
    breakable: false,
  )

  show raw: set text(font: "DejaVu Sans Mono", size: 0.88em, fill: report-ink)
  show raw.where(block: true): it => block(
    fill: rgb("#F1F7F8"),
    stroke: 0.55pt + rgb("#B8CDD2"),
    inset: (x: 9pt, y: 8pt),
    radius: 3pt,
    width: 100%,
    text(font: "DejaVu Sans Mono", size: 8.15pt, fill: report-ink, it),
  )
  show link: set text(fill: report-blue)
  show figure: set block(breakable: true)

  body
}
