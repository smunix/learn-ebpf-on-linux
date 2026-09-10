// Linked, explicit cross-reference helpers. Supply a concise title whenever
// a reader benefits from context; the generated number stays owned by Typst.
#let xref(target, kind: "Section", title: none) = link(target)[
  #kind #ref(target, supplement: none)
  #if title != none [ — #title]
]

#let chapter-ref(target, title: none) = xref(target, kind: "Chapter", title: title)
#let section-ref(target, title: none) = xref(target, kind: "Section", title: title)
#let figure-ref(target, title: none) = xref(target, kind: "Figure", title: title)
#let table-ref(target, title: none) = xref(target, kind: "Table", title: title)
#let listing-ref(target, title: none) = xref(target, kind: "Listing", title: title)
#let page-ref(target) = link(target)[page #ref(target, form: "page")]

// Apply a stable label to prose definitions that do not otherwise create a target.
#let definition-target(id, term, body) = [
  #block(
    above: 0.7em,
    below: 0.7em,
    fill: rgb("#F6F9FA"),
    stroke: (left: 2pt + rgb("#007F8B"), rest: 0pt + none),
    inset: (left: 8pt, right: 8pt, top: 5pt, bottom: 5pt),
  )[
    #text(font: "Noto Sans", weight: 700)[#term]
    #h(0.35em)— #body
  ]
  #label(id)
]
