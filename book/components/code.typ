// Listings are local components; report-theme.typ owns the global raw-code style.
#import "../theme.typ": report-ink, report-navy

// Pass code as a string (typically `read(path)`). `source-path` is a visible
// provenance label, distinct from the code text itself.
#let code-listing(title, code, language: "text", source-path: none) = figure(
  kind: "listing",
  supplement: [Listing],
  caption: [
    #text(font: "Noto Sans", size: 8.3pt, weight: 700, fill: report-navy)[#title]
    #if source-path != none [ #text(fill: report-ink)[— #source-path]]
  ],
  block(
    width: 100%,
    fill: rgb("#F1F7F8"),
    stroke: 0.55pt + rgb("#B8CDD2"),
    inset: 9pt,
    radius: 3pt,
    if type(code) == str {
      raw(code, lang: language, block: true)
    } else {
      code
    },
  ),
)

// Keep listings honest: import the canonical repository file rather than a copied snippet.
// `lines` uses inclusive one-based bounds when supplied.
#let code-file(path, title: none, language: "text", lines: none, source-path: none) = {
  let text = read(path)
  let selected = if lines == none {
    text
  } else {
    let all = text.split("\n")
    all.slice(lines.first() - 1, lines.last()).join("\\n")
  }
  let caption = if title == none { path } else { title }
  code-listing(caption, selected, language: language, source-path: if source-path == none { path } else { source-path })
}

#let terminal-listing(title: "Terminal", code) = code-listing(title, code, language: "bash", source-path: "expected command")
