// First-use acronym and glossary-term helpers. The contextual state settles
// during Typst layout so each short form is expanded once in reading order.
#import "../glossary.typ": glossary-entry

#let seen-acronyms = state("learn-ebpf-acronyms", ())

#let acronym(key) = context {
  let entry = glossary-entry(key)
  let seen = seen-acronyms.get()
  if key in seen {
    [#entry.short]
  } else {
    seen-acronyms.update(old => old + (key,))
    [#entry.term (#entry.short)]
  }
}

#let glossary-term(key) = {
  let entry = glossary-entry(key)
  [#entry.term]
}

#let reset-acronyms() = seen-acronyms.update(())
