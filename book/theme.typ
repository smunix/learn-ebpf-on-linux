// Book-facing compatibility layer. Global styling stays in report-theme.typ.
#import "report-theme.typ": report-theme, report-accent, report-amber, report-blue, report-cyan, report-ink, report-mist, report-navy, report-paper, report-rule, chapter-opener, part-opener

#let book-theme = report-theme
#let palette = (
  navy: report-navy,
  blue: report-blue,
  cyan: report-cyan,
  amber: report-amber,
  ink: report-ink,
  paper: report-paper,
  mist: report-mist,
)
