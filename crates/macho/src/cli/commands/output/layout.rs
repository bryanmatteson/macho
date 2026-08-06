//! Column layout backed by the `laidout` pretty-printing kernel.
//!
//! Cells carry their theme token as a layout annotation rather than embedded
//! ANSI. Laying out unstyled text is what makes the columns correct: escape
//! sequences never count toward a column's width, and every run is measured by
//! its Unicode display width, so a name containing wide characters occupies the
//! columns it actually paints.
//!
//! Styling is applied after layout by walking the annotated runs, so the theme
//! stays the only place that knows about ANSI.

use std::num::NonZeroU32;

use laidout::{Column, Doc, RenderOptions, Table, render};
use termosaic::{HumanText, TokenId};

use super::Style;

/// One laid-out cell: unstyled text tagged with the tokens that paint it.
pub type Cell = Doc<TokenId>;

/// The width used when a caller does not constrain the output.
///
/// Rows are laid out on one line each, matching a terminal that never wraps.
/// Callers wanting reflow pass their own width to [`align_to`].
const UNCONSTRAINED: u32 = 1 << 20;

/// A cell holding one token's text.
pub fn cell(token: &TokenId, value: &str) -> Cell {
    Doc::annotate(token.clone(), plain(value))
}

/// A cell holding unstyled text.
pub fn plain_cell(value: &str) -> Cell {
    plain(value)
}

/// A `key=value` cell whose key and value paint differently.
pub fn property_cell(key_token: &TokenId, key: &str, value_token: &TokenId, value: &str) -> Cell {
    Doc::concat([
        Doc::annotate(key_token.clone(), plain(&format!("{key}="))),
        Doc::annotate(value_token.clone(), plain(value)),
    ])
}

/// Join cells side by side without a column boundary between them.
pub fn join_cells(cells: impl IntoIterator<Item = Cell>) -> Cell {
    Doc::concat(cells)
}

/// Lay out `rows` into left-aligned columns separated by two spaces.
///
/// The result is one styled line per row, with trailing padding removed.
pub fn align(rows: &[Vec<Cell>], style: Style) -> Vec<String> {
    align_to(rows, style, UNCONSTRAINED)
}

/// Lay out `rows` within `width` columns.
pub fn align_to(rows: &[Vec<Cell>], style: Style, width: u32) -> Vec<String> {
    if rows.is_empty() {
        return Vec::new();
    }
    let column_count = rows.iter().map(Vec::len).max().unwrap_or(0);
    if column_count == 0 {
        return rows.iter().map(|_| String::new()).collect();
    }

    let mut table =
        Table::<TokenId>::new((0..column_count).map(|_| Column::<TokenId>::unlabeled()));
    for row in rows {
        table.push_row(row.iter().cloned());
    }
    let Ok(document) = table.build() else {
        // A cell the table cannot measure is a construction error, not a
        // reason to lose the row; fall back to unaligned text.
        return rows.iter().map(|row| unaligned(row, style)).collect();
    };

    let width = NonZeroU32::new(width.max(1)).expect("width is at least one");
    // `LayoutStrategy::Fast` never selects a table's compact form, so tables
    // use the exact solver.
    let options = RenderOptions::new(width);
    let Ok(rendered) = render(&document, options) else {
        return rows.iter().map(|row| unaligned(row, style)).collect();
    };

    let mut output = String::new();
    for run in rendered.annotated_runs() {
        match run.annotations.first() {
            Some(token) => paint_run(&mut output, style, token, run.text),
            None => output.push_str(run.text),
        }
    }
    output
        .split('\n')
        .map(|line| line.trim_end().to_owned())
        .collect()
}

/// Paint one run, keeping each line independently styled.
///
/// A run can straddle a line break when a table falls back to stacking cells;
/// styling each segment keeps every line's escapes balanced on that line.
fn paint_run(output: &mut String, style: Style, token: &TokenId, text: &str) {
    let mut lines = text.split('\n');
    if let Some(first) = lines.next() {
        push_painted(output, style, token, first);
    }
    for line in lines {
        output.push('\n');
        push_painted(output, style, token, line);
    }
}

fn push_painted(output: &mut String, style: Style, token: &TokenId, text: &str) {
    if text.is_empty() {
        return;
    }
    output.push_str(&style.token(token, text));
}

/// Render one row without column padding, for the rare unmeasurable row.
///
/// No cell built by this module can reach here: a table only rejects headers,
/// choice-bearing cells, and cells with no flat projection, while these columns
/// are unlabeled and every cell is text, concatenation, or annotation. The path
/// exists so a future cell constructor that does introduce a choice degrades to
/// unaligned output instead of dropping the row.
fn unaligned(row: &[Cell], style: Style) -> String {
    let document = Doc::concat(
        row.iter()
            .cloned()
            .flat_map(|cell| [cell, plain("  ")])
            .take(row.len().saturating_mul(2).saturating_sub(1)),
    );
    let options =
        RenderOptions::new(NonZeroU32::new(UNCONSTRAINED).expect("constant width is non-zero"));
    match render(&document, options) {
        Ok(rendered) => {
            let mut output = String::new();
            for run in rendered.annotated_runs() {
                match run.annotations.first() {
                    Some(token) => paint_run(&mut output, style, token, run.text),
                    None => output.push_str(run.text),
                }
            }
            output.trim_end().to_owned()
        }
        Err(_) => String::new(),
    }
}

/// Build a text document, replacing control characters the layout cannot carry.
fn plain(value: &str) -> Cell {
    Doc::text(HumanText::sanitize(value).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use termosaic::tokens;

    fn style() -> Style {
        Style::new(false)
    }

    #[test]
    fn columns_align_to_their_widest_cell() {
        let rows = vec![
            vec![plain_cell("a"), plain_cell("alpha")],
            vec![plain_cell("bbbb"), plain_cell("b")],
        ];
        assert_eq!(align(&rows, style()), vec!["a     alpha", "bbbb  b"]);
    }

    #[test]
    fn trailing_padding_is_removed() {
        let rows = vec![
            vec![plain_cell("a"), plain_cell("long-value")],
            vec![plain_cell("b"), plain_cell("x")],
        ];
        for line in align(&rows, style()) {
            assert_eq!(line, line.trim_end(), "no line keeps trailing padding");
        }
    }

    #[test]
    fn wide_characters_are_measured_by_display_width() {
        // Three ideographs paint six columns. Measuring by character count
        // would call this name three wide and ragged the next column.
        let rows = vec![
            vec![plain_cell("\u{65e5}\u{672c}\u{8a9e}"), plain_cell("wide")],
            vec![plain_cell("abcdef"), plain_cell("ascii")],
        ];
        let lines = align(&rows, style());
        let starts = lines
            .iter()
            .map(|line| {
                let gutter = line.rfind("  ").expect("column gutter");
                line[..gutter].chars().count()
            })
            .collect::<Vec<_>>();
        // The ASCII name is six characters and six columns; the ideographs are
        // three characters and six columns, so both second cells start together.
        assert_eq!(starts[0], 3, "the wide name stays three characters");
        assert_eq!(starts[1], 6, "the ASCII name stays six characters");
        assert!(lines[0].ends_with("wide") && lines[1].ends_with("ascii"));
    }

    #[test]
    fn ragged_rows_keep_every_cell() {
        let rows = vec![
            vec![plain_cell("one")],
            vec![plain_cell("one"), plain_cell("two"), plain_cell("three")],
        ];
        let lines = align(&rows, style());
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("three"));
    }

    #[test]
    fn annotations_paint_only_when_color_is_enabled() {
        let rows = vec![vec![cell(&tokens::DATA_NUMBER, "42")]];
        assert_eq!(align(&rows, Style::new(false)), vec!["42"]);
        let colored = align(&rows, Style::new(true));
        assert!(
            colored[0].contains("42") && colored[0].contains('\u{1b}'),
            "expected ANSI around the value: {colored:?}"
        );
    }

    #[test]
    fn property_cells_keep_key_and_value_in_one_column() {
        let rows = vec![vec![property_cell(
            &tokens::TEXT_MUTED,
            "size",
            &tokens::DATA_NUMBER,
            "8",
        )]];
        assert_eq!(align(&rows, style()), vec!["size=8"]);
    }

    #[test]
    fn empty_input_produces_no_lines() {
        assert!(align(&[], style()).is_empty());
    }
}
