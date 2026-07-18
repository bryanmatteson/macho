//! Column alignment for human-readable output.

/// Left-align rows into columns separated by a two-space gutter.
///
/// Widths are computed across the complete row set. The final cell is not
/// padded and trailing whitespace is removed from every rendered line.
pub fn align(rows: &[Vec<String>]) -> Vec<String> {
    let column_count = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0usize; column_count];
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(display_width(cell));
        }
    }

    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (index, cell) in row.iter().enumerate() {
                if index > 0 {
                    line.push_str("  ");
                }
                line.push_str(cell);
                if index + 1 < row.len() {
                    let pad = widths[index].saturating_sub(display_width(cell));
                    line.extend(std::iter::repeat_n(' ', pad));
                }
            }
            line.truncate(line.trim_end_matches(' ').len());
            line
        })
        .collect()
}

fn display_width(value: &str) -> usize {
    let mut width = 0;
    let mut in_sgr = false;
    for character in value.chars() {
        if in_sgr {
            if character == 'm' {
                in_sgr = false;
            }
        } else if character == '\u{1b}' {
            in_sgr = true;
        } else {
            width += 1;
        }
    }
    width
}

#[cfg(test)]
mod tests {
    use super::align;

    fn rows(raw: &[&[&str]]) -> Vec<Vec<String>> {
        raw.iter()
            .map(|row| row.iter().map(|cell| cell.to_string()).collect())
            .collect()
    }

    #[test]
    fn mixed_width_cells_align_every_column() {
        let output = align(&rows(&[
            &[
                "__TEXT",
                "VM",
                "0x100000000",
                "(0x20)",
                "File",
                "0x00000000",
            ],
            &[
                "__DATA_CONST",
                "VM",
                "0x100000020",
                "(0x1000)",
                "File",
                "0x00000020",
            ],
        ]));
        let vm_offsets = output
            .iter()
            .map(|line| line.find("VM").expect("VM column"))
            .collect::<Vec<_>>();
        let file_offsets = output
            .iter()
            .map(|line| line.find("File").expect("File column"))
            .collect::<Vec<_>>();
        assert_eq!(vm_offsets[0], vm_offsets[1]);
        assert_eq!(file_offsets[0], file_offsets[1]);
    }

    #[test]
    fn empty_trailing_cells_do_not_leave_whitespace() {
        let output = align(&rows(&[&["id", "name", ""], &["id2", "n", "value"]]));
        assert_eq!(output[0], "id   name");
        assert!(!output.iter().any(|line| line.ends_with(' ')));
    }

    #[test]
    fn ansi_sgr_sequences_do_not_change_column_widths() {
        let output = align(&rows(&[
            &["\u{1b}[36m0x1\u{1b}[0m", "0x8", "[nlist]"],
            &["\u{1b}[36m0x100\u{1b}[0m", "0x48", "[export]"],
        ]));
        let plain = output
            .iter()
            .map(|line| line.replace("\u{1b}[36m", "").replace("\u{1b}[0m", ""))
            .collect::<Vec<_>>();
        assert_eq!(plain[0].find("0x8"), plain[1].find("0x48"));
        assert_eq!(plain[0].find("[nlist]"), plain[1].find("[export]"));
    }
}
