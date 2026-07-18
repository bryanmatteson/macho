//! JSON serialization helpers for machine output.

use std::io::Write;

use serde::Serialize;
use serde_json::Value;

use super::Result;

/// Serialize one value as pretty JSON followed by a newline.
pub fn write_pretty<T: Serialize + ?Sized>(out: &mut dyn Write, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    out.write_all(&bytes)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Serialize one value as pretty JSON bytes.
pub fn to_vec_pretty<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(value)?)
}

/// Serialize one value as pretty JSON text without a terminal newline.
pub fn to_string_pretty<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Serialize per-architecture values, unwrapping the single-architecture case.
pub fn write_selected(values: Vec<(String, Value)>, out: &mut dyn Write) -> Result<()> {
    let value = if values.len() == 1 {
        values.into_iter().next().expect("one value").1
    } else {
        Value::Object(values.into_iter().collect())
    };
    write_pretty(out, &value)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{write_pretty, write_selected};

    #[test]
    fn pretty_json_has_one_terminal_newline() {
        let mut output = Vec::new();
        write_pretty(&mut output, &json!({ "ok": true })).expect("serialize");
        assert!(output.ends_with(b"}\n"));
        assert!(!output.ends_with(b"}\n\n"));
        serde_json::from_slice::<serde_json::Value>(&output).expect("valid JSON");
    }

    #[test]
    fn selected_json_unwraps_one_architecture() {
        let mut output = Vec::new();
        write_selected(
            vec![("arm64".to_owned(), json!({ "value": 1 }))],
            &mut output,
        )
        .expect("serialize");
        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(value, json!({ "value": 1 }));
    }
}
