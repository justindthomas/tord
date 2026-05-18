//! Output formatting for `tord query`.
//!
//! The control socket always speaks JSON; this module renders a
//! reply for a terminal. `table` (the default) is human-readable;
//! `json` passes the reply through pretty-printed for scripts.
//!
//! The split — JSON on the wire, presentation in the CLI — is the
//! pattern intended for every imp daemon's query tool, so the
//! rendering here is deliberately generic: a key/value view for
//! object replies and a column table for list replies, driven off
//! the JSON shape rather than hard-coded per command.

use std::fmt::Write;

use serde_json::Value;

/// How `tord query` renders a reply.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text — key/value or a column table.
    Table,
    /// Pretty-printed JSON, as received on the wire.
    Json,
}

/// Render a control-socket reply for display.
pub fn render(command: &str, reply: &str, format: OutputFormat) -> String {
    let value: Value = match serde_json::from_str(reply) {
        Ok(v) => v,
        // The control socket should always send JSON; if it somehow
        // did not, show the raw bytes rather than nothing.
        Err(_) => return reply.trim_end().to_string(),
    };
    match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| reply.trim_end().to_string())
        }
        OutputFormat::Table => render_table(command, &value),
    }
}

fn render_table(command: &str, v: &Value) -> String {
    // Error reply: {"status":"error","message":"..."}.
    if v.get("status").and_then(Value::as_str) == Some("error") {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return format!("error: {msg}");
    }
    // List reply (the `streams` command): {"status":"ok","streams":[…]}.
    if let Some(rows) = v.get("streams").and_then(Value::as_array) {
        return render_streams(rows);
    }
    // Everything else: a key/value object.
    render_kv(command, v)
}

/// Render an object reply (`status`, `stats`, `ping`, `reload`) as
/// aligned `key: value` lines, recursing into nested objects.
fn render_kv(command: &str, v: &Value) -> String {
    let mut lines: Vec<(String, Option<String>)> = Vec::new();
    collect_kv(v, 0, &mut lines);
    if lines.is_empty() {
        return format!("{command}: ok");
    }
    let key_width = lines
        .iter()
        .filter(|(_, val)| val.is_some())
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (key, val) in &lines {
        match val {
            Some(s) => {
                let _ = writeln!(out, "{key:<key_width$}   {s}");
            }
            // Nested-object header.
            None => {
                let _ = writeln!(out, "{key}:");
            }
        }
    }
    out.trim_end().to_string()
}

/// Flatten an object into `(display-key, value)` lines. A `None`
/// value marks a nested-object header; its children follow indented.
fn collect_kv(v: &Value, indent: usize, out: &mut Vec<(String, Option<String>)>) {
    let Some(obj) = v.as_object() else {
        return;
    };
    for (k, val) in obj {
        // `status` is protocol framing, not data — drop it.
        if indent == 0 && k == "status" {
            continue;
        }
        let key = format!("{}{}", "  ".repeat(indent), k);
        if val.is_object() {
            out.push((key, None));
            collect_kv(val, indent + 1, out);
        } else {
            out.push((key, Some(scalar(val))));
        }
    }
}

/// Render the `streams` list as an aligned column table.
fn render_streams(rows: &[Value]) -> String {
    if rows.is_empty() {
        return "no active connections".to_string();
    }
    let mut table: Vec<Vec<String>> = vec![[
        "ID", "PEER", "TARGET", "ISO", "AGE", "UP", "DOWN",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()];
    for r in rows {
        table.push(vec![
            r.get("id").map(scalar).unwrap_or_default(),
            field(r, "peer"),
            field(r, "target"),
            field(r, "isolation"),
            human_age(r.get("age_secs").and_then(Value::as_u64).unwrap_or(0)),
            human_bytes(r.get("bytes_to_upstream").and_then(Value::as_u64).unwrap_or(0)),
            human_bytes(r.get("bytes_to_client").and_then(Value::as_u64).unwrap_or(0)),
        ]);
    }
    let cols = table[0].len();
    let mut width = vec![0usize; cols];
    for row in &table {
        for (i, cell) in row.iter().enumerate() {
            width[i] = width[i].max(cell.len());
        }
    }
    let mut out = String::new();
    for row in &table {
        let line: Vec<String> = row
            .iter()
            .zip(&width)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out.trim_end().to_string()
}

/// A string field, or `-` when absent or null.
fn field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        _ => "-".to_string(),
    }
}

/// Render a JSON scalar without the JSON quoting; `null` becomes `-`.
fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// `1536` → `1.5K`, for the byte columns.
fn human_bytes(n: u64) -> String {
    const UNIT: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNIT.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else {
        format!("{value:.1}{}", UNIT[unit])
    }
}

/// `75` → `1m15s`, for the age column.
fn human_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}
