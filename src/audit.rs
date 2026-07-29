//! Local, append-only audit log of secret access.
//!
//! Every cache hit, delegate fetch, store mutation, and passthrough is
//! recorded as one JSON line, including which process chain asked. Secret
//! values are never written. Logging is best-effort: failures warn on
//! stderr but never block an operation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub ts: u64,
    pub op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<&'a str>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_remaining: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a str>,
    pub pid: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}

/// Record one audit event. Never fails; never blocks the caller.
pub fn record(
    op: &'static str,
    reference: Option<&str>,
    outcome: &'static str,
    ttl_remaining: Option<u64>,
    command: Option<&str>,
) {
    if let Err(e) = try_record(op, reference, outcome, ttl_remaining, command) {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| eprintln!("[op-fast] warning: audit log unavailable: {}", e));
    }
}

fn try_record(
    op: &'static str,
    reference: Option<&str>,
    outcome: &'static str,
    ttl_remaining: Option<u64>,
    command: Option<&str>,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let dir = audit_dir().context("could not determine audit directory")?;
    try_record_to(&dir, op, reference, outcome, ttl_remaining, command)
}

fn try_record_to(
    dir: &std::path::Path,
    op: &'static str,
    reference: Option<&str>,
    outcome: &'static str,
    ttl_remaining: Option<u64>,
    command: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    // Converge pre-existing directories created before the 0700 policy.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let stamp = month_stamp(now);
    let path = dir.join(format!("{}.jsonl", stamp));

    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > MAX_LOG_BYTES
    {
        let _ = std::fs::rename(&path, dir.join(format!("{}.jsonl.old", stamp)));
    }

    let event = Event {
        ts: now,
        op,
        reference,
        outcome,
        ttl_remaining,
        command,
        pid: std::process::id(),
        chain: process_chain(),
    };
    let line = serde_json::to_string(&event)?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// `YYYY-MM` (UTC) for a unix timestamp — names the log file for that month.
pub(crate) fn month_stamp(secs: u64) -> String {
    let (year, month) = civil_year_month(secs / 86_400);
    format!("{:04}-{:02}", year, month)
}

// Howard Hinnant's civil-from-days algorithm, trimmed to year/month.
fn civil_year_month(days_since_epoch: u64) -> (i64, u32) {
    let z = days_since_epoch as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m)
}

/// Directory holding audit log files.
pub(crate) fn audit_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("OP_FAST_STORE_DIR") {
        return Some(PathBuf::from(path).join("audit"));
    }

    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_sys::home_dir().map(|h| h.join(".local/share")))
        .map(|dir| dir.join("op-fast").join("audit"))
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Summary {
    pub total: usize,
    pub malformed: usize,
    pub by_outcome: BTreeMap<String, usize>,
    pub by_reference: BTreeMap<String, usize>,
}

/// Aggregate parsed JSONL lines into counts. Malformed lines are counted,
/// never fatal.
pub(crate) fn summarize<'a, I: Iterator<Item = &'a str>>(lines: I) -> Summary {
    let mut summary = Summary::default();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                summary.total += 1;
                if let Some(outcome) = value.get("outcome").and_then(|v| v.as_str()) {
                    *summary.by_outcome.entry(outcome.to_string()).or_insert(0) += 1;
                }
                if let Some(reference) = value.get("reference").and_then(|v| v.as_str()) {
                    *summary
                        .by_reference
                        .entry(reference.to_string())
                        .or_insert(0) += 1;
                }
            }
            Err(_) => summary.malformed += 1,
        }
    }
    summary
}

/// Best-effort ancestor chain of the current process: `name(pid)` entries,
/// nearest first, at most three levels. Empty on any failure.
#[cfg(target_os = "macos")]
pub(crate) fn process_chain() -> Vec<String> {
    let mut chain = Vec::new();
    let mut pid = std::os::unix::process::parent_id() as i32;
    for _ in 0..3 {
        if pid <= 1 {
            break;
        }
        let name = proc_name(pid).unwrap_or_else(|| "?".to_string());
        chain.push(format!("{}({})", name, pid));
        match proc_ppid(pid) {
            Some(ppid) if ppid > 0 && ppid != pid => pid = ppid,
            _ => break,
        }
    }
    chain
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn process_chain() -> Vec<String> {
    // No libproc; ancestry attribution is macOS-only for now.
    Vec::new()
}

#[cfg(target_os = "macos")]
fn proc_name(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..n as usize]).to_string();
    path.rsplit('/').next().map(|name| name.to_string())
}

#[cfg(target_os = "macos")]
fn proc_ppid(pid: i32) -> Option<i32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n < size {
        return None;
    }
    Some(info.pbi_ppid as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_stamp_formats_known_dates() {
        assert_eq!(month_stamp(0), "1970-01");
        assert_eq!(month_stamp(1_000_000_000), "2001-09"); // 2001-09-09
        assert_eq!(month_stamp(1_704_067_200), "2024-01"); // 2024-01-01
        assert_eq!(month_stamp(951_782_400), "2000-02"); // 2000-02-29 (leap)
    }

    #[test]
    fn event_serializes_with_stable_schema_and_omits_empty_fields() {
        let event = Event {
            ts: 1000,
            op: "read",
            reference: Some("op://a/b/c"),
            outcome: "hit",
            ttl_remaining: Some(3600),
            command: None,
            pid: 42,
            chain: vec!["zsh(41)".into(), "claude(40)".into()],
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"ts":1000,"op":"read","reference":"op://a/b/c","outcome":"hit","ttl_remaining":3600,"pid":42,"chain":["zsh(41)","claude(40)"]}"#
        );

        let bare = Event {
            ts: 1000,
            op: "passthrough",
            reference: None,
            outcome: "delegated",
            ttl_remaining: None,
            command: Some("whoami"),
            pid: 42,
            chain: Vec::new(),
        };
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            r#"{"ts":1000,"op":"passthrough","outcome":"delegated","command":"whoami","pid":42}"#
        );
    }

    #[test]
    fn summarize_counts_outcomes_and_references_and_tolerates_garbage() {
        let lines = [
            r#"{"ts":1,"op":"read","reference":"op://a/b/c","outcome":"hit","pid":1}"#,
            r#"{"ts":2,"op":"read","reference":"op://a/b/c","outcome":"fetched","pid":1}"#,
            r#"{"ts":3,"op":"run","reference":"op://d/e/f","outcome":"hit","pid":1}"#,
            "not json at all",
        ];
        let summary = summarize(lines.iter().copied());
        assert_eq!(summary.total, 3);
        assert_eq!(summary.malformed, 1);
        assert_eq!(summary.by_outcome.get("hit"), Some(&2));
        assert_eq!(summary.by_outcome.get("fetched"), Some(&1));
        assert_eq!(summary.by_reference.get("op://a/b/c"), Some(&2));
        assert_eq!(summary.by_reference.get("op://d/e/f"), Some(&1));
    }

    #[test]
    fn audit_dir_and_log_file_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!("op-fast-audit-test-{}", std::process::id()));
        let dir = base.join("audit");
        try_record_to(&dir, "read", Some("op://t/t/t"), "hit", Some(1), None).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let entry = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap();
        let file_mode = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn process_chain_reports_at_least_the_parent() {
        // Under `cargo test` the parent is the test runner / shell.
        let chain = process_chain();
        assert!(!chain.is_empty());
        assert!(chain[0].contains('('));
    }
}
