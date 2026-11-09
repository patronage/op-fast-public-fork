//! Error types that map to specific exit behavior.

use std::fmt;

/// Exit code when 1Password approval was needed, was unavailable, and
/// nothing could be served (BSD `EX_TEMPFAIL`).
pub const EXIT_NEEDS_APPROVAL: i32 = 75;

pub const NEEDS_APPROVAL_REMEDY: &str =
    "run 'op-fast warm' at the desk, or configure a service account";

/// Why a delegate call failed. Recorded in the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    ApprovalUnavailable,
    NotFound,
    InvalidReference,
    Permission,
    RateLimit,
    Other,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::ApprovalUnavailable => "approval-unavailable",
            ErrorClass::NotFound => "not-found",
            ErrorClass::InvalidReference => "invalid-reference",
            ErrorClass::Permission => "permission",
            ErrorClass::RateLimit => "rate-limit",
            ErrorClass::Other => "other",
        }
    }

    /// Classify a failed `op` call from its stderr. `timed_out` means
    /// op-fast killed it at a deadline.
    pub fn classify(stderr: &str, timed_out_waiting_for_approval: bool) -> Self {
        if timed_out_waiting_for_approval {
            return ErrorClass::ApprovalUnavailable;
        }
        let s = stderr.to_ascii_lowercase();
        let any = |needles: &[&str]| needles.iter().any(|n| s.contains(n));

        if any(&[
            "authorization timeout",
            "authorization prompt dismissed",
            "authorization prompt was dismissed",
            "connecting to desktop app",
            "connect to desktop app",
            "connect to the 1password app",
            "connect to 1password app",
            "1password app is not running",
            "desktop app is not running",
            "cannot connect to 1password",
            "couldn't connect to 1password",
            "could not connect to 1password",
        ]) {
            ErrorClass::ApprovalUnavailable
        } else if any(&["rate limit", "too many requests", "(429)"]) {
            ErrorClass::RateLimit
        } else if any(&[
            "invalid secret reference",
            "invalid reference",
            "could not parse",
            "too many '/'",
            "is not a valid secret reference",
        ]) {
            ErrorClass::InvalidReference
        } else if any(&[
            "isn't an item",
            "isn't a vault",
            "isn't a field",
            "no item found",
            "not found",
            "could not find",
            "does not have a field",
            "doesn't exist",
        ]) {
            ErrorClass::NotFound
        } else if any(&[
            "permission denied",
            "forbidden",
            "access denied",
            "not authorized",
            "unauthorized",
            "(403)",
            "(401)",
            "invalid token",
            "token is invalid",
        ]) {
            ErrorClass::Permission
        } else {
            ErrorClass::Other
        }
    }
}

/// A failed delegate call. `message` is the delegate's stderr, already
/// stripped of any token text.
#[derive(Debug)]
pub struct DelegateError {
    pub class: ErrorClass,
    pub code: i32,
    pub message: String,
}

impl fmt::Display for DelegateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message.trim_end())
    }
}

impl std::error::Error for DelegateError {}

/// Approval was needed and unavailable, and nothing could be served.
#[derive(Debug)]
pub struct NeedsApproval {
    pub subjects: Vec<String>,
}

impl NeedsApproval {
    pub fn line(&self) -> String {
        format!(
            "op-fast: needs approval: {}; {}",
            self.subjects.join(", "),
            NEEDS_APPROVAL_REMEDY
        )
    }
}

impl fmt::Display for NeedsApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.line())
    }
}

impl std::error::Error for NeedsApproval {}

/// Exit with a specific code after the command already printed what it
/// needed to.
#[derive(Debug)]
pub struct ExitCode(pub i32);

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exit {}", self.0)
    }
}

impl std::error::Error for ExitCode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_op_messages() {
        let c = ErrorClass::classify;
        assert_eq!(
            c(
                "[ERROR] 2026/01/01 error initializing client: authorization timeout",
                false
            ),
            ErrorClass::ApprovalUnavailable
        );
        assert_eq!(
            c(
                "[ERROR] authorization prompt dismissed, please try again",
                false
            ),
            ErrorClass::ApprovalUnavailable
        );
        assert_eq!(c("", true), ErrorClass::ApprovalUnavailable);
        assert_eq!(
            c(
                r#"[ERROR] could not read secret: "nope" isn't an item in the "V" vault"#,
                false
            ),
            ErrorClass::NotFound
        );
        assert_eq!(
            c(
                "[ERROR] invalid secret reference 'op://x': too many '/'",
                false
            ),
            ErrorClass::InvalidReference
        );
        assert_eq!(c("[ERROR] (403) Forbidden", false), ErrorClass::Permission);
        assert_eq!(
            c("[ERROR] (429) Too Many Requests", false),
            ErrorClass::RateLimit
        );
        assert_eq!(c("[ERROR] something else", false), ErrorClass::Other);
    }

    #[test]
    fn needs_approval_line_shape() {
        let e = NeedsApproval {
            subjects: vec!["op://a/b/c".into(), "op://d/e/f".into()],
        };
        assert_eq!(
            e.line(),
            "op-fast: needs approval: op://a/b/c, op://d/e/f; run 'op-fast warm' at the desk, or configure a service account"
        );
    }
}
