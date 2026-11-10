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

    /// Classify a failed `op` call from its stderr.
    ///
    /// `references` are removed from the text first, along with every
    /// quoted segment, so an item, vault, or field *named* like an error
    /// message cannot steer the result. Specific failures (not found,
    /// permission, invalid reference, rate limit) win. Approval-unavailable
    /// needs an anchored message shape and is only possible for desktop
    /// calls (`desktop`); a service-account failure never is.
    pub fn classify(stderr: &str, references: &[&str], desktop: bool) -> Self {
        let lines: Vec<String> = stderr
            .lines()
            .map(|l| sanitize_line(l, references))
            .filter(|l| !l.is_empty())
            .collect();
        let any = |needles: &[&str]| lines.iter().any(|l| needles.iter().any(|n| l.contains(n)));

        if any(&[
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
        } else if any(&[
            "invalid secret reference",
            "invalid reference",
            "could not parse",
            "too many '/'",
            "is not a valid secret reference",
        ]) {
            ErrorClass::InvalidReference
        } else if any(&["rate limit", "too many requests", "(429)"]) {
            ErrorClass::RateLimit
        } else if desktop
            && lines
                .iter()
                .any(|l| APPROVAL_PREFIXES.iter().any(|p| l.starts_with(p)))
        {
            ErrorClass::ApprovalUnavailable
        } else {
            ErrorClass::Other
        }
    }
}

/// Message shapes (after the `[ERROR] <timestamp>` prefix) that mean the
/// desktop app could not give an approval. Matched as prefixes only.
const APPROVAL_PREFIXES: &[&str] = &[
    "error initializing client: authorization timeout",
    "error initializing client: authorization prompt dismissed",
    "error initializing client: connecting to desktop app",
    "error initializing client: cannot connect to the 1password app",
    "error initializing client: could not connect to the 1password app",
    "connecting to desktop app:",
    "authorization prompt dismissed",
];

/// Lowercase one stderr line, drop the `[ERROR] YYYY/MM/DD HH:MM:SS`
/// prefix, the reference texts, and every quoted segment.
fn sanitize_line(line: &str, references: &[&str]) -> String {
    let mut s = line.trim().to_string();
    for r in references {
        if !r.is_empty() {
            s = s.replace(r, "");
        }
    }
    // Drop quoted segments. A single quote only opens at a word start and
    // only closes at a word end, so apostrophes ("isn't") survive.
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut quote: Option<char> = None;
    for (i, &c) in chars.iter().enumerate() {
        let prev_alnum = i > 0 && chars[i - 1].is_alphanumeric();
        let next_alnum = chars.get(i + 1).is_some_and(|n| n.is_alphanumeric());
        match quote {
            Some(q) => {
                let closes = match q {
                    '\'' => c == '\'' && !next_alnum,
                    '\u{201c}' => c == '\u{201d}',
                    _ => c == q,
                };
                if closes {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\u{201c}' => quote = Some(c),
                '\'' if !prev_alnum => quote = Some(c),
                _ => out.push(c),
            },
        }
    }
    let mut rest = out.trim_start();
    if let Some(r) = rest.strip_prefix("[ERROR]") {
        rest = r.trim_start();
    }
    // Optional "YYYY/MM/DD HH:MM:SS" timestamp.
    let bytes = rest.as_bytes();
    if bytes.len() >= 19
        && bytes[4] == b'/'
        && bytes[7] == b'/'
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[..4].iter().all(u8::is_ascii_digit)
    {
        rest = rest[19..].trim_start();
    }
    rest.to_ascii_lowercase()
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
        let c = |m: &str| ErrorClass::classify(m, &[], true);
        assert_eq!(
            c("[ERROR] 2026/01/01 10:00:00 error initializing client: authorization timeout"),
            ErrorClass::ApprovalUnavailable
        );
        assert_eq!(
            c(
                "[ERROR] 2026/01/01 10:00:00 error initializing client: authorization prompt dismissed, please try again"
            ),
            ErrorClass::ApprovalUnavailable
        );
        assert_eq!(
            c(r#"[ERROR] could not read secret: "nope" isn't an item in the "V" vault"#),
            ErrorClass::NotFound
        );
        assert_eq!(
            c("[ERROR] invalid secret reference: too many '/' characters"),
            ErrorClass::InvalidReference
        );
        assert_eq!(c("[ERROR] (403) Forbidden"), ErrorClass::Permission);
        assert_eq!(c("[ERROR] (429) Too Many Requests"), ErrorClass::RateLimit);
        assert_eq!(c("[ERROR] something else"), ErrorClass::Other);
    }

    #[test]
    fn names_equal_to_trigger_phrases_cannot_force_approval_unavailable() {
        for phrase in [
            "authorization timeout",
            "error initializing client: authorization timeout",
            "authorization prompt dismissed",
            "connecting to desktop app:",
        ] {
            let item_ref = format!("op://Private/{}/password", phrase);
            let item = format!(
                "[ERROR] 2026/11/09 12:00:00 could not read secret '{}': \"{}\" isn't an item in the \"Private\" vault",
                item_ref, phrase
            );
            assert_eq!(
                ErrorClass::classify(&item, &[&item_ref], true),
                ErrorClass::NotFound,
                "item {}",
                phrase
            );
            let vault_ref = format!("op://{}/item/password", phrase);
            let vault = format!(
                "[ERROR] 2026/11/09 12:00:00 could not read secret '{}': \"{}\" isn't a vault in this account",
                vault_ref, phrase
            );
            assert_eq!(
                ErrorClass::classify(&vault, &[&vault_ref], true),
                ErrorClass::NotFound,
                "vault {}",
                phrase
            );
            let field_ref = format!("op://Private/item/{}", phrase);
            let field = format!(
                "[ERROR] 2026/11/09 12:00:00 could not read secret '{}': item \"item\" does not have a field \"{}\"",
                field_ref, phrase
            );
            assert_eq!(
                ErrorClass::classify(&field, &[&field_ref], true),
                ErrorClass::NotFound,
                "field {}",
                phrase
            );
            // Reference text alone (unquoted), with no other error words.
            let bare = format!("[ERROR] 2026/11/09 12:00:00 {}", item_ref);
            assert_eq!(
                ErrorClass::classify(&bare, &[&item_ref], true),
                ErrorClass::Other
            );
        }
    }

    #[test]
    fn permission_message_containing_trigger_phrase_is_permission() {
        let m = "[ERROR] 2026/11/09 12:00:00 permission denied: error initializing client: authorization timeout";
        assert_eq!(ErrorClass::classify(m, &[], true), ErrorClass::Permission);
    }

    #[test]
    fn service_account_failures_are_never_approval_unavailable() {
        let m = "[ERROR] 2026/11/09 12:00:00 (401) Unauthorized: error initializing client: authorization timeout";
        assert_eq!(ErrorClass::classify(m, &[], false), ErrorClass::Permission);
        let m = "[ERROR] 2026/11/09 12:00:00 error initializing client: authorization timeout";
        assert_eq!(ErrorClass::classify(m, &[], false), ErrorClass::Other);
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
