//! Secret-reference detection, variable expansion, and substitution.
//!
//! Variable syntax: `$NAME`, `${NAME}`, `${NAME:-default}` (and the
//! equivalent `${NAME:default}`). Inside a secret reference an unset
//! variable with no default is an error; a partly expanded reference is
//! never fetched or cached.

use std::collections::HashSet;

use anyhow::{Result, bail};
use fancy_regex::Regex;

lazy_static::lazy_static! {
    // A reference never spans a newline or tab. Item names may contain
    // spaces, but a space followed by another `op://` or by `NAME=` starts
    // a new token. Query strings (`?attribute=otp`) stay part of it.
    static ref UNENCLOSED_REF: Regex = Regex::new(
        r"(?<![A-Za-z0-9\-+\\.])(op://(?:[A-Za-z0-9\-?_./=&]| (?! *(?:op://|[A-Za-z_][A-Za-z0-9_]*=)))+)"
    ).unwrap();

    static ref ENCLOSED_REF: Regex = Regex::new(
        r"\{\{ *(op://[^}\n]+?) *\}\}"
    ).unwrap();

    // A reference before variable expansion: the same grammar plus `$NAME`
    // and `${...}` units.
    static ref RAW_REF: Regex = Regex::new(
        r"(?<![A-Za-z0-9\-+\\.])op://(?:[A-Za-z0-9\-?_./=&]|\$\{[^}\n]*\}|\$[A-Za-z_][A-Za-z0-9_]*| (?! *(?:op://|[A-Za-z_][A-Za-z0-9_]*=)))+"
    ).unwrap();
}

/// A secret reference op-fast will fetch, cache, or audit: it starts with
/// `op://` and contains no control characters.
pub fn validate_reference(reference: &str) -> Result<()> {
    if !reference.starts_with("op://") {
        bail!("not a secret reference (must start with op://)");
    }
    if reference.chars().any(char::is_control) {
        bail!("secret reference contains a control character; refusing it");
    }
    Ok(())
}

pub fn extract_references(input: &str) -> HashSet<String> {
    let mut refs = HashSet::new();

    for cap in UNENCLOSED_REF.captures_iter(input).flatten() {
        if let Some(m) = cap.get(1) {
            refs.insert(m.as_str().trim().to_string());
        }
    }

    for cap in ENCLOSED_REF.captures_iter(input).flatten() {
        if let Some(m) = cap.get(1) {
            refs.insert(m.as_str().trim().to_string());
        }
    }

    refs
}

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Expand variables in `input`. Unset variables without a default are an
/// error when `strict`, and left as written otherwise.
pub fn expand_with<F: Fn(&str) -> Option<String>>(
    input: &str,
    strict: bool,
    lookup: &F,
) -> Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let is_start = |c: char| c.is_ascii_alphabetic() || c == '_';
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    while i < chars.len() {
        let c = chars[i];
        if c != '$' {
            out.push(c);
            i += 1;
            continue;
        }
        // ${NAME}, ${NAME:-default}, ${NAME:default}
        if chars.get(i + 1) == Some(&'{')
            && let Some(close) = chars[i + 2..].iter().position(|&c| c == '}')
        {
            let body: String = chars[i + 2..i + 2 + close].iter().collect();
            let (name, default) = match body.find(':') {
                Some(colon) => {
                    let d = &body[colon + 1..];
                    (&body[..colon], Some(d.strip_prefix('-').unwrap_or(d)))
                }
                None => (body.as_str(), None),
            };
            let valid = name.chars().next().is_some_and(is_start) && name.chars().all(is_name);
            if valid {
                match (lookup(name), default) {
                    (Some(v), _) => out.push_str(&v),
                    (None, Some(d)) => out.push_str(d),
                    (None, None) if strict => {
                        bail!("unset variable `{}` in secret reference", name)
                    }
                    (None, None) => out.extend(&chars[i..i + 3 + close]),
                }
                i += 3 + close;
                continue;
            }
        }
        // $NAME
        if chars.get(i + 1).is_some_and(|&c| is_start(c)) {
            let mut j = i + 1;
            while j < chars.len() && is_name(chars[j]) {
                j += 1;
            }
            let name: String = chars[i + 1..j].iter().collect();
            match lookup(&name) {
                Some(v) => out.push_str(&v),
                None if strict => bail!("unset variable `{}` in secret reference", name),
                None => out.extend(&chars[i..j]),
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    Ok(out)
}

/// Expand one secret reference strictly from the process environment.
pub fn expand_reference(reference: &str) -> Result<String> {
    expand_with(reference, true, &env_lookup)
}

/// Expand variables inside every secret reference in `input` (strictly),
/// and in the surrounding text only when `expand_rest` (leniently).
pub fn expand_text(input: &str, expand_rest: bool) -> Result<String> {
    expand_text_with(input, expand_rest, &env_lookup)
}

pub fn expand_text_with<F: Fn(&str) -> Option<String>>(
    input: &str,
    expand_rest: bool,
    lookup: &F,
) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in RAW_REF.find_iter(input).flatten() {
        let between = &input[last..m.start()];
        if expand_rest {
            out.push_str(&expand_with(between, false, lookup)?);
        } else {
            out.push_str(between);
        }
        out.push_str(&expand_with(m.as_str(), true, lookup)?);
        last = m.end();
    }
    let tail = &input[last..];
    if expand_rest {
        out.push_str(&expand_with(tail, false, lookup)?);
    } else {
        out.push_str(tail);
    }
    Ok(out)
}

pub fn substitute_references<F>(input: &str, resolver: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let input = ENCLOSED_REF.replace_all(input, |caps: &fancy_regex::Captures| {
        let reference = caps.get(1).unwrap().as_str().trim();
        resolver(reference).unwrap_or_else(|| caps.get(0).unwrap().as_str().to_string())
    });

    UNENCLOSED_REF
        .replace_all(&input, |caps: &fancy_regex::Captures| {
            let whole = caps.get(0).unwrap().as_str();
            let reference = whole.trim_end();
            // Keep any trailing spaces the match took.
            let trailing = &whole[reference.len()..];
            match resolver(reference.trim()) {
                Some(v) => format!("{}{}", v, trailing),
                None => whole.to_string(),
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(s: &str) -> Vec<String> {
        let mut v: Vec<String> = extract_references(s).into_iter().collect();
        v.sort();
        v
    }

    fn vars(name: &str) -> Option<String> {
        match name {
            "VAULT" => Some("prod".into()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    #[test]
    fn whitespace_does_not_swallow_the_next_reference_or_assignment() {
        assert_eq!(refs("op://V/i/f op://V/j/f"), ["op://V/i/f", "op://V/j/f"]);
        assert_eq!(
            refs("op://V/i/f C=op://V/j/f"),
            ["op://V/i/f", "op://V/j/f"]
        );
        assert_eq!(
            refs("op://Private/My Item/password"),
            ["op://Private/My Item/password"]
        );
    }

    #[test]
    fn references_never_span_newlines_and_keep_query_strings() {
        assert_eq!(refs("password: op://V/i/f\nuser: bob"), ["op://V/i/f"]);
        assert_eq!(refs("a: op://V/i/f\tb"), ["op://V/i/f"]);
        assert_eq!(
            refs("op://V/i/otp?attribute=otp"),
            ["op://V/i/otp?attribute=otp"]
        );
        assert_eq!(refs("{{ op://V/i/f\n}}"), ["op://V/i/f"]);
    }

    #[test]
    fn substitution_replaces_each_reference() {
        let out = substitute_references("A=op://V/i/f C=op://V/j/f", |r| {
            Some(if r == "op://V/i/f" { "one" } else { "two" }.to_string())
        });
        assert_eq!(out, "A=one C=two");
    }

    #[test]
    fn expansion_syntax() {
        let e = |s: &str, strict| expand_with(s, strict, &vars);
        assert_eq!(e("op://$VAULT/x", true).unwrap(), "op://prod/x");
        assert_eq!(e("op://${VAULT}/x", true).unwrap(), "op://prod/x");
        assert_eq!(e("op://${NOPE:-dev}/x", true).unwrap(), "op://dev/x");
        assert_eq!(e("op://${NOPE:dev}/x", true).unwrap(), "op://dev/x");
        assert_eq!(e("op://${EMPTY:-dev}/x", true).unwrap(), "op:///x");
        let err = e("op://$NOPE/x", true).unwrap_err().to_string();
        assert!(err.contains("`NOPE`"), "{}", err);
        assert!(e("op://${NOPE}/x", true).is_err());
        assert_eq!(e("cost $5 and $NOPE", false).unwrap(), "cost $5 and $NOPE");
    }

    #[test]
    fn expand_text_is_strict_in_references_only() {
        let t = |s: &str, rest| expand_text_with(s, rest, &vars);
        assert_eq!(
            t("a $NOPE op://$VAULT/i/f", false).unwrap(),
            "a $NOPE op://prod/i/f"
        );
        assert_eq!(
            t("a $VAULT op://$VAULT/i/f", true).unwrap(),
            "a prod op://prod/i/f"
        );
        assert_eq!(t("a $VAULT", false).unwrap(), "a $VAULT");
        assert!(t("x={{ op://$NOPE/i/f }}", true).is_err());
        assert!(t("op://V/$NOPE/f", false).is_err());
    }

    #[test]
    fn reference_validation() {
        assert!(validate_reference("op://V/i/f").is_ok());
        assert!(validate_reference("agents").is_err());
        assert!(validate_reference("op://V/i\n/f").is_err());
        assert!(validate_reference("op://V/i\x1b[2J/f").is_err());
    }
}
