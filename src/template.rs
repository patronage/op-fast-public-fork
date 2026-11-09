use std::collections::HashSet;

use fancy_regex::Regex;

lazy_static::lazy_static! {
    // Item names may contain spaces, but whitespace followed by another
    // `op://` or by `NAME=` starts a new token, not more of this reference.
    static ref UNENCLOSED_REF: Regex = Regex::new(
        r"(?<![A-Za-z0-9\-+\\.])(op://(?:[A-Za-z0-9\-?_./]|\s(?!\s*(?:op://|[A-Za-z_][A-Za-z0-9_]*=)))+)"
    ).unwrap();

    static ref ENCLOSED_REF: Regex = Regex::new(
        r"\{\{\s*(op://[^\}]+)\s*\}\}"
    ).unwrap();
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

pub fn resolve_variables(input: &str) -> String {
    subst::substitute(input, &subst::Env).unwrap_or_else(|_| input.to_string())
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
            let reference = caps.get(1).unwrap().as_str().trim();
            resolver(reference).unwrap_or_else(|| caps.get(0).unwrap().as_str().to_string())
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
    fn substitution_replaces_each_reference() {
        let out = substitute_references("A=op://V/i/f C=op://V/j/f", |r| {
            Some(if r == "op://V/i/f" { "one" } else { "two" }.to_string())
        });
        assert_eq!(out, "A=one C=two");
    }
}
