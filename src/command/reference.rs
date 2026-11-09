use anyhow::{Context, Result, bail};
use clap::Parser;
use serde_json::Value;

use crate::account::Selector;
use crate::audit::Entry;
use crate::config::Config;
use crate::delegate::{CallAuth, OpDelegate};
use crate::error::{DelegateError, ErrorClass, NeedsApproval};

#[derive(Debug, Parser)]
#[clap(
    about = "Print an ID-based secret reference for an item (no values)",
    long_about = "Look up an item with `op item get --format json` and print a stable,
ID-based reference: op://<vault-id>/<item-id>/<field-id>.

Use it when an item or field name has spaces, slashes, or other characters
that break name-based references. Without a field, prints one reference per
field with its label. Never prints field values.",
    after_help = "Examples:
  op-fast ref 'Stripe (live)' 'secret key' --vault Agents
  op-fast ref 'Stripe (live)' --vault Agents
"
)]
pub struct RefArgs {
    #[clap(help = "Item name or ID")]
    pub item: String,

    #[clap(help = "Field label or ID")]
    pub field: Option<String>,

    #[clap(long, help = "Vault name or ID")]
    pub vault: Option<String>,
}

pub fn execute(args: RefArgs, sa: Option<&str>) -> Result<()> {
    let config = Config::load()?;
    let selector = Selector::new(&config, sa)?;
    let auth = selector.for_vault(args.vault.as_deref());
    let token = crate::account::token_for(&auth)?;
    let call = CallAuth::new(auth.clone(), token, &config);
    let delegate = OpDelegate::new(&config)?;

    let item = match delegate.item_get_json(&args.item, args.vault.as_deref(), &call) {
        Ok(item) => item,
        Err(err) => {
            if let Some(de) = err.downcast_ref::<DelegateError>() {
                crate::audit::log(Entry {
                    op: "ref",
                    outcome: "error",
                    command: Some(&args.item),
                    error_class: Some(de.class.as_str()),
                    account: Some(auth.label()),
                    ..Entry::default()
                });
                if de.class == ErrorClass::ApprovalUnavailable {
                    return Err(NeedsApproval {
                        subjects: vec![format!("item {:?}", args.item)],
                    }
                    .into());
                }
            }
            return Err(err);
        }
    };
    crate::audit::log(Entry {
        op: "ref",
        outcome: "fetched",
        command: Some(&args.item),
        account: Some(auth.label()),
        ..Entry::default()
    });

    for line in references(&item, args.field.as_deref())? {
        println!("{}", line);
    }
    Ok(())
}

/// Build reference lines from `op item get --format json` output. Reads
/// only ids and labels; values are never touched.
pub fn references(item: &Value, field: Option<&str>) -> Result<Vec<String>> {
    let item_id = item
        .get("id")
        .and_then(Value::as_str)
        .context("item JSON has no id")?;
    let vault_id = item
        .pointer("/vault/id")
        .and_then(Value::as_str)
        .context("item JSON has no vault.id")?;
    let fields: Vec<(&str, &str)> = item
        .get("fields")
        .and_then(Value::as_array)
        .map(|fs| {
            fs.iter()
                .filter_map(|f| {
                    let id = f.get("id").and_then(Value::as_str)?;
                    let label = f.get("label").and_then(Value::as_str).unwrap_or("");
                    Some((id, label))
                })
                .collect()
        })
        .unwrap_or_default();
    let reference = |id: &str| format!("op://{}/{}/{}", vault_id, item_id, id);

    match field {
        Some(wanted) => {
            let matches: Vec<&(&str, &str)> = fields
                .iter()
                .filter(|(id, label)| *id == wanted || label.eq_ignore_ascii_case(wanted))
                .collect();
            match matches.as_slice() {
                [] => bail!(
                    "no field {:?} on item (fields: {})",
                    wanted,
                    labels(&fields)
                ),
                [(id, _)] => Ok(vec![reference(id)]),
                many => {
                    // Prefer an exact id match over ambiguous labels.
                    if let Some((id, _)) = many.iter().find(|(id, _)| *id == wanted) {
                        return Ok(vec![reference(id)]);
                    }
                    bail!(
                        "field label {:?} is ambiguous; use a field id: {}",
                        wanted,
                        many.iter()
                            .map(|(id, _)| *id)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
        }
        None => Ok(fields
            .iter()
            .map(|(id, label)| format!("{}\t{}", reference(id), label))
            .collect()),
    }
}

fn labels(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> Value {
        serde_json::json!({
            "id": "itm123",
            "vault": {"id": "vlt456", "name": "Agents"},
            "fields": [
                {"id": "username", "label": "username", "value": "SHOULD-NOT-PRINT-1"},
                {"id": "password", "label": "password", "value": "SHOULD-NOT-PRINT-2"},
                {"id": "abc9", "label": "secret key", "value": "SHOULD-NOT-PRINT-3"}
            ]
        })
    }

    #[test]
    fn builds_id_reference_by_label_or_id() {
        assert_eq!(
            references(&item(), Some("Secret Key")).unwrap(),
            vec!["op://vlt456/itm123/abc9"]
        );
        assert_eq!(
            references(&item(), Some("abc9")).unwrap(),
            vec!["op://vlt456/itm123/abc9"]
        );
        assert!(references(&item(), Some("nope")).is_err());
    }

    #[test]
    fn listing_never_includes_values() {
        let lines = references(&item(), None).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| !l.contains("SHOULD-NOT-PRINT")));
    }
}
