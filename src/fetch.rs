//! Cache-or-fetch resolution shared by `read`, `run`, `inject`, `refresh`,
//! and `warm`.
//!
//! A cache miss (or `--refresh`) groups references by the account that
//! serves them and makes one delegate call per group. When a call fails
//! because 1Password approval was unavailable, expired entries inside the
//! `stale_grace` window are served with a warning; anything else that could
//! not be served becomes a `NeedsApproval` error (exit 75).

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;

use crate::account::{self, Auth, Selector};
use crate::audit::{self, Entry};
use crate::config::Config;
use crate::delegate::{CallAuth, OpDelegate};
use crate::error::{DelegateError, ErrorClass, NeedsApproval};
use crate::store::Store;

pub const NO_STALE_ENV: &str = "OP_FAST_NO_STALE";

pub struct Fetcher<'a> {
    config: &'a Config,
    selector: Selector<'a>,
    store: Option<Store>,
    delegate: OpDelegate,
    op: &'static str,
}

#[derive(Debug, Default)]
pub struct WarmReport {
    pub refreshed: Vec<String>,
    pub failed: Vec<(String, ErrorClass)>,
    pub skipped: Vec<String>,
}

impl<'a> Fetcher<'a> {
    pub fn new(config: &'a Config, cli_sa: Option<&str>, op: &'static str) -> Result<Self> {
        let selector = Selector::new(config, cli_sa)?;
        let store = match Store::open(config.stale_grace) {
            Ok(store) => Some(store),
            Err(e) => {
                log::error!("Store unavailable, delegating to op: {}", e);
                None
            }
        };
        let delegate = OpDelegate::new(config)?;
        Ok(Self {
            config,
            selector,
            store,
            delegate,
            op,
        })
    }

    pub fn store(&self) -> Option<&Store> {
        self.store.as_ref()
    }

    pub fn selector(&self) -> &Selector<'a> {
        &self.selector
    }

    fn group<'r>(&self, refs: impl IntoIterator<Item = &'r str>) -> BTreeMap<Auth, Vec<&'r str>> {
        let mut groups: BTreeMap<Auth, Vec<&'r str>> = BTreeMap::new();
        for r in refs {
            groups
                .entry(self.selector.for_reference(r))
                .or_default()
                .push(r);
        }
        groups
    }

    fn call_auth(&self, auth: &Auth) -> Result<CallAuth> {
        if matches!(auth, Auth::Account(_)) {
            // Check before reading the token from the keyring at all.
            self.delegate.verify_for_token()?;
        }
        let token = account::token_for(auth)?;
        Ok(CallAuth::new(auth.clone(), token, self.config))
    }

    fn fetch_group(&self, refs: &[&str], call: &CallAuth) -> Result<HashMap<String, String>> {
        if refs.len() == 1 && self.op == "read" {
            let value = self.delegate.read(refs[0], call)?;
            Ok(HashMap::from([(refs[0].to_string(), value)]))
        } else {
            self.delegate.read_batch(refs, call)
        }
    }

    fn put(&self, reference: &str, value: &str, auth: &Auth) -> Result<()> {
        if let Some(store) = &self.store {
            let ttl = self
                .config
                .resolve_ttl_for(reference, self.selector.service_account(auth));
            store.put(reference, value, ttl)?;
        }
        Ok(())
    }

    /// Resolve every reference to a value: cache first (unless `refresh`),
    /// then one delegate call per account group.
    pub fn resolve(&self, references: &[String], refresh: bool) -> Result<HashMap<String, String>> {
        let mut values: HashMap<String, String> = HashMap::new();
        let mut misses: Vec<&str> = Vec::new();

        for reference in references {
            if values.contains_key(reference) || misses.contains(&reference.as_str()) {
                continue;
            }
            let hit = match (&self.store, refresh) {
                (Some(store), false) => store.get_with_meta(reference)?,
                _ => None,
            };
            match hit {
                Some((value, meta)) => {
                    audit::log(Entry {
                        op: self.op,
                        reference: Some(reference),
                        outcome: "hit",
                        ttl_remaining: Some(meta.remaining_secs()),
                        ..Entry::default()
                    });
                    values.insert(reference.clone(), value);
                }
                None => misses.push(reference),
            }
        }

        let no_stale = crate::command::is_truthy(std::env::var_os(NO_STALE_ENV).as_deref());
        let mut stale: Vec<(String, String, u64, Auth)> = Vec::new();
        let mut needs: Vec<String> = Vec::new();

        for (auth, refs) in self.group(misses.iter().copied()) {
            let call = self.call_auth(&auth)?;
            match self.fetch_group(&refs, &call) {
                Ok(fetched) => {
                    for reference in &refs {
                        let Some(value) = fetched.get(*reference) else {
                            continue;
                        };
                        self.put(reference, value, &auth)?;
                        audit::log(Entry {
                            op: self.op,
                            reference: Some(reference),
                            outcome: if refresh { "refreshed" } else { "fetched" },
                            account: Some(auth.label()),
                            ..Entry::default()
                        });
                    }
                    values.extend(fetched);
                }
                Err(err) => {
                    let Some(de) = err.downcast_ref::<DelegateError>() else {
                        return Err(err);
                    };
                    for reference in &refs {
                        audit::log(Entry {
                            op: self.op,
                            reference: Some(reference),
                            outcome: "error",
                            error_class: Some(de.class.as_str()),
                            account: Some(auth.label()),
                            ..Entry::default()
                        });
                    }
                    if de.class != ErrorClass::ApprovalUnavailable {
                        return Err(err);
                    }
                    for reference in &refs {
                        let fallback = match (&self.store, refresh || no_stale) {
                            (Some(store), false) => store
                                .get_any(reference)?
                                .filter(|(_, meta)| meta.is_in_grace(self.config.stale_grace)),
                            _ => None,
                        };
                        match fallback {
                            Some((value, meta)) => stale.push((
                                reference.to_string(),
                                value,
                                meta.expired_for_secs().unwrap_or(0),
                                auth.clone(),
                            )),
                            None => needs.push(reference.to_string()),
                        }
                    }
                }
            }
        }

        if !needs.is_empty() {
            return Err(NeedsApproval { subjects: needs }.into());
        }

        for (reference, value, age, auth) in stale {
            eprintln!(
                "warning: served expired cache for {} (expired {} ago); 1Password approval unavailable",
                reference,
                humantime::format_duration(std::time::Duration::from_secs(age))
            );
            audit::log(Entry {
                op: self.op,
                reference: Some(&reference),
                outcome: "stale-served",
                error_class: Some(ErrorClass::ApprovalUnavailable.as_str()),
                account: Some(auth.label()),
                ..Entry::default()
            });
            values.insert(reference, value);
        }

        Ok(values)
    }

    /// Fetch and overwrite each reference without printing values. One
    /// batched call per account group; a group that fails for a reason
    /// other than approval falls back to per-reference reads so one bad
    /// reference does not sink the rest.
    pub fn warm(&self, references: &[String]) -> WarmReport {
        let mut report = WarmReport::default();
        let mut valid: Vec<&str> = Vec::new();
        for r in references {
            if !r.starts_with("op://") {
                report.skipped.push(r.clone());
            } else if !valid.contains(&r.as_str()) {
                valid.push(r);
            }
        }

        for (auth, refs) in self.group(valid) {
            let call = match self.call_auth(&auth) {
                Ok(call) => call,
                Err(e) => {
                    eprintln!("op-fast: {:#}", e);
                    for r in refs {
                        report.failed.push((r.to_string(), ErrorClass::Other));
                    }
                    continue;
                }
            };
            match self.delegate.read_batch(&refs, &call) {
                Ok(fetched) => {
                    for r in &refs {
                        if let Some(v) = fetched.get(*r) {
                            self.record_refresh(r, v, &auth, &mut report);
                        }
                    }
                }
                Err(err) => {
                    let class = err
                        .downcast_ref::<DelegateError>()
                        .map(|d| d.class)
                        .unwrap_or(ErrorClass::Other);
                    if class == ErrorClass::ApprovalUnavailable || refs.len() == 1 {
                        for r in &refs {
                            self.record_failure(r, class, &auth, &mut report);
                        }
                        continue;
                    }
                    for r in &refs {
                        match self.delegate.read(r, &call) {
                            Ok(v) => self.record_refresh(r, &v, &auth, &mut report),
                            Err(e) => {
                                let class = e
                                    .downcast_ref::<DelegateError>()
                                    .map(|d| d.class)
                                    .unwrap_or(ErrorClass::Other);
                                self.record_failure(r, class, &auth, &mut report);
                            }
                        }
                    }
                }
            }
        }
        report
    }

    fn record_refresh(&self, r: &str, v: &str, auth: &Auth, report: &mut WarmReport) {
        match self.put(r, v, auth) {
            Ok(()) => {
                audit::log(Entry {
                    op: self.op,
                    reference: Some(r),
                    outcome: "refreshed",
                    account: Some(auth.label()),
                    ..Entry::default()
                });
                report.refreshed.push(r.to_string());
            }
            Err(e) => {
                log::error!("Failed to store {}: {}", r, e);
                report.failed.push((r.to_string(), ErrorClass::Other));
            }
        }
    }

    fn record_failure(&self, r: &str, class: ErrorClass, auth: &Auth, report: &mut WarmReport) {
        audit::log(Entry {
            op: self.op,
            reference: Some(r),
            outcome: "error",
            error_class: Some(class.as_str()),
            account: Some(auth.label()),
            ..Entry::default()
        });
        report.failed.push((r.to_string(), class));
    }
}
