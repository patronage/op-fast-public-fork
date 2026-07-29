use std::ffi::OsString;

use anyhow::Result;
use clap::Parser;

pub mod audit;
pub mod inject;
pub mod read;
pub mod run;
pub mod store;

#[derive(Debug, Parser)]
pub enum Subcommand {
    #[clap(hide = true)]
    Read(read::ReadArgs),

    #[clap(hide = true)]
    Inject(inject::InjectArgs),

    #[clap(hide = true)]
    Run(run::RunArgs),

    #[clap(hide = true)]
    Store(store::StoreCommand),

    #[clap(hide = true)]
    Audit(audit::AuditCommand),

    #[clap(external_subcommand)]
    Other(Vec<OsString>),
}

pub fn execute(subcommand: Subcommand) -> Result<()> {
    match subcommand {
        Subcommand::Read(args) => read::execute(args),
        Subcommand::Inject(args) => inject::execute(args),
        Subcommand::Run(args) => run::execute(args),
        Subcommand::Store(cmd) => store::execute(cmd),
        Subcommand::Audit(cmd) => audit::execute(cmd),
        Subcommand::Other(args) => delegate_passthrough(&args),
    }
}

fn delegate_passthrough(args: &[OsString]) -> Result<()> {
    let subcommand = args
        .first()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_default();
    crate::audit::record("passthrough", None, "delegated", None, Some(&subcommand));

    let delegate = crate::delegate::OpDelegate::new()?;
    let status = delegate.command().args(args).status()?;

    std::process::exit(status.code().unwrap_or(1));
}
