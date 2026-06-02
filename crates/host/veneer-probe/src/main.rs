//! veneer CLI entry. Today only the read-only verbs are wired; the actual
//! VMRUN launcher will land when the UEFI / kernel-driver platform module
//! is built out.

mod cli;
mod modes;

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let a = cli::parse(&argv);

    if a.cmd.is_empty() || matches!(a.cmd.as_str(), "help" | "-h" | "--help") {
        cli::usage();
        return Ok(());
    }

    match a.cmd.as_str() {
        "inspect"        => modes::inspect::run(),
        "plan"           => modes::plan::run(),
        "profile-check"  => {
            let path = a.positional.get(0)
                .ok_or_else(|| anyhow::anyhow!("profile-check requires <toml-path>"))?;
            modes::profile_check::run(path)
        }
        other => { cli::usage(); bail!("unknown command: {other}"); }
    }
}
