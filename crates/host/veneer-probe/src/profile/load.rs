//! Read a `profile.toml` from disk into the shared `Profile` via the
//! shared no_std parser.
//!
//! The old serde path + auto-create-default is gone: the schema is
//! `#[repr(C, packed)]` with a parser but no serializer, so the host
//! validates existing files rather than writing new ones.

use std::fs;

use anyhow::{Context as _, Result};
use veneer_profile::toml::apply_profile;
use veneer_profile::Profile;

pub fn load_explicit(path: &std::path::Path) -> Result<Profile> {
    let bytes = fs::read(path).with_context(|| format!("read profile {}", path.display()))?;
    let mut p = Profile::empty();
    let mut warns = 0u32;
    let applied = apply_profile(&bytes, &mut p, &mut warns);
    if applied == 0 {
        anyhow::bail!("{}: no recognised profile fields", path.display());
    }
    Ok(p)
}
