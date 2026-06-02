//! Usermode-simulation platform — exists so we can `cargo test` the core
//! without booting anything. `run_guest` here doesn't actually run
//! a guest; it just exercises the dispatch loop with synthesised
//! VMEXITs so we know the wiring holds.

use anyhow::Result;

use super::{Backend, Platform};
use crate::profile::Profile;

pub struct UserModeSim;

impl Platform for UserModeSim {
    fn alloc_page(&mut self) -> Result<(usize, u64)> {
        // In usermode we have no notion of host physical address. Use
        // the virtual address as a placeholder. Real launcher returns
        // an actual physical address.
        let p = Box::leak(Box::new([0u8; 4096])).as_mut_ptr() as usize;
        Ok((p, p as u64))
    }

    fn run_guest(&mut self, backend: Backend, _profile: &Profile) -> Result<()> {
        anyhow::bail!("usermode-sim doesn't run a real guest \
                       (selected backend: {backend:?}). \
                       See `veneer plan` + ARCHITECTURE.md §7 for the launcher path.");
    }
}
