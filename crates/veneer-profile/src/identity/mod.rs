//! Per-unit identifier generation — the rules for filling each component's
//! `instance` fields within its `spec` constraints. Pure and OS-agnostic:
//! the randomness source is injected as an `Rng`, so the runtime supplies
//! RDRAND while host-side tools can use a seeded generator for tests.

pub mod format;
pub mod generate;

/// Randomness source for identifier generation. The runtime implements this
/// over RDRAND; tests can implement it deterministically.
pub trait Rng {
    fn next_u64(&mut self) -> u64;
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}
