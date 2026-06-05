//! Shared low-level primitives used across every layer: CPU access, the
//! virtual clock/timekeeping, config parsing, and the serial log transport.

pub mod arch;
pub mod clock;
pub mod config;
pub mod serial;
