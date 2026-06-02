//! Developer diagnostics: the WinDbg KD bridge, runtime validation, and boot
//! reporting. Removable without changing guest-visible behaviour.

pub mod serial_kd;
pub mod validator;
pub mod report;
pub mod snapshot;
