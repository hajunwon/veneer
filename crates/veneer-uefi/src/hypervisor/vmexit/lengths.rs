//! Instruction-length constants for handlers that don't get next_rip from
//! the VMCB. Centralised so the per-instruction values can't drift between
//! the handler and the guest blob.
//!
//! AMD APM Vol 3 / opcode map for the encodings the guest blob uses:
//!   cpuid       0F A2                — 2 bytes
//!   rdmsr       0F 32                — 2 bytes
//!   wrmsr       0F 30                — 2 bytes
//!   rdtsc       0F 31                — 2 bytes
//!   rdpmc       0F 33                — 2 bytes
//!   pushf       9C                   — 1 byte
//!   popf        9D                   — 1 byte
//!   vmmcall     0F 01 D9             — 3 bytes
//!   mov reg,CR  0F 20 /r             — 3 bytes  (no REX in our blob)
//!   mov CR,reg  0F 22 /r             — 3 bytes
//!   mov reg,DR  0F 21 /r             — 3 bytes
//!   mov DR,reg  0F 23 /r             — 3 bytes
//!   (sgdt/sidt   0F 01 /r — variable, see intercept/dt.rs decoder)
//!   invd        0F 08                — 2 bytes
//!   wbinvd      0F 09                — 2 bytes
//!   monitor     0F 01 C8             — 3 bytes
//!   mwait       0F 01 C9             — 3 bytes
//!   xsetbv      0F 01 D1             — 3 bytes
//!   hlt         F4                   — 1 byte

pub const CPUID: u64 = 2;
pub const RDMSR: u64 = 2;
pub const WRMSR: u64 = 2;
pub const RDTSC: u64 = 2;
pub const RDTSCP: u64 = 3;   // 0F 01 F9
pub const RDPMC: u64 = 2;
pub const PUSHF: u64 = 1;
pub const POPF: u64 = 1;
pub const VMMCALL: u64 = 3;
pub const CR_ACCESS: u64 = 3;
pub const DR_ACCESS: u64 = 3;
pub const INVD: u64 = 2;
pub const WBINVD: u64 = 2;
pub const MONITOR: u64 = 3;
pub const MWAIT: u64 = 3;
pub const XSETBV: u64 = 3;
pub const HLT: u64 = 1;
pub const PAUSE: u64 = 2;    // F3 90
