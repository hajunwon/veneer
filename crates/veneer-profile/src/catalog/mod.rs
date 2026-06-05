//! Known-parts catalog: verified real-hardware values composed into a
//! profile's `spec` fields at generation time. Pure reference data — the
//! resolved concrete values are what persist to NVRAM, so a later catalog
//! edit never silently changes an already-cached machine identity.

pub mod dies;
pub mod cpus;
pub mod platforms;
pub mod disks;
pub mod nics;
pub mod memory;
pub mod gpus;
pub mod audio;
pub mod machines;
