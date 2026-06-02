//! Storage subsystem — presents block storage to the guest.
//!
//! Two concerns, two module boundaries:
//!   - `backend`: where the bytes come from (host disk via UEFI BlockIO).
//!     Block-device-agnostic; a file or RAM backend would slot in here
//!     behind the same read/write/geometry surface.
//!   - `nvme`: the controller interface the guest sees (NVMe 1.4). A SATA
//!     (AHCI) or virtio-blk controller would be a sibling module here,
//!     sharing the same `backend`.
//!
//! veneer chooses what to advertise on the PCI bus; the guest only ever
//! reacts to that. "Which controller" is our decision, not the guest's —
//! so today we present exactly one (NVMe) backed by the host disk, with
//! room to add more controllers without touching the backend.

pub mod ahci;
pub mod backend;
pub mod host_ahci;
pub mod nvme;
