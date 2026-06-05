#![no_std]
#![allow(dead_code)]
//! veneer hypervisor core — OS/firmware-agnostic.
//!
//! Modules are migrated here from `veneer-uefi` so the core (SVM, vmexit
//! dispatch, device emulation, introspection) carries no UEFI dependency.
//! The environment is injected through traits (host storage, host input,
//! platform services); the UEFI app implements them.

extern crate alloc;

pub mod platform;
pub mod infra;
pub mod hypervisor;
pub mod hardware;
pub mod introspect;
pub mod diag;
pub mod guest_mem;
