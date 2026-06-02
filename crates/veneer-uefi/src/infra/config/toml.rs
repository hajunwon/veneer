//! Config TOML dispatch. The shared tokenizer + `Value`/`Line`/`parse_line`
//! and the Profile half live in `veneer_profile::toml`; this keeps only
//! veneer's own Config schema (Config is hypervisor-internal).

#![allow(dead_code)]

use crate::infra::config::{Config, LogLevel, QuickPolicy, VmwareBackdoorPolicy};
use veneer_profile::toml::{
    as_bool, as_int, as_str, parse_line, set_bool_field, set_u32_field, set_u64_field,
    set_u8_field, Line, Value,
};

// Re-export so existing `crate::toml::apply_profile` call sites keep working.
pub use veneer_profile::toml::apply_profile;

pub fn apply_config(text: &[u8], c: &mut Config, warn_count: &mut u32) -> u32 {
    let mut section: &[u8] = b"";
    let mut applied = 0u32;
    for raw_line in text.split(|&c| c == b'\n') {
        match parse_line(raw_line) {
            Line::Skip => {}
            Line::Bad => *warn_count += 1,
            Line::Section(s) => section = s,
            Line::KeyValue(k, v) => {
                if apply_config_field(c, section, k, v) {
                    applied += 1;
                } else {
                    *warn_count += 1;
                }
            }
        }
    }
    applied
}

fn apply_config_field(c: &mut Config, section: &[u8], key: &[u8], v: Value) -> bool {
    let c_ptr = c as *mut Config;
    match (section, key) {
        (b"menu", b"timeout_secs") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u8_field(core::ptr::addr_of_mut!((*c_ptr).menu.timeout_secs), n as u8); }
            true
        }
        (b"menu", b"force_show") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).menu.force_show), b); }
            true
        }
        (b"policy", b"default") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            let p = match s {
                b"intel_laptop" => QuickPolicy::IntelLaptop,
                b"amd_desktop" => QuickPolicy::AmdDesktop,
                b"ryzen_nuc" => QuickPolicy::RyzenNuc,
                _ => return false,
            };
            unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*c_ptr).policy.default), p); }
            true
        }
        (b"policy", b"prompt_on_miss") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).policy.prompt_on_miss), b); }
            true
        }
        (b"log", b"serial") => {
            let lvl = match as_str(v) { Some(s) => parse_log_level(s), None => return false };
            let lvl = match lvl { Some(l) => l, None => return false };
            unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*c_ptr).log.serial), lvl); }
            true
        }
        (b"log", b"console") => {
            let lvl = match as_str(v) { Some(s) => parse_log_level(s), None => return false };
            let lvl = match lvl { Some(l) => l, None => return false };
            unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*c_ptr).log.console), lvl); }
            true
        }
        (b"intercept", b"lapic_emulation") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).intercept.lapic_emulation), b); }
            true
        }
        (b"intercept", b"ap_probe") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).intercept.ap_probe), b); }
            true
        }
        (b"intercept", b"bsp_self_test") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).intercept.bsp_self_test), b); }
            true
        }
        (b"intercept", b"multi_vcpu_vmrun") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).intercept.multi_vcpu_vmrun), b); }
            true
        }
        (b"intercept", b"rdrand_intercept") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*c_ptr).intercept.rdrand_intercept), b); }
            true
        }
        (b"intercept", b"vmware_backdoor") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            let p = match s {
                b"block" => VmwareBackdoorPolicy::Block,
                b"passthrough" => VmwareBackdoorPolicy::Passthrough,
                _ => return false,
            };
            unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*c_ptr).intercept.vmware_backdoor), p); }
            true
        }
        (b"timing", b"rdtsc_stride") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u32_field(core::ptr::addr_of_mut!((*c_ptr).timing.rdtsc_stride), n as u32); }
            true
        }
        (b"timing", b"rdtsc_seed") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u64_field(core::ptr::addr_of_mut!((*c_ptr).timing.rdtsc_seed), n as u64); }
            true
        }
        (b"timing", b"vmmcall_signature") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u64_field(core::ptr::addr_of_mut!((*c_ptr).timing.vmmcall_signature), n as u64); }
            true
        }
        (b"runtime", b"max_vmrun_iters") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u32_field(core::ptr::addr_of_mut!((*c_ptr).runtime.max_vmrun_iters), n as u32); }
            true
        }
        (b"runtime", b"asid_base_bsp") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u32_field(core::ptr::addr_of_mut!((*c_ptr).runtime.asid_base_bsp), n as u32); }
            true
        }
        (b"runtime", b"asid_base_ap") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u32_field(core::ptr::addr_of_mut!((*c_ptr).runtime.asid_base_ap), n as u32); }
            true
        }
        _ => false,
    }
}

fn parse_log_level(s: &[u8]) -> Option<LogLevel> {
    match s {
        b"none" => Some(LogLevel::None),
        b"minimal" => Some(LogLevel::Minimal),
        b"verbose" => Some(LogLevel::Verbose),
        _ => None,
    }
}
