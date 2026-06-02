//! `veneer profile-check <toml-path>` — validate a profile.toml against the
//! shared schema the hypervisor actually consumes.

use std::path::Path;

use anyhow::Result;

use veneer::profile::load::load_explicit;

pub fn run(path_s: &str) -> Result<()> {
    let path = Path::new(path_s);
    if !path.exists() {
        anyhow::bail!("{path_s:?} not found");
    }
    let p = load_explicit(path)?;

    // Profile is `#[repr(C, packed)]`; copy each sub-struct out before
    // reading. `ProfileStr`/bool have alignment 1, so their field access
    // is fine once the parent is a local copy.
    let name = unsafe { core::ptr::addr_of!(p.name).read_unaligned() };
    let cpu = unsafe { core::ptr::addr_of!(p.hardware.cpu).read_unaligned() };
    let smb = unsafe { core::ptr::addr_of!(p.hardware.smbios).read_unaligned() };
    let net = unsafe { core::ptr::addr_of!(p.hardware.network).read_unaligned() };
    let disk = unsafe { core::ptr::addr_of!(p.hardware.disk).read_unaligned() };

    println!("==== profile: {} ====", name.as_str());
    println!("  cpu.brand        : {}", cpu.brand.as_str());
    println!("  cpu.vendor       : {}", cpu.vendor.as_str());
    println!("  cpu.hide_hyper_b : {}", cpu.hide_hypervisor_bit);
    println!("  cpu.hide_hyper_l : {}", cpu.hide_hypervisor_leaf);
    println!("  smbios.product   : {} {}", smb.manufacturer.as_str(), smb.product.as_str());
    println!("  smbios.serial    : {}", smb.serial.as_str());
    println!("  network.mac      : {}", net.mac.as_str());
    println!("  disk.model       : {}", disk.model.as_str());
    println!();

    // ProfileStr<48> *is* the 48-byte (12-register) CPUID brand block, so
    // the brand round-trips by construction — confirm it packs/unpacks clean.
    let padded = cpu.brand.to_padded();
    let rendered = std::str::from_utf8(&padded).unwrap_or("").trim_end_matches('\0');
    if rendered == cpu.brand.as_str() {
        println!("  [+] CPUID brand string packs into the 48-byte leaf block");
    } else {
        println!("  [!] brand pack mismatch: {:?} vs {:?}", cpu.brand.as_str(), rendered);
    }

    Ok(())
}
