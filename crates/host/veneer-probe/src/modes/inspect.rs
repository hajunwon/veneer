//! `veneer inspect` — probe the host CPU and print what we found.

use anyhow::Result;

use veneer::cpu::{probe, Vendor};

pub fn run() -> Result<()> {
    let caps = probe();
    println!("==== host CPU capabilities ====");
    println!("  vendor             : {:?} ({})", caps.vendor, caps.vendor.as_str());
    println!("  family/model       : 0x{:08x}", caps.family_model);
    println!("  virt extension     : {}", caps.virt_extension);
    println!("  nested paging      : {}", caps.nested_paging);
    println!("  long mode (x64)    : {}", caps.long_mode);
    println!("  1 GiB pages        : {}", caps.large_pages);
    if matches!(caps.vendor, Vendor::AuthenticAmd) {
        println!("  AMD ASIDs          : {}", caps.max_asid);
    }
    println!();
    println!("  viable for veneer   : {}", caps.viable());
    if !caps.viable() {
        println!("  blockers:");
        for b in caps.blockers() {
            println!("    - {b}");
        }
    }
    Ok(())
}
