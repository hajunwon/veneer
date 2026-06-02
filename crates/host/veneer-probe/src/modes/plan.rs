//! `veneer plan` — pick the backend, report what veneer would need.

use anyhow::Result;

use veneer::cpu::probe;
use veneer::platform::{pick_backend, Backend};

pub fn run() -> Result<()> {
    let caps = probe();
    let backend = pick_backend(&caps);
    println!("==== veneer bring-up plan ====");
    println!("  selected backend : {backend:?}");
    match backend {
        Backend::Svm => {
            println!("  rationale        : AuthenticAMD CPU + SVM + NPT — full path available");
            println!();
            println!("  memory required (per guest):");
            println!("    VMCB              : 1 page    (4 KiB, aligned)");
            println!("    HSAVE             : 1 page    (4 KiB, host-state save for VMRUN)");
            println!("    MSRPM             : 2 pages   (8 KiB, MSR intercept bitmap)");
            println!("    IOPM              : 2 pages   (8 KiB, IOIO intercept bitmap)");
            println!("    NPT root + tables : ~5 pages  (PML4 + sparse PDPTs for guest GPA)");
            println!("    ---------------------------");
            println!("    veneer overhead    : ~11 pages = ~44 KiB total per guest");
        }
        Backend::Vmx => {
            println!("  rationale        : GenuineIntel CPU + VMX — VT-x path available");
            println!("                     (VMX backend is currently SKELETON, see ARCHITECTURE §2/§7)");
        }
        Backend::None => {
            println!("  rationale        : neither SVM nor VMX viable on this host");
            for b in caps.blockers() {
                println!("    - {b}");
            }
        }
    }
    Ok(())
}
