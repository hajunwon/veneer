//! Boot-time reporting of SVM bring-up, active profile, AP probe, and
//! VMEXIT state to the serial console.

use crate::{sprint, sprintln};
use crate::hardware::identity::profile;
use crate::hypervisor::svm::{self, smp, vmcb, vmrun};

pub fn report_profile(p: &profile::Profile) {
    // packed-struct fields → read_unaligned via local copies
    let name = unsafe { core::ptr::addr_of!(p.name).read_unaligned() };
    let cpu = unsafe { core::ptr::addr_of!(p.hardware.cpu).read_unaligned() };
    let smb = unsafe { core::ptr::addr_of!(p.hardware.smbios).read_unaligned() };
    let net = unsafe { core::ptr::addr_of!(p.hardware.network).read_unaligned() };
    let disk = unsafe { core::ptr::addr_of!(p.hardware.disk).read_unaligned() };

    sprintln!("[prof] active: name=\"{}\"", name.as_str());
    sprintln!("[prof]   cpu     : brand=\"{}\" vendor=\"{}\" hide_bit={} hide_leaf={}",
        cpu.brand.as_str(), cpu.vendor.as_str(),
        cpu.hide_hypervisor_bit, cpu.hide_hypervisor_leaf);
    sprintln!("[prof]   smbios  : manufacturer=\"{}\" product=\"{}\"",
        smb.manufacturer.as_str(), smb.product.as_str());
    sprintln!("[prof]   smbios  : serial=\"{}\" uuid=\"{}\"",
        smb.serial.as_str(), smb.uuid.as_str());
    sprintln!("[prof]   network : mac=\"{}\"", net.mac.as_str());
    sprintln!("[prof]   disk    : slot=\"{}\" model=\"{}\" serial=\"{}\"",
        disk.slot.as_str(), disk.model.as_str(), disk.serial.as_str());
}

pub fn report_ap_probe(r: &smp::ApReports) {
    let mut any = false;
    for slot in r.slots.iter() {
        if !slot.valid {
            continue;
        }
        any = true;
        let v = core::str::from_utf8(&slot.vendor).unwrap_or("???");
        sprintln!(
            "[ap  ] APIC#{:02} vendor={} svm={} svmdis={} EFER=0x{:016X}",
            slot.apic_id, v, slot.svm_supported, slot.svmdis, slot.efer
        );
    }
    if !any {
        sprintln!("[ap  ] startup_all_aps returned no AP reports");
    }
}

pub fn verify(name: &str, got: u64, want: u64) {
    let mark = if got == want { "✓ MATCH" } else { "✗ MISMATCH" };
    sprintln!("[vmm ]   {} : got 0x{:016X}  want 0x{:016X}  {}", name, got, want, mark);
}

pub fn report_vmexit(v: &vmrun::VmexitInfo) {
    let name = vmrun::exit_code_name(v.exit_code).unwrap_or("(unrecognised)");
    sprintln!(
        "[exit] exit_code   : 0x{:016X}  ({})",
        v.exit_code, name
    );
    sprintln!("[exit] exit_info_1 : 0x{:016X}", v.exit_info_1);
    sprintln!("[exit] exit_info_2 : 0x{:016X}", v.exit_info_2);
    sprintln!("[exit] guest RIP   : 0x{:016X}", v.guest_rip);
    sprintln!("[exit] guest RAX   : 0x{:016X}", v.guest_rax);
}

pub fn report_success(s: &svm::SvmState) {
    let v = core::str::from_utf8(&s.vendor).unwrap_or("???");
    sprintln!("[svm ] vendor              : {}", v);
    sprintln!(
        "[svm ] family/model/stepping: 0x{:08X}",
        s.family_model_stepping
    );
    sprintln!("[svm ] svm supported       : {}", s.svm_supported);
    sprintln!("[svm ] nested paging (NPT) : {}", s.nested_paging);
    sprintln!("[svm ] N_ASIDs             : {}", s.n_asids);
    sprintln!("[svm ] EFER before         : 0x{:016X}", s.efer_before);
    sprintln!(
        "[svm ] EFER after  (SVME=1): 0x{:016X}",
        s.efer_after
    );
    sprintln!(
        "[svm ] VM_HSAVE_PA before  : 0x{:016X}",
        s.vm_hsave_pa_before
    );
    sprintln!(
        "[svm ] VM_HSAVE_PA after   : 0x{:016X}",
        s.vm_hsave_pa_after
    );
    sprintln!("[svm ] ext save PA (VMSAVE) : 0x{:016X}", s.ext_save_pa);
    sprintln!("[vmcb] phys addr           : 0x{:016X}", s.vmcb_phys);
    sprintln!("[vmcb] intercept_vec1      : 0x{:08X}", s.vmcb_intercept_vec1);
    sprintln!("[vmcb] intercept_vec2      : 0x{:08X}", s.vmcb_intercept_vec2);
    sprintln!("[vmcb] guest_asid          : {}", s.vmcb_guest_asid);
    sprintln!("[svm ] bring-up: OK — SVM armed, VMCB configured.");
}

pub fn report_error(e: &svm::BringupError) {
    sprint!("[svm ] bring-up FAILED: ");
    match e {
        svm::BringupError::NotAmd => sprintln!("CPU is not AuthenticAMD"),
        svm::BringupError::SvmUnsupported => {
            sprintln!("CPUID 0x80000001.ECX bit 2 = 0 (SVM not in CPU)")
        }
        svm::BringupError::SvmDisabledByBios => {
            sprintln!("VM_CR.SVMDIS = 1 (BIOS/firmware disables SVM)")
        }
        svm::BringupError::EferWriteRejected => {
            sprintln!("EFER.SVME wrote but read back 0 (locked by firmware)")
        }
        svm::BringupError::HostSaveAllocFailed => {
            sprintln!("UEFI AllocatePages refused to give us 4 KiB")
        }
        svm::BringupError::HsavePaReadbackMismatch { wrote, read } => sprintln!(
            "VM_HSAVE_PA wrote 0x{:016X} read 0x{:016X}",
            wrote, read
        ),
        svm::BringupError::VmcbAllocFailed(e) => match e {
            vmcb::AllocError::AllocatePagesFailed => {
                sprintln!("UEFI AllocatePages refused VMCB 4 KiB")
            }
            vmcb::AllocError::NotPageAligned(addr) => {
                sprintln!("VMCB page came back unaligned: 0x{:016X}", addr)
            }
        },
    }
}
