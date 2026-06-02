//! VMRUN — execute the guest, capture the VMEXIT.
//!
//! AMD APM Vol 2 §15.5: VMRUN/VMEXIT save/load only the "basic" state.
//! FS.base, GS.base, KernelGsBase, STAR/LSTAR/CSTAR/SFMASK and SYSENTER_*
//! require explicit VMSAVE/VMLOAD. Without that, every guest GS-relative
//! percpu read sees CPU.GS.base = 0 (host UEFI value), reads from the
//! kernel image template (= 0), and falls into __list_del_entry NULL deref
//! at mem_init. Bracket VMRUN with vmsave host / vmload guest before and
//! vmsave guest / vmload host after to keep VMCB and CPU hidden state in
//! sync.
//!
//! Round-trip pattern:
//!   1. Push host non-volatile regs (rbx, rbp) — LLVM reserves these so we
//!      can't list them as clobbers; save/restore them ourselves.
//!   2. Push host_ext_save_pa, gprs ptr, vmcb_phys onto stack.
//!   3. `vmsave host_ext_save_pa` — save host FS/GS/KernelGsBase/etc.
//!   4. `vmload vmcb_phys` — load guest FS/GS/KernelGsBase/etc. into CPU.
//!   5. Load guest RBX..R15 from `gprs` (RAX via VMCB.state.rax).
//!   6. `mov rax, vmcb_phys` ; `vmrun`. Hardware saves host RAX/etc to
//!      VM_HSAVE_PA and resumes the guest at VMCB.state.rip.
//!   7. On VMEXIT, hardware reloads host RAX (= vmcb_phys); guest's
//!      RBX..R15 still in CPU regs. Save them back to gprs.
//!   8. `vmsave vmcb_phys` — save guest FS/GS/etc. back to VMCB so the
//!      next vmload picks up SWAPGS effects / pre-WRMSR-intercept state.
//!   9. `vmload host_ext_save_pa` — restore host FS/GS/etc.
//!   10. Pop discards then host rbp, host rbx.

use core::arch::asm;

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

#[derive(Debug, Clone, Copy)]
pub struct VmexitInfo {
    pub exit_code: u64,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub guest_rip: u64,
    pub guest_rax: u64,
}

pub unsafe fn vmrun(vmcb_phys: u64, host_ext_save_pa: u64, gprs: &mut GuestGprs) -> VmexitInfo {
    unsafe {
        // Three `in(reg)` inputs + 13 clobbered registers + 3 LLVM-reserved
        // (rbx/rbp/rsp) exhausts the 16 GPRs and LLVM rejects the asm. Pin
        // each input to a specific register via `inout("rXX") val => _` so
        // its slot is shared between input and clobber.
        //
        // Stack layout after the five pushes (top → bottom):
        //   [rsp + 0]   vmcb_phys
        //   [rsp + 8]   gprs ptr
        //   [rsp + 16]  host_ext_save_pa
        //   [rsp + 24]  host rbp
        //   [rsp + 32]  host rbx
        asm!(
            "push rbx",
            "push rbp",
            "push rdi",              // host_ext_save_pa
            "push rsi",              // gprs ptr
            "push rdx",              // vmcb_phys

            // ---- save host extended state (FS/GS/KernelGsBase/STAR/...) ----
            "mov rax, [rsp + 16]",   // rax = host_ext_save_pa
            "vmsave rax",

            // ---- load guest extended state into CPU ----
            "mov rax, [rsp]",        // rax = vmcb_phys
            "vmload rax",

            // ---- load guest GPRs from gprs ----
            "mov rax, [rsp + 8]",    // rax = gprs ptr
            "mov rbx, [rax + 0]",
            "mov rcx, [rax + 8]",
            "mov rdx, [rax + 16]",
            "mov rsi, [rax + 24]",
            "mov rdi, [rax + 32]",
            "mov rbp, [rax + 40]",
            "mov r8,  [rax + 48]",
            "mov r9,  [rax + 56]",
            "mov r10, [rax + 64]",
            "mov r11, [rax + 72]",
            "mov r12, [rax + 80]",
            "mov r13, [rax + 88]",
            "mov r14, [rax + 96]",
            "mov r15, [rax + 104]",

            // ---- VMRUN ----
            // Set host IF=1 so VMRUN saves it: with V_INTR_MASKING the saved
            // host IF gates PHYSICAL interrupts during guest execution, and the
            // INTR intercept turns a host preemption-tick interrupt into a
            // #VMEXIT(INTR) instead of vectoring it anywhere. The `sti` interrupt
            // shadow plus GIF=0 (cleared by the previous exit's clgi) keep the
            // gap before vmrun interrupt-free; vmrun then sets GIF=1 for guest.
            "sti",
            "mov rax, [rsp]",        // rax = vmcb_phys
            "vmrun",
            // === VMEXIT lands here ===

            // ---- save guest GPRs back to gprs ----
            "mov rax, [rsp + 8]",    // rax = gprs ptr
            "mov [rax + 0],   rbx",
            "mov [rax + 8],   rcx",
            "mov [rax + 16],  rdx",
            "mov [rax + 24],  rsi",
            "mov [rax + 32],  rdi",
            "mov [rax + 40],  rbp",
            "mov [rax + 48],  r8",
            "mov [rax + 56],  r9",
            "mov [rax + 64],  r10",
            "mov [rax + 72],  r11",
            "mov [rax + 80],  r12",
            "mov [rax + 88],  r13",
            "mov [rax + 96],  r14",
            "mov [rax + 104], r15",

            // ---- save guest extended state back to VMCB ----
            // Must precede the intercept handler so handler-side writes
            // to s.gs.base / s.fs.base / s.kernel_gs_base are the LAST
            // write and not clobbered by hardware-saved state.
            "mov rax, [rsp]",        // rax = vmcb_phys
            "vmsave rax",

            // ---- restore host extended state ----
            "mov rax, [rsp + 16]",   // rax = host_ext_save_pa
            "vmload rax",
            // Interrupt window: #VMEXIT cleared GIF, so the physical tick that
            // forced an INTR exit is still pending and un-acked. Open a one-
            // instruction window (stgi enables interrupt delivery, sti+nop lets
            // the CPU vector the pending IRQ into our host timer ISR which EOIs
            // it) then close it again (cli/clgi) so host context stays quiet —
            // veneer otherwise polls UEFI with interrupts off. Without this the
            // next vmrun would re-exit immediately on the same pending IRQ.
            "stgi",
            "sti",
            "nop",
            "cli",
            "clgi",

            // ---- cleanup ----
            "add rsp, 24",   // discard vmcb_phys + gprs ptr + host_ext_save_pa
            "pop rbp",       // restore host rbp
            "pop rbx",       // restore host rbx

            inout("rdx") vmcb_phys => _,
            inout("rsi") gprs as *mut GuestGprs => _,
            inout("rdi") host_ext_save_pa => _,
            // rbx and rbp are LLVM-reserved; saved/restored manually above.
            out("rax") _, out("rcx") _,
            out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
        );
    }

    // Pull exit info out of the VMCB. UEFI hands us identity-mapped memory
    // so we can treat vmcb_phys as a regular pointer.
    let vmcb = vmcb_phys as *const Vmcb;
    let c = unsafe { &(*vmcb).control };
    let s = unsafe { &(*vmcb).state };
    VmexitInfo {
        exit_code: c.exit_code,
        exit_info_1: c.exit_info_1,
        exit_info_2: c.exit_info_2,
        guest_rip: s.rip,
        guest_rax: s.rax,
    }
}

/// Human-readable mnemonic for an AMD SVM exit code (the subset we care
/// about). Returns `None` for codes we haven't tagged.
pub fn exit_code_name(code: u64) -> Option<&'static str> {
    use crate::hypervisor::vmexit::exception;
    use crate::hypervisor::svm::vmcb::exit_code as ec;
    if ec::is_cr_read(code) { return Some("CR read"); }
    if ec::is_cr_write(code) { return Some("CR write"); }
    if ec::is_dr_read(code) { return Some("DR read"); }
    if ec::is_dr_write(code) { return Some("DR write"); }
    if exception::is_exception(code) {
        let vector = (code - exception::EXCP_BASE) as u8;
        return Some(exception::name(vector));
    }
    Some(match code {
        ec::INTR => "INTR (physical interrupt / preemption tick)",
        ec::CPUID => "CPUID",
        ec::HLT => "HLT",
        ec::IOIO => "IOIO (in/out)",
        ec::MSR => "MSR (RDMSR / WRMSR)",
        ec::RDTSC => "RDTSC",
        ec::RDTSCP => "RDTSCP",
        ec::RDPMC => "RDPMC",
        ec::PUSHF => "PUSHF",
        ec::POPF => "POPF",
        ec::IDTR_READ => "SIDT",
        ec::GDTR_READ => "SGDT",
        ec::LDTR_READ => "SLDT",
        ec::TR_READ => "STR",
        ec::INVD => "INVD",
        ec::WBINVD => "WBINVD",
        ec::MONITOR => "MONITOR",
        ec::MWAIT => "MWAIT",
        ec::XSETBV => "XSETBV",
        ec::SHUTDOWN => "SHUTDOWN",
        ec::VMRUN => "VMRUN",
        ec::VMMCALL => "VMMCALL",
        ec::NPF => "NPF (nested page fault)",
        ec::INVALID => "INVALID (consistency check failed)",
        _ => return None,
    })
}
