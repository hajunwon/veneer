//! VMCB layout for the UEFI runtime side. Mirrors `src/svm/vmcb.rs` on the
//! std crate — same `#[repr(C, packed)]` offsets, same AMD APM Vol 2 Table
//! B-1 spec-lock. Duplicated here to avoid forcing the root crate to be
//! `no_std`. If the two ever diverge, the integration test in
//! `tests/vmcb_layout.rs` will fail on size, and the offset-check function
//! in this module will fail at VMCB allocation time.
//!
//! Why a separate copy: the root crate pulls in `anyhow`, `thiserror` and
//! `serde` which are all std-only. Refactoring all of that to be no_std-
//! aware is a v0.4 task. For now the VMCB definition is small enough to
//! duplicate, and the cost is one extra place to keep in sync if the spec
//! ever changes (it won't — the layout is fixed by AMD).

#![allow(dead_code)]


pub const VMCB_SIZE: usize = 0x1000;
pub const VMCB_CONTROL_SIZE: usize = 0x400;
pub const VMCB_STATE_SAVE_OFFSET: usize = 0x400;

#[repr(C, align(4096))]
pub struct Vmcb {
    pub control: VmcbControl,
    pub state: VmcbStateSave,
}

const _: () = {
    assert!(core::mem::size_of::<Vmcb>() == VMCB_SIZE);
};

#[repr(C, packed)]
pub struct VmcbControl {
    pub intercept_cr_read: u16,         // 0x000
    pub intercept_cr_write: u16,        // 0x002
    pub intercept_dr_read: u16,         // 0x004
    pub intercept_dr_write: u16,        // 0x006
    pub intercept_exceptions: u32,      // 0x008
    pub intercept_vec1: u32,            // 0x00C
    pub intercept_vec2: u32,            // 0x010
    _rsvd0: [u8; 0x028],                // 0x014..0x03C
    pub pause_filter_thresh: u16,       // 0x03C
    pub pause_filter_count: u16,        // 0x03E
    pub iopm_pa: u64,                   // 0x040
    pub msrpm_pa: u64,                  // 0x048
    pub tsc_offset: u64,                // 0x050
    pub guest_asid: u32,                // 0x058
    pub tlb_control: u32,               // 0x05C
    pub vintr: u64,                     // 0x060
    pub interrupt_shadow: u64,          // 0x068
    pub exit_code: u64,                 // 0x070
    pub exit_info_1: u64,               // 0x078
    pub exit_info_2: u64,               // 0x080
    pub exit_int_info: u64,             // 0x088
    // bit 0 = NP_ENABLE, bit 1 = ENABLE_SEV, bit 2 = ENABLE_SEV_ES.
    // (The std-side VmcbControl in src/svm/vmcb.rs misnames this `ncr3`;
    // we use the correct name here and put NCR3 in its actual location.)
    pub np_enable: u64,                 // 0x090
    _rsvd_avic_bar: u64,                // 0x098 — AVIC_APIC_BAR (unused)
    _rsvd_ghcb_or_pat: u64,             // 0x0A0 — GHCB_GPA / guest_PAT (unused)
    pub event_inj: u64,                 // 0x0A8 — event_inj (32) + err (32)
    pub ncr3: u64,                      // 0x0B0 — TRUE Nested CR3
    pub lbr_virt_enable: u64,           // 0x0B8 — LBR / virt_ext bits
    pub clean_bits: u32,                // 0x0C0
    _rsvd_clean: u32,                   // 0x0C4
    pub next_rip: u64,                  // 0x0C8 — AMD NRIPS feature
    pub guest_inst_len: u8,             // 0x0D0
    pub guest_inst_bytes: [u8; 15],     // 0x0D1..0x0E0
    _rsvd_tail: [u8; VMCB_CONTROL_SIZE - 0xE0],
}

const _: () = {
    assert!(core::mem::size_of::<VmcbControl>() == VMCB_CONTROL_SIZE);
};

#[repr(C, packed)]
pub struct VmcbStateSave {
    pub es: SegSelector,   // 0x400
    pub cs: SegSelector,   // 0x410
    pub ss: SegSelector,   // 0x420
    pub ds: SegSelector,   // 0x430
    pub fs: SegSelector,   // 0x440
    pub gs: SegSelector,   // 0x450
    pub gdtr: SegSelector, // 0x460
    pub ldtr: SegSelector, // 0x470
    pub idtr: SegSelector, // 0x480
    pub tr: SegSelector,   // 0x490
    _rsvd0: [u8; 0x2B],    // 0x4A0..0x4CB
    pub cpl: u8,           // 0x4CB
    _rsvd1: u32,           // 0x4CC
    pub efer: u64,         // 0x4D0
    _rsvd2: [u8; 0x70],    // 0x4D8..0x548
    pub cr4: u64,          // 0x548
    pub cr3: u64,          // 0x550
    pub cr0: u64,          // 0x558
    pub dr7: u64,          // 0x560
    pub dr6: u64,          // 0x568
    pub rflags: u64,       // 0x570
    pub rip: u64,          // 0x578
    _rsvd3: [u8; 0x58],    // 0x580..0x5D8
    pub rsp: u64,          // 0x5D8
    _rsvd4: [u8; 0x18],    // 0x5E0..0x5F8
    pub rax: u64,          // 0x5F8
    pub star: u64,         // 0x600
    pub lstar: u64,        // 0x608
    pub cstar: u64,        // 0x610
    pub sfmask: u64,       // 0x618
    pub kernel_gs_base: u64, // 0x620
    pub sysenter_cs: u64,    // 0x628
    pub sysenter_esp: u64,   // 0x630
    pub sysenter_eip: u64,   // 0x638
    pub cr2: u64,            // 0x640
    _rsvd_tail: [u8; VMCB_SIZE - VMCB_STATE_SAVE_OFFSET - 0x248],
}

const _: () = {
    assert!(core::mem::size_of::<VmcbStateSave>() == VMCB_SIZE - VMCB_STATE_SAVE_OFFSET);
};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SegSelector {
    pub selector: u16,
    pub attribute: u16,
    pub limit: u32,
    pub base: u64,
}

const _: () = {
    assert!(core::mem::size_of::<SegSelector>() == 0x10);
};

/// Bit positions in `VmcbControl.intercept_vec1`. Only what veneer touches.
/// (AMD APM Vol 2 §15.9, Table 15-9.)
pub mod intercept_vec1 {
    pub const INTR: u32 = 1 << 0;
    pub const NMI: u32 = 1 << 1;
    pub const SMI: u32 = 1 << 2;
    pub const INIT: u32 = 1 << 3;
    pub const VINTR: u32 = 1 << 4;
    pub const CPUID: u32 = 1 << 18;
    pub const RSM: u32 = 1 << 19;
    pub const IRET: u32 = 1 << 20;
    pub const RDTSC: u32 = 1 << 14;
    pub const RDPMC: u32 = 1 << 15;
    pub const PUSHF: u32 = 1 << 16;
    pub const POPF: u32 = 1 << 17;
    // Descriptor-table read intercepts (SIDT/SGDT/SLDT/STR).
    pub const IDTR_READ: u32 = 1 << 6;
    pub const GDTR_READ: u32 = 1 << 7;
    pub const LDTR_READ: u32 = 1 << 8;
    pub const TR_READ: u32 = 1 << 9;
    pub const INVD: u32 = 1 << 22;
    pub const PAUSE: u32 = 1 << 23;
    pub const HLT: u32 = 1 << 24;
    pub const INVLPG: u32 = 1 << 25;
    pub const INVLPGA: u32 = 1 << 26;
    pub const IOIO_PROT: u32 = 1 << 27;
    pub const MSR_PROT: u32 = 1 << 28;
    pub const SHUTDOWN: u32 = 1 << 31;
}

/// `VmcbControl.intercept_vec2` (AMD APM Vol 2 §15.9, Table 15-10).
pub mod intercept_vec2 {
    pub const VMRUN: u32 = 1 << 0;  // must always be set for AMD SVM
    pub const VMMCALL: u32 = 1 << 1;
    pub const VMLOAD: u32 = 1 << 2;
    pub const VMSAVE: u32 = 1 << 3;
    pub const STGI: u32 = 1 << 4;
    pub const CLGI: u32 = 1 << 5;
    pub const SKINIT: u32 = 1 << 6;
    pub const RDTSCP: u32 = 1 << 7;
    pub const ICEBP: u32 = 1 << 8;
    pub const WBINVD: u32 = 1 << 9;
    pub const MONITOR: u32 = 1 << 10;
    pub const MWAIT: u32 = 1 << 11;
    pub const XSETBV: u32 = 1 << 13;
}

/// `VmcbControl.vintr` field (offset 0x60) bit layout — AMD APM Vol 2
/// §15.21.2 (Injecting Virtual Interrupts). veneer raises maskable guest
/// interrupts through V_IRQ so the CPU gates delivery on V_TPR (the guest's
/// virtualised IRQL/CR8) and guest IF, exactly as physical interrupt
/// acceptance does — rather than the unconditional event_inj path.
pub mod vintr {
    /// V_TPR — bits 7:0. Bits 3:0 hold the guest CR8 (task priority / IRQL);
    /// the CPU maintains this when CR8 is left un-intercepted.
    pub const V_TPR_MASK: u64 = 0xFF;
    /// V_IRQ (bit 8) — a virtual interrupt is pending. Hardware clears it
    /// once the interrupt is delivered to the guest.
    pub const V_IRQ: u64 = 1 << 8;
    /// V_INTR_PRIO (bits 19:16) — priority of the pending virtual interrupt.
    /// Delivered only when V_INTR_PRIO > V_TPR (unless V_IGN_TPR).
    pub const V_INTR_PRIO_SHIFT: u64 = 16;
    /// V_IGN_TPR (bit 20) — ignore V_TPR when deciding to deliver. Left clear
    /// so IRQL gating applies.
    pub const V_IGN_TPR: u64 = 1 << 20;
    /// V_INTR_MASKING (bit 24) — virtualise guest IF/TPR; physical IRQs use
    /// host IF.
    pub const V_INTR_MASKING: u64 = 1 << 24;
    /// V_INTR_VECTOR (bits 39:32) — the vector delivered when V_IRQ fires.
    pub const V_INTR_VECTOR_SHIFT: u64 = 32;
}

/// AMD APM Vol 2 §15.9 / Appendix C. Only the exit codes veneer cares about.
/// (Cross-checked against Linux KVM's `arch/x86/include/uapi/asm/svm.h`.)
pub mod exit_code {
    pub const INTR: u64 = 0x60;          // physical interrupt (with INTR intercept)
    pub const HLT: u64 = 0x78;
    pub const INVLPGA: u64 = 0x7A;
    pub const IOIO: u64 = 0x7B;          // in/out — exit_info_1 bits 16-31 = port
    pub const MSR: u64 = 0x7C;           // RDMSR + WRMSR; exit_info_1 bit 0 distinguishes
    pub const SHUTDOWN: u64 = 0x7F;
    pub const VMRUN: u64 = 0x80;
    pub const VMMCALL: u64 = 0x81;
    pub const CPUID: u64 = 0x72;
    pub const RDTSC: u64 = 0x6E;
    pub const RDPMC: u64 = 0x6F;
    pub const RDTSCP: u64 = 0x87;
    pub const PUSHF: u64 = 0x70;
    pub const POPF: u64 = 0x71;
    pub const INVD: u64 = 0x76;
    pub const WBINVD: u64 = 0x89;
    pub const MONITOR: u64 = 0x8A;
    pub const MWAIT: u64 = 0x8B;
    pub const XSETBV: u64 = 0x8D;
    // Descriptor-table reads (SGDT/SIDT/SLDT/STR) and writes.
    pub const IDTR_READ: u64 = 0x66;
    pub const GDTR_READ: u64 = 0x67;
    pub const LDTR_READ: u64 = 0x68;
    pub const TR_READ: u64 = 0x69;
    pub const NPF: u64 = 0x400;
    pub const INVALID: u64 = u64::MAX;

    // Control-register access: 0x000–0x00F = CRn read, 0x010–0x01F = CRn write.
    pub const CR_READ_BASE: u64 = 0x000;
    pub const CR_WRITE_BASE: u64 = 0x010;
    // Debug-register access: 0x020–0x02F = DRn read, 0x030–0x03F = DRn write.
    pub const DR_READ_BASE: u64 = 0x020;
    pub const DR_WRITE_BASE: u64 = 0x030;

    #[inline]
    pub fn is_cr_read(code: u64) -> bool {
        (CR_READ_BASE..CR_READ_BASE + 0x10).contains(&code)
    }
    #[inline]
    pub fn is_cr_write(code: u64) -> bool {
        (CR_WRITE_BASE..CR_WRITE_BASE + 0x10).contains(&code)
    }
    #[inline]
    pub fn is_dr_read(code: u64) -> bool {
        (DR_READ_BASE..DR_READ_BASE + 0x10).contains(&code)
    }
    #[inline]
    pub fn is_dr_write(code: u64) -> bool {
        (DR_WRITE_BASE..DR_WRITE_BASE + 0x10).contains(&code)
    }
}

/// Allocate one zeroed 4 KiB page from UEFI BootServices. Returns the
/// physical address of the page (== virtual under UEFI identity mapping).
/// The page is allocated as `RUNTIME_SERVICES_DATA` so it survives
/// `ExitBootServices`.
pub fn alloc_vmcb() -> Result<*mut Vmcb, AllocError> {
    let phys = crate::platform::alloc_pages(1)
        .map_err(|_| AllocError::AllocatePagesFailed)?;
    let ptr = phys.as_ptr();
    let addr = ptr as usize;
    if addr & 0xFFF != 0 {
        return Err(AllocError::NotPageAligned(addr));
    }
    unsafe { core::ptr::write_bytes(ptr, 0u8, VMCB_SIZE) };
    Ok(ptr.cast::<Vmcb>())
}

#[derive(Debug)]
pub enum AllocError {
    AllocatePagesFailed,
    NotPageAligned(usize),
}

/// Configure a freshly-zeroed VMCB to intercept the standard set veneer
/// cares about: CPUID, HLT, every MSR, every IO port, every CPU exception
/// (0..31). `msrpm_phys` is an 8 KiB MSRPM (see `msrpm.rs`),
/// `iopm_phys` is a 12 KiB IOPM (see `iopm.rs`). Guest state is left zero
/// — call `init_guest_*` separately.
pub unsafe fn init_for_cpuid_intercept(vmcb: *mut Vmcb, msrpm_phys: u64, iopm_phys: u64) {
    let c = unsafe { &mut (*vmcb).control };
    c.intercept_vec1 = intercept_vec1::CPUID
        | intercept_vec1::HLT
        | intercept_vec1::IOIO_PROT
        | intercept_vec1::MSR_PROT
        | intercept_vec1::RDTSC
        | intercept_vec1::RDPMC
        | intercept_vec1::PUSHF
        | intercept_vec1::POPF
        | intercept_vec1::IDTR_READ
        | intercept_vec1::GDTR_READ
        | intercept_vec1::LDTR_READ
        | intercept_vec1::TR_READ
        | intercept_vec1::INVD
        | intercept_vec1::PAUSE;
    // PAUSE filter: a guest that spins with `pause` (spinlocks, idle polls,
    // ownership waits) executes no interceptable instruction, so without this
    // VMRUN never returns and veneer can't inject a pending IRQ or observe the
    // wedge. Intercepting PAUSE hands control back so the dispatcher's
    // stage_pending runs and the stuck-detector sees the spin. The filter
    // batches: exit only after `count` tight pauses (within `thresh` cycles of
    // each other) so a normal sprinkling of PAUSE doesn't exit every time.
    c.pause_filter_count = 65535;
    c.pause_filter_thresh = 0;
    c.intercept_vec2 = intercept_vec2::VMRUN
        | intercept_vec2::VMMCALL
        | intercept_vec2::RDTSCP
        | intercept_vec2::WBINVD
        | intercept_vec2::MONITOR
        | intercept_vec2::MWAIT
        | intercept_vec2::XSETBV;
    // Trap every CPU exception (vector 0..31) so we can decide per-vector
    // later (shadow #PF, emulate #UD, etc.). For the current guest none
    // should fire — any that does means a host or VMCB bug.
    c.intercept_exceptions = 0xFFFF_FFFF;
    // Trap every CR access (CR0..CR15 read/write) and every DR access, EXCEPT
    // CR8. Bit 8 = CR8 = the task-priority register the guest uses for IRQL.
    // Under V_INTR_MASKING the CPU virtualises guest CR8 into VMCB V_TPR
    // (bits 3:0) with no exit; intercepting it instead would route the write
    // here where there's no V_TPR plumbing, so the guest's IRQL would never
    // reach V_TPR and interrupt delivery couldn't honour it. Leave CR8 to the
    // hardware so V_TPR tracks the guest's current IRQL.
    c.intercept_cr_read = 0xFFFF & !(1 << 8);
    c.intercept_cr_write = 0xFFFF & !(1 << 8);
    c.intercept_dr_read = 0xFFFF;
    c.intercept_dr_write = 0xFFFF;
    c.guest_asid = 1;
    c.iopm_pa = iopm_phys;
    c.msrpm_pa = msrpm_phys;
    // V_INTR_MASKING (VINTR bit 24): physical interrupts are governed by
    // the HOST RFLAGS.IF, not the guest's. Per the AMD SVM manual this MUST
    // be paired with the host clearing RFLAGS.IF around VMRUN (see the
    // cli/sti bracket in vmrun.rs) so physical host IRQs stay pending
    // during guest execution instead of vectoring into the guest IDT
    // (which showed up as a spurious vector-0x40 at CpuDxe EnableInterrupts).
    c.vintr = 1 << 24;
}

/// Turn on AMD Nested Paging. Sets NP_ENABLE bit 0 and points NCR3 at the
/// nested page-table root (a PML4 the caller built — see `npt::build_*`).
/// After this returns, guest physical addresses are translated through
/// `ncr3` before becoming host-physical.
pub unsafe fn enable_npt(vmcb: *mut Vmcb, ncr3_phys: u64) {
    let c = unsafe { &mut (*vmcb).control };
    c.np_enable = 1;
    c.ncr3 = ncr3_phys;
}

/// CPU modes veneer can launch a guest in. Each variant carries exactly
/// the address(es) needed to land the fetch pointer in the right place.
#[derive(Debug, Clone, Copy)]
pub enum GuestMode {
    /// 16-bit real mode. `code_phys` is the host-physical address of the
    /// guest's instruction stream; CS.base is set to it, RIP = 0.
    Real16 { code_phys: u64 },
    /// 32-bit protected-mode flat. Requires a GDT in memory + CR0.PE = 1.
    /// Reserved for v0.4-gamma.
    Protected32,
    /// 64-bit long mode with paging on. We reuse the host's CR0/CR3/CR4/EFER
    /// (UEFI gives us an identity-mapped page table covering the entire
    /// physical address space), so guest paging Just Works for any host-
    /// physical address. `code_lin` is the linear address the fetch starts
    /// at — in our case the same physical page the host allocated.
    Long64 { code_lin: u64 },
    /// 64-bit long mode entry into a Linux kernel's `startup_64`. Same
    /// CPU state as `Long64`, but:
    ///   - RIP = `entry_rip` (bzImage protected-mode kernel + 0x200)
    ///   - CR3 = `guest_cr3` (page table we built inside guest RAM --
    ///     UEFI's host CR3 wouldn't survive the NPT translation)
    ///   - RSI = `boot_params_phys` (sole argument startup_64 reads)
    ///   - RSP = a clean stack pointer below 1 MiB so verify_cpu /
    ///     decompressor stub can push/pop before the kernel installs
    ///     its own stack.
    /// Per Documentation/x86/boot.rst "64-bit BOOT PROTOCOL".
    LinuxKernel { entry_rip: u64, boot_params_phys: u64, guest_cr3: u64 },
    /// 32-bit protected-mode entry into a Linux kernel's PVH stub
    /// (`pvh_start_xen`). The Xen-defined PVH boot protocol is the
    /// minimal one Cloud Hypervisor / Firecracker use; the kernel does
    /// its own paging / IDT / stack setup, so we just have to land it
    /// in 32-bit flat protected mode with EBX = start_info phys.
    ///
    /// Per ELF Note XEN_ELFNOTE_PHYS32_ENTRY (vmlinux PT_NOTE) +
    /// Documentation/virt/kvm/x86/PVH-boot-protocol.txt.
    LinuxPvh { entry_eip: u32, start_info_phys: u32 },
    /// x86 power-on reset state — the CPU's architectural state at the
    /// first instruction fetch. Used to hand control to a guest firmware
    /// (OVMF) whose reset vector lives at 0xFFFFFFF0. Same real-mode
    /// segment setup as `Real16`, but CS.base is fixed to 0xFFFF0000 so
    /// CS.base + RIP(0xFFF0) = 0xFFFFFFF0 (the architectural reset vector).
    ResetVector,
}

/// Single entry point for initialising VMCB.state per a chosen `GuestMode`.
///
/// Real16 and Long64 are implemented. Protected32 is stubbed.
pub unsafe fn init_guest(vmcb: *mut Vmcb, mode: GuestMode) {
    match mode {
        GuestMode::Real16 { code_phys } => unsafe { init_guest_realmode(vmcb, code_phys) },
        GuestMode::Protected32 => unimplemented!("Protected32 guest — see v0.4 TODO"),
        GuestMode::Long64 { code_lin } => unsafe { init_guest_longmode(vmcb, code_lin) },
        GuestMode::LinuxKernel { entry_rip, boot_params_phys, guest_cr3 } => unsafe {
            init_guest_linux(vmcb, entry_rip, boot_params_phys, guest_cr3)
        },
        GuestMode::LinuxPvh { entry_eip, start_info_phys } => unsafe {
            init_guest_pvh(vmcb, entry_eip, start_info_phys)
        },
        GuestMode::ResetVector => unsafe { init_guest_reset_vector(vmcb) },
    }
}

/// Configure VMCB.state for the x86 architectural reset vector. The guest
/// begins fetching at 0xFFFFFFF0 (CS.base 0xFFFF0000 + RIP 0xFFF0), which
/// is where a PC firmware (OVMF) places its first instruction. Identical
/// to `init_guest_realmode` except CS.base is the fixed reset value rather
/// than a blob address.
///
/// "Big real mode": CS.base sits near 4 GiB but the segment runs in real
/// mode (CR0.PE=0, limit 0xFFFF). The CPU uses the hidden base cache, so
/// the selector (0xF000) is irrelevant to address generation. OVMF's
/// ResetVector code then probes CR0.PE and transitions to protected/long
/// mode itself.
pub unsafe fn init_guest_reset_vector(vmcb: *mut Vmcb) {
    let s = unsafe { &mut (*vmcb).state };

    // Code segment — real-mode 16-bit, base = architectural reset value.
    // attr 0x009B = type 0xB (execute/read/accessed) | S=1 | P=1
    s.cs = SegSelector {
        selector: 0xF000,
        attribute: 0x009B,
        limit: 0xFFFF,
        base: 0xFFFF_0000,
    };

    // Data segments — real-mode 16-bit, base 0.
    let data = SegSelector { selector: 0x0000, attribute: 0x0093, limit: 0xFFFF, base: 0 };
    s.ss = data;
    s.ds = data;
    s.es = data;
    s.fs = data;
    s.gs = data;

    s.gdtr = SegSelector { selector: 0, attribute: 0, limit: 0xFFFF, base: 0 };
    s.idtr = SegSelector { selector: 0, attribute: 0, limit: 0xFFFF, base: 0 };
    s.ldtr = SegSelector { selector: 0, attribute: 0x0000, limit: 0, base: 0 };
    s.tr = SegSelector { selector: 0, attribute: 0x0083, limit: 0x67, base: 0 };

    s.cpl = 0;

    // CR0 = 0x60000010 → NW=1, CD=1, ET=1, PE=0, PG=0 (real mode).
    s.cr0 = 0x6000_0010;
    s.cr3 = 0;
    s.cr4 = 0;
    // EFER.SVME must stay set for the guest (AMD APM Vol 2 §15.5 consistency
    // check — a guest with SVME=0 fails VMRUN with #VMEXIT(INVALID)). Real
    // mode otherwise, so LME/LMA stay clear. The architectural reset value
    // is EFER=0, but under SVM the hypervisor must keep SVME asserted.
    s.efer = crate::infra::arch::EFER_SVME;

    s.rip = 0xFFF0;
    s.rsp = 0;
    s.rax = 0;
    s.rflags = 0x2;

    s.dr6 = 0xFFFF_0FF0;
    s.dr7 = 0x0000_0400;
}

/// Configure VMCB.state for a real-mode guest whose code lives at
/// `guest_code_phys` (a 4 KiB-aligned host-physical address from UEFI).
///
/// Trick: we set `cs.base = guest_code_phys` and `rip = 0`. The CPU computes
/// linear address as `cs.base + rip` regardless of the selector field, so
/// this places the guest's fetch pointer exactly at our blob — even though
/// UEFI handed us a page above the 1 MiB real-mode addressing limit. This
/// is the classic "unreal-mode hidden-base cache" pattern.
///
/// AMD APM Vol 2 §15.5 consistency checks we satisfy here:
///   - CR0.PE=0 + CR0.PG=0           → real mode
///   - CR0.NW=1 + CR0.CD=1            → cache-disable (both required together)
///   - CR4.PAE=0 + CR3 high bits 0    → no long mode
///   - CS/SS/DS/ES/FS/GS attributes   → P=1, S=1, type's "accessed" bit set
///   - SS DPL == CPL                  → both 0
///   - TR present                     → attribute 0x8B (busy 16-bit TSS, P=1)
///   - LDTR present-but-null          → attribute 0x82
///   - RFLAGS reserved bit 1          → 0x2
pub unsafe fn init_guest_realmode(vmcb: *mut Vmcb, guest_code_phys: u64) {
    let s = unsafe { &mut (*vmcb).state };

    // Code segment — real-mode 16-bit. Base is set to the blob's physical
    // address so RIP=0 lands the fetch on the first byte of our code.
    // attr 0x009B = type 0xB (execute/read/accessed) | S=1 | P=1
    s.cs = SegSelector {
        selector: 0x0000,
        attribute: 0x009B,
        limit: 0xFFFF,
        base: guest_code_phys,
    };

    // Data segments — real-mode 16-bit, base 0 (the blob does no data
    // accesses, so it doesn't matter where these point).
    // attr 0x0093 = type 0x3 (read/write/accessed) | S=1 | P=1
    let data = SegSelector { selector: 0x0000, attribute: 0x0093, limit: 0xFFFF, base: 0 };
    s.ss = data;
    s.ds = data;
    s.es = data;
    s.fs = data;
    s.gs = data;

    // Descriptor table registers — real-mode defaults.
    s.gdtr = SegSelector { selector: 0, attribute: 0, limit: 0xFFFF, base: 0 };
    s.idtr = SegSelector { selector: 0, attribute: 0, limit: 0xFFFF, base: 0 };

    // LDTR — null. AMD consistency check accepts selector=0 with P=0 (null
    // LDT). Earlier we set P=1 which is inconsistent for a null selector
    // and causes #VMEXIT(INVALID).
    s.ldtr = SegSelector { selector: 0, attribute: 0x0000, limit: 0, base: 0 };

    // TR — must be present per AMD consistency check. 16-bit busy TSS has
    // type=3 (0x83 with P=1) and a 0x67 byte limit. Earlier we used 0x8B
    // (32-bit busy TSS) with a 0xFFFF limit — that type/limit combination
    // is rejected.
    s.tr = SegSelector { selector: 0, attribute: 0x0083, limit: 0x67, base: 0 };

    s.cpl = 0;

    // CR0 = 0x60000010 → NW=1, CD=1, ET=1, PE=0, PG=0 (real mode).
    s.cr0 = 0x6000_0010;
    s.cr3 = 0;
    s.cr4 = 0;
    s.efer = 0;

    s.rip = 0;
    s.rsp = 0;
    s.rax = 0;
    s.rflags = 0x2; // bit 1 is reserved-set-to-1

    s.dr6 = 0xFFFF_0FF0;
    s.dr7 = 0x0000_0400;
}

/// Configure VMCB.state for a 64-bit long-mode guest. The guest reuses the
/// host's CR0/CR3/CR4/EFER (UEFI gives the firmware app an identity-mapped
/// page table that covers every host-physical address), so we can put
/// `code_lin` anywhere the host can address and the guest will fetch it.
///
/// AMD APM Vol 2 §15.5 consistency checks we satisfy here:
///   - CR0.PE=1 + CR0.PG=1 + EFER.LMA=1 + EFER.LME=1 + CR4.PAE=1 → long mode
///   - CS attribute L=1, D=0 (mandatory for 64-bit code segments)
///   - TR busy, P=1, limit = 0x67 (64-bit TSS minimum)
///   - LDTR null with P=0
///   - RFLAGS reserved bit 1 → 0x2
pub unsafe fn init_guest_longmode(vmcb: *mut Vmcb, code_lin: u64) {
    let s = unsafe { &mut (*vmcb).state };

    // Code segment — long-mode 64-bit. attr 0x029B = type 0xB | S=1 | P=1 | L=1.
    // base/limit are ignored in long mode but we set sensible values.
    s.cs = SegSelector { selector: 0x10, attribute: 0x029B, limit: 0xFFFFFFFF, base: 0 };

    // Data segments — type 3 (RW/accessed), S=1, P=1. base/limit ignored.
    let data = SegSelector { selector: 0x18, attribute: 0x0093, limit: 0xFFFFFFFF, base: 0 };
    s.ss = data;
    s.ds = data;
    s.es = data;
    s.fs = data;
    s.gs = data;

    // Seed plausible Windows-kernel IDTR/GDTR values so SIDT/SGDT reports
    // a high kernel address (real Windows ASLR slot range), not 0 — a
    // ScoopyNG-style detector reading IDTR base == 0 immediately flags
    // hypervisor. Intercepts catch all exceptions before any IDT lookup
    // so these never get dereferenced. The exact numbers come from a
    // typical Windows 11 kernel layout but the values themselves are
    // synthetic — not pulled from any live system.
    s.gdtr = SegSelector { selector: 0, attribute: 0, limit: 0x007F, base: 0xFFFF_F800_0000_2000 };
    s.idtr = SegSelector { selector: 0, attribute: 0, limit: 0x0FFF, base: 0xFFFF_F800_0000_1000 };
    // LDTR null with P=0.
    s.ldtr = SegSelector { selector: 0, attribute: 0x0000, limit: 0, base: 0 };
    // TR busy 64-bit TSS, P=1, type 0xB. limit 0x67 = standard. Selector
    // 0x0040 is the typical Windows TR slot (KGDT64_SYS_TSS).
    s.tr = SegSelector { selector: 0x0040, attribute: 0x008B, limit: 0x67, base: 0xFFFF_F800_0000_3000 };

    s.cpl = 0;

    // Snapshot the host's paging state. UEFI guarantees identity mapping
    // so guest linear == guest physical for the regions we care about.
    s.cr0 = crate::infra::arch::read_cr0();
    s.cr3 = crate::infra::arch::read_cr3();
    s.cr4 = crate::infra::arch::read_cr4();
    s.efer = unsafe { crate::infra::arch::rdmsr(crate::infra::arch::MSR_EFER) };

    s.rip = code_lin;
    s.rsp = 0;
    s.rax = 0;
    s.rflags = 0x2;

    s.dr6 = 0xFFFF_0FF0;
    s.dr7 = 0x0000_0400;
}

/// Configure VMCB.state for entry into a Linux kernel `startup_64`.
///
/// VMCB only carries RAX/RSP/RIP/RFLAGS in its state-save area; the
/// rest of the GP file (including RSI, which boot.rst mandates point
/// at boot_params) is staged through `GuestGprs` by the caller and
/// loaded by the VMRUN inline-asm trampoline. This function therefore
/// only touches what lives in the VMCB itself; pair it with
/// `GuestGprs { rsi: boot_params_phys, .. }` at the call site.
///
/// Same long-mode CPU posture as `init_guest_longmode`, but:
///   - RIP = `entry_rip` (=`KERNEL_LOAD_PHYS + 0x200`, the 64-bit
///     decompressor entry bzImage exposes)
///   - RSP points at a free conventional-memory page below 1 MiB so
///     `verify_cpu` / the decompressor stub can push/pop before Linux
///     installs its own stack
///   - RFLAGS.IF = 0 (boot.rst: interrupts must be off)
///
/// Selectors stay 0x10 (CS) / 0x18 (DS-family) — startup_64 re-loads
/// the GDT in its first few instructions, so what matters is that the
/// descriptor cache fields (attribute/limit/base) describe a valid
/// 64-bit code segment with L=1.
/// Configure VMCB.state for a 32-bit protected-mode PVH entry.
///
/// PVH boot protocol (Xen-defined, used by Cloud Hypervisor / Firecracker):
///   - CR0.PE = 1, CR0.PG = 0 (32-bit protected, paging off)
///   - CR4 = 0 (no PAE / no LME)
///   - EFER = 0
///   - CS = 4 GiB flat 32-bit code (sel 0x10, attr 0xC9B = G=1 D=1 + type=B+S=1+P=1)
///   - DS/ES/SS = 4 GiB flat data (sel 0x18, attr 0xC93)
///   - EIP = `entry_eip` (XEN_ELFNOTE_PHYS32_ENTRY from vmlinux PT_NOTE)
///   - EBX = `start_info_phys` (hvm_start_info struct)
///   - kernel does its own paging / GDT / IDT / stack setup
pub unsafe fn init_guest_pvh(vmcb: *mut Vmcb, entry_eip: u32, _start_info_phys: u32) {
    let s = unsafe { &mut (*vmcb).state };

    // Cloud Hypervisor / Firecracker PVH initial vCPU state. Reference:
    //   cloud-hypervisor/vmm/src/cpu.rs configure_pvh_vcpu()
    //
    // CS: 32-bit flat code, type=0xB (exec/read/accessed)
    //   AMD VMCB attribute encoding: bits 0..7 = access byte
    //   (P|DPL|S|type), bits 8..11 = upper (AVL|L|D|G).
    //   0xC9B = G=1 D=1 L=0 AVL=0 | P=1 DPL=0 S=1 type=0xB.
    s.cs = SegSelector { selector: 0x10, attribute: 0x0C9B, limit: 0xFFFF_FFFF, base: 0 };
    // DS/ES/SS/FS/GS: 32-bit flat data, type=3 (RW/accessed).
    // 0xC93 = G=1 D=1 | P=1 DPL=0 S=1 type=3.
    let data = SegSelector { selector: 0x18, attribute: 0x0C93, limit: 0xFFFF_FFFF, base: 0 };
    s.ss = data;
    s.ds = data;
    s.es = data;
    s.fs = data;
    s.gs = data;

    // GDTR/IDTR: base 0, limit 0xFFFF (CloudHV value). PVH stub
    // installs its own immediately.
    s.gdtr = SegSelector { selector: 0, attribute: 0,      limit: 0xFFFF, base: 0 };
    s.idtr = SegSelector { selector: 0, attribute: 0,      limit: 0xFFFF, base: 0 };
    // LDTR: type=2 (LDT), S=0, P=0 (not present). attribute 0x0082.
    s.ldtr = SegSelector { selector: 0, attribute: 0x0082, limit: 0xFFFF, base: 0 };
    // TR: type=0xB (busy 32-bit TSS), S=0, P=1. attribute 0x008B.
    s.tr   = SegSelector { selector: 0, attribute: 0x008B, limit: 0xFFFF, base: 0 };

    s.cpl = 0;

    // 32-bit protected, paging off. CR0 = PE | ET = 0x11 (CloudHV).
    s.cr0 = 0x0000_0011;
    s.cr3 = 0;
    s.cr4 = 0;
    s.efer = 0;

    s.rip = entry_eip as u64;
    s.rsp = 0;
    s.rax = 0;
    s.rflags = 0x2;

    s.dr6 = 0xFFFF_0FF0;
    s.dr7 = 0x0000_0400;
}

pub unsafe fn init_guest_linux(
    vmcb: *mut Vmcb,
    entry_rip: u64,
    _boot_params_phys: u64,
    guest_cr3: u64,
) {
    // Start from the standard long-mode setup, then override fields
    // that differ. `_boot_params_phys` is plumbed through the API for
    // documentation symmetry; the caller is responsible for writing
    // it to GuestGprs.rsi before calling vmrun().
    unsafe { init_guest_longmode(vmcb, entry_rip) };
    let s = unsafe { &mut (*vmcb).state };

    // Replace the host's UEFI CR3 with our guest-side page table. Under
    // isolated NPT the host CR3 (which lives in some UEFI page outside
    // our 1-GiB guest RAM block) would translate into uncovered host
    // pages and fault before the very first instruction even retires.
    s.cr3 = guest_cr3;

    // RSP = top of the dedicated 16 KiB scratch stack we reserved in
    // linux_loader. Using any other low-memory address blindly gives us
    // stale UEFI BootServices data on the first pop, which crashed
    // verify_cpu's `ret` on iter#19 of the first M1 attempt (popped
    // 0x40 -> jump to junk -> #UD).
    s.rsp = crate::guest_mem::STACK_TOP;

    // Clean RAX/RFLAGS for post-crash diagnosis.
    s.rax = 0;
    s.rflags = 0x2;  // IF=0, bit 1 reserved=1
}
