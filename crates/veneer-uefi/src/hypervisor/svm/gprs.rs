//! Software-saved guest general-purpose registers.
//!
//! AMD SVM's VMCB only saves a tiny subset of registers automatically:
//!   - host  side (via VM_HSAVE_PA): RAX, RSP, RIP, RFLAGS, EFER, CR0/3/4,
//!                                   GDTR/IDTR, ES/CS/SS/DS selectors
//!   - guest side (via VMCB.state):  RAX, RSP, RIP, RFLAGS plus all
//!                                   segment registers, CR0/3/4, EFER, DRs
//!
//! Everything else — RBX, RCX, RDX, RSI, RDI, RBP, R8..R15 — must be
//! shuffled by the VMM software stub on every VMRUN/VMEXIT round-trip.
//! The asm in `vmrun.rs` loads these into hardware registers right before
//! the `vmrun` instruction and writes them back into this struct at the
//! VMEXIT site.
//!
//! Layout is `#[repr(C)]` so the asm can use simple `[base + offset]`
//! addressing modes. Offsets are baked into the asm constants below.

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GuestGprs {
    pub rbx: u64,    // 0
    pub rcx: u64,    // 8
    pub rdx: u64,    // 16
    pub rsi: u64,    // 24
    pub rdi: u64,    // 32
    pub rbp: u64,    // 40
    pub r8:  u64,    // 48
    pub r9:  u64,    // 56
    pub r10: u64,    // 64
    pub r11: u64,    // 72
    pub r12: u64,    // 80
    pub r13: u64,    // 88
    pub r14: u64,    // 96
    pub r15: u64,    // 104
}

// Compile-time sanity check: layout matches the offsets the asm uses.
const _: () = {
    let _ = [(); core::mem::size_of::<GuestGprs>() - 14 * 8];
};

impl GuestGprs {
    /// Write a 64-bit value into the GPR identified by the Intel/AMD GPR
    /// index encoding (bits 0..3 of CR/DR-intercept `exit_info_1`).
    /// `vmcb_state` is passed in for RAX/RSP which live in the VMCB
    /// state-save area, not in this struct.
    pub fn write_indexed(
        &mut self,
        state: &mut crate::hypervisor::svm::vmcb::VmcbStateSave,
        idx: u8,
        val: u64,
    ) {
        match idx {
            0 => state.rax = val,
            1 => self.rcx = val,
            2 => self.rdx = val,
            3 => self.rbx = val,
            4 => state.rsp = val,
            5 => self.rbp = val,
            6 => self.rsi = val,
            7 => self.rdi = val,
            8 => self.r8 = val,
            9 => self.r9 = val,
            10 => self.r10 = val,
            11 => self.r11 = val,
            12 => self.r12 = val,
            13 => self.r13 = val,
            14 => self.r14 = val,
            15 => self.r15 = val,
            _ => {}
        }
    }

    pub fn read_indexed(
        &self,
        state: &crate::hypervisor::svm::vmcb::VmcbStateSave,
        idx: u8,
    ) -> u64 {
        match idx {
            0 => state.rax,
            1 => self.rcx,
            2 => self.rdx,
            3 => self.rbx,
            4 => state.rsp,
            5 => self.rbp,
            6 => self.rsi,
            7 => self.rdi,
            8 => self.r8,
            9 => self.r9,
            10 => self.r10,
            11 => self.r11,
            12 => self.r12,
            13 => self.r13,
            14 => self.r14,
            15 => self.r15,
            _ => 0,
        }
    }

    /// Width-aware write, following x86_64 long-mode semantics:
    /// 64-bit writes clear nothing, 32-bit zero-extend to 64, and
    /// 16/8-bit overwrite only the low bytes (upper bits preserved).
    pub fn write_indexed_width(
        &mut self,
        state: &mut crate::hypervisor::svm::vmcb::VmcbStateSave,
        idx: u8,
        val: u64,
        width: u8,
    ) {
        let cur = self.read_indexed(state, idx);
        let new = match width {
            1 => (cur & !0xFFu64) | (val & 0xFF),
            2 => (cur & !0xFFFFu64) | (val & 0xFFFF),
            4 => val & 0xFFFF_FFFF,
            8 => val,
            _ => return,
        };
        self.write_indexed(state, idx, new);
    }
}
