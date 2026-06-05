//! Minimal x86_64 MOV-family decoder for the NPF post-fault path.
//!
//! AMD's decode-assist fills `vmcb.control.guest_inst_bytes` with up to
//! 15 bytes of the faulting instruction stream, but `guest_inst_len` is
//! the count of bytes *fetched* (often the cache-line tail), not the
//! actual instruction length. To advance RIP and emulate the access we
//! decode the instruction ourselves and recover:
//!
//!   - **length**       — bytes to add to RIP
//!   - **register**      — 0..15 (REX.R combined with ModR/M.reg) for the
//!                         register operand (loads/stores via a register)
//!   - **mem_width**     — width of the memory access (1/2/4/8 bytes), i.e.
//!                         how many bytes to read/write at the device
//!   - **reg_width**     — width of the destination register for loads
//!                         (movzx/movsx widen a narrow memory operand into a
//!                         wider register)
//!   - **direction**     — true = store-to-memory, false = load-from-memory
//!   - **signed**        — load sign-extends (movsx) rather than zero-extends
//!   - **imm**           — for immediate stores (C6/C7) the value comes from
//!                         the instruction, not from a register
//!
//! Scope (covers the encodings real MMIO drivers emit):
//!   88 / 89 / 8A / 8B    — MOV r/m,r and MOV r,r/m
//!   C6 / C7              — MOV r/m, imm8 / imm (store-immediate)
//!   0F B6 / 0F B7        — MOVZX r, r/m8 / r/m16
//!   0F BE / 0F BF        — MOVSX r, r/m8 / r/m16
//! VEX/EVEX, string ops, MOV reg,moffs (A0..A3) remain out of scope — for
//! those we return None and the caller aborts.
//!
//! References: AMD APM Vol 3, Intel SDM Vol 2 Appendix A.

/// One decoded MOV-family memory access.
#[derive(Debug, Clone, Copy)]
pub struct DecodedMov {
    pub len: u64,
    pub reg: u8,
    /// Bytes accessed at the memory (device) operand.
    pub mem_width: u8,
    /// Destination register width for loads (>= mem_width for movzx/movsx).
    pub reg_width: u8,
    pub is_write: bool,
    /// Load sign-extends instead of zero-extending (MOVSX).
    pub signed: bool,
    /// Immediate value to store (Some only for C6/C7); when present the
    /// caller writes this to memory instead of reading a register.
    pub imm: Option<u64>,
}

const REX_MIN: u8 = 0x40;
const REX_MAX: u8 = 0x4F;
const REX_W: u8 = 1 << 3;
const REX_R: u8 = 1 << 2;

const PFX_OP_SIZE: u8 = 0x66;
const PFX_ADDR_SIZE: u8 = 0x67;
const PFX_LOCK: u8 = 0xF0;
const PFX_REPNE: u8 = 0xF2;
const PFX_REP: u8 = 0xF3;
const PFX_SEG_ES: u8 = 0x26;
const PFX_SEG_CS: u8 = 0x2E;
const PFX_SEG_SS: u8 = 0x36;
const PFX_SEG_DS: u8 = 0x3E;
const PFX_SEG_FS: u8 = 0x64;
const PFX_SEG_GS: u8 = 0x65;

const MOV_RM8_R8: u8 = 0x88; // MOV r/m8,  r8   — store, byte
const MOV_RM_R: u8 = 0x89;   // MOV r/m,   r    — store
const MOV_R8_RM8: u8 = 0x8A; // MOV r8,    r/m8 — load, byte
const MOV_R_RM: u8 = 0x8B;   // MOV r,     r/m  — load
const MOV_RM8_IMM8: u8 = 0xC6; // MOV r/m8, imm8 — store-immediate, byte
const MOV_RM_IMM: u8 = 0xC7;   // MOV r/m,  imm  — store-immediate

const TWO_BYTE_ESCAPE: u8 = 0x0F;
const MOVZX_RM8: u8 = 0xB6;  // 0F B6 — MOVZX r, r/m8
const MOVZX_RM16: u8 = 0xB7; // 0F B7 — MOVZX r, r/m16
const MOVSX_RM8: u8 = 0xBE;  // 0F BE — MOVSX r, r/m8
const MOVSX_RM16: u8 = 0xBF; // 0F BF — MOVSX r, r/m16

/// Decode the memory-form MOV-family instruction at the head of `bytes`.
pub fn decode_mov(bytes: &[u8]) -> Option<DecodedMov> {
    let mut p: usize = 0;
    let mut has_op_size = false;
    let mut rex: u8 = 0;

    loop {
        match bytes.get(p).copied() {
            Some(PFX_OP_SIZE) => { has_op_size = true; p += 1; }
            Some(PFX_ADDR_SIZE)
            | Some(PFX_LOCK)
            | Some(PFX_REPNE)
            | Some(PFX_REP)
            | Some(PFX_SEG_ES)
            | Some(PFX_SEG_CS)
            | Some(PFX_SEG_SS)
            | Some(PFX_SEG_DS)
            | Some(PFX_SEG_FS)
            | Some(PFX_SEG_GS) => { p += 1; }
            _ => break,
        }
    }

    if let Some(&b) = bytes.get(p) {
        if (REX_MIN..=REX_MAX).contains(&b) {
            rex = b;
            p += 1;
        }
    }

    let opcode = *bytes.get(p)?;
    p += 1;

    // Default register width from REX.W / 0x66 (used by the plain MOVs and
    // as the destination width for MOVZX/MOVSX).
    let oper_width: u8 = if (rex & REX_W) != 0 {
        8
    } else if has_op_size {
        2
    } else {
        4
    };

    // Classify the opcode. `imm_size` is the number of immediate bytes that
    // follow the ModR/M (+SIB+disp); `kind` carries direction / widths.
    enum Kind {
        // Register operand MOV. (is_write, mem_width, reg_width)
        RegMov { is_write: bool, mem_width: u8, reg_width: u8, signed: bool },
        // Store-immediate. mem_width + imm_size are the same field set.
        ImmStore { mem_width: u8 },
    }

    let (kind, imm_size): (Kind, usize) = match opcode {
        MOV_RM8_R8 => (Kind::RegMov { is_write: true,  mem_width: 1, reg_width: 1, signed: false }, 0),
        MOV_RM_R   => (Kind::RegMov { is_write: true,  mem_width: oper_width, reg_width: oper_width, signed: false }, 0),
        MOV_R8_RM8 => (Kind::RegMov { is_write: false, mem_width: 1, reg_width: 1, signed: false }, 0),
        MOV_R_RM   => (Kind::RegMov { is_write: false, mem_width: oper_width, reg_width: oper_width, signed: false }, 0),
        // Store-immediate: imm8 for C6, imm16/32 (no imm64; sign-extended
        // imm32 for REX.W) for C7.
        MOV_RM8_IMM8 => (Kind::ImmStore { mem_width: 1 }, 1),
        MOV_RM_IMM => {
            let isz = if has_op_size { 2 } else { 4 }; // C7 imm is never 8
            (Kind::ImmStore { mem_width: oper_width }, isz)
        }
        TWO_BYTE_ESCAPE => {
            let op2 = *bytes.get(p)?;
            p += 1;
            match op2 {
                MOVZX_RM8  => (Kind::RegMov { is_write: false, mem_width: 1, reg_width: oper_width, signed: false }, 0),
                MOVZX_RM16 => (Kind::RegMov { is_write: false, mem_width: 2, reg_width: oper_width, signed: false }, 0),
                MOVSX_RM8  => (Kind::RegMov { is_write: false, mem_width: 1, reg_width: oper_width, signed: true  }, 0),
                MOVSX_RM16 => (Kind::RegMov { is_write: false, mem_width: 2, reg_width: oper_width, signed: true  }, 0),
                _ => return None,
            }
        }
        _ => return None,
    };

    let modrm = *bytes.get(p)?;
    p += 1;
    let mode = (modrm >> 6) & 0b11;
    let reg_field = (modrm >> 3) & 0b111;
    let rm = modrm & 0b111;

    // mode=11 is register-to-register — no memory operand, so the NPF
    // couldn't have come from this instruction. Bail.
    if mode == 0b11 {
        return None;
    }

    let rex_r = (rex & REX_R) >> 2;
    let reg = (rex_r << 3) | reg_field;

    // SIB byte present when rm == 100 and mode != 11.
    let mut disp_size: usize = 0;
    if rm == 0b100 {
        let sib = *bytes.get(p)?;
        p += 1;
        let sib_base = sib & 0b111;
        // Special case: mode=00, SIB.base=101 ⇒ disp32 with no base reg.
        if mode == 0b00 && sib_base == 0b101 {
            disp_size = 4;
        }
    }

    if disp_size == 0 {
        disp_size = match mode {
            0b00 => if rm == 0b101 { 4 } else { 0 },
            0b01 => 1,
            0b10 => 4,
            _ => return None,
        };
    }

    if bytes.len() < p + disp_size {
        return None;
    }
    p += disp_size;

    // Decode the trailing immediate for the store-immediate forms.
    let imm = match &kind {
        Kind::ImmStore { .. } => {
            if bytes.len() < p + imm_size {
                return None;
            }
            let mut v: u64 = 0;
            for i in 0..imm_size {
                v |= (bytes[p + i] as u64) << (8 * i);
            }
            // C7 with REX.W stores a sign-extended imm32 into a 64-bit slot;
            // sign-extend the imm32 so an 8-byte device store sees the right
            // value. C6 (imm8) and 16-bit forms don't widen here.
            if imm_size == 4 {
                v = (v as i32) as i64 as u64;
            }
            p += imm_size;
            Some(v)
        }
        Kind::RegMov { .. } => None,
    };

    let (is_write, mem_width, reg_width, signed) = match kind {
        Kind::RegMov { is_write, mem_width, reg_width, signed } => (is_write, mem_width, reg_width, signed),
        Kind::ImmStore { mem_width } => (true, mem_width, mem_width, false),
    };

    Some(DecodedMov {
        len: p as u64,
        reg,
        mem_width,
        reg_width,
        is_write,
        signed,
        imm,
    })
}
