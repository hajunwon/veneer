//! TPM crypto primitives — thin wrappers over vetted RustCrypto no_std
//! crates (rsa / p256), seeded from the CPU `RDRAND` instruction.

#![allow(dead_code)]

use rand_core::{CryptoRng, RngCore};

/// Hardware RNG: the `RDRAND` instruction with the AMD-recommended retry.
pub struct Rdrand;

fn rdrand64() -> u64 {
    for _ in 0..64 {
        let val: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {c}",
                v = out(reg) val,
                c = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        if ok != 0 {
            return val;
        }
    }
    0
}

impl RngCore for Rdrand {
    fn next_u32(&mut self) -> u32 {
        rdrand64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        rdrand64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let mut i = 0;
        while i < dst.len() {
            let v = rdrand64().to_le_bytes();
            let n = core::cmp::min(8, dst.len() - i);
            dst[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

impl CryptoRng for Rdrand {}

/// Compile/link smoke: forces the heavy RSA-2048 keygen and P-256 ECDSA
/// code paths to monomorphize in the no_std UEFI target. Never called.
pub fn _smoke() -> bool {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rsa::RsaPrivateKey;
    let mut rng = Rdrand;
    let rsa_ok = RsaPrivateKey::new(&mut rng, 2048).is_ok();
    let sk = SigningKey::random(&mut rng);
    let _sig: Signature = sk.sign(b"smoke");
    rsa_ok
}
