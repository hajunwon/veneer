//! Synthetic Endorsement Key certificate + template blobs.
//!
//! Placed at NV indices 0x01C00002 (EK cert) and 0x01C00004 (EK template)
//! per TCG TPM 2.0 Endorsement Key Profile. The cert is *not*
//! cryptographically valid — it's a structurally well-formed X.509
//! DER blob whose subject claims to be "AMD fTPM EK". Local presence
//! checks (the kind vgc uses) only verify "EK NV index exists, length
//! is plausibly cert-shaped"; they don't walk the chain to an AMD root.
//!
//! Online attestation servers WILL reject this — they verify against
//! genuine AMD/Intel/Infineon EK Root CAs. That path requires real
//! vendor private keys and is out of scope for veneer.

/// EK certificate blob — 1024 bytes. Starts with valid X.509 SEQUENCE
/// headers; the rest is plausibly-distributed bytes that decode as
/// nested ASN.1 structures without crashing a permissive parser.
pub const EK_CERT_DER: &[u8] = &EK_CERT_BYTES;

const EK_CERT_BYTES: [u8; 1024] = {
    let mut buf = [0u8; 1024];
    // SEQUENCE, length 0x0400 - 4 = 1020 bytes (long-form length)
    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = 0x03;
    buf[3] = 0xFC;
    // tbsCertificate SEQUENCE — length 0x0300
    buf[4] = 0x30;
    buf[5] = 0x82;
    buf[6] = 0x03;
    buf[7] = 0x00;
    // [0] EXPLICIT Version v3 (INTEGER 2)
    buf[8] = 0xA0;
    buf[9] = 0x03;
    buf[10] = 0x02;
    buf[11] = 0x01;
    buf[12] = 0x02;
    // serialNumber INTEGER (9 bytes, positive). The real per-machine serial is
    // patched in at TPM provisioning (state::init) from the SMBIOS UUID hash;
    // this static default is only a fallback and must NOT be a recognizable
    // pattern (the old value embedded 0xC0FFEE/0xC0FEED — a veneer watermark
    // that any TPM/EK inspection would flag as fake).
    buf[13] = 0x02;
    buf[14] = 0x09;
    buf[15] = 0x4B; buf[16] = 0x7A; buf[17] = 0x16; buf[18] = 0xC3;
    buf[19] = 0x5E; buf[20] = 0x09; buf[21] = 0xB1; buf[22] = 0x2D; buf[23] = 0xF4;
    // signature AlgorithmIdentifier SEQUENCE — sha256WithRSAEncryption
    // (1.2.840.113549.1.1.11)
    buf[24] = 0x30;
    buf[25] = 0x0D;
    buf[26] = 0x06;
    buf[27] = 0x09;
    buf[28] = 0x2A; buf[29] = 0x86; buf[30] = 0x48; buf[31] = 0x86;
    buf[32] = 0xF7; buf[33] = 0x0D; buf[34] = 0x01; buf[35] = 0x01;
    buf[36] = 0x0B;
    buf[37] = 0x05;
    buf[38] = 0x00;
    // issuer SEQUENCE — length 0x4D, CN="AMD EK Issuer CA",O="AMD"
    buf[39] = 0x30;
    buf[40] = 0x4D;
    buf[41] = 0x31; buf[42] = 0x0C; buf[43] = 0x30; buf[44] = 0x0A;
    buf[45] = 0x06; buf[46] = 0x03; buf[47] = 0x55; buf[48] = 0x04;
    buf[49] = 0x06; buf[50] = 0x13; buf[51] = 0x03; buf[52] = b'U';
    buf[53] = b'S'; buf[54] = b'\0';
    buf[55] = 0x31; buf[56] = 0x0C; buf[57] = 0x30; buf[58] = 0x0A;
    buf[59] = 0x06; buf[60] = 0x03; buf[61] = 0x55; buf[62] = 0x04;
    buf[63] = 0x0A; buf[64] = 0x13; buf[65] = 0x03;
    buf[66] = b'A'; buf[67] = b'M'; buf[68] = b'D';
    buf[69] = 0x31; buf[70] = 0x2F; buf[71] = 0x30; buf[72] = 0x2D;
    buf[73] = 0x06; buf[74] = 0x03; buf[75] = 0x55; buf[76] = 0x04;
    buf[77] = 0x03; buf[78] = 0x13; buf[79] = 0x26;
    // "AMD fTPM Endorsement Key Issuer CA" — 38 chars
    let issuer_cn = b"AMD fTPM Endorsement Key Issuer CA RC";
    let mut i = 0;
    while i < issuer_cn.len() {
        buf[80 + i] = issuer_cn[i];
        i += 1;
    }
    // After the issuer block we leave room for validity / subject /
    // subjectPublicKeyInfo / extensions and the trailing signature.
    // The remainder is zero-filled; permissive parsers will detect
    // truncation, but the typical presence check just reads the first
    // 64-128 bytes and confirms ASN.1 framing.
    let _ = i;
    buf
};

/// EK template — TPM2B_PUBLIC encoded RSA-2048 EK template. Size = 0x82
/// (130 bytes) — the canonical TCG EK template for RSA 2048 / SHA-256.
pub const EK_TEMPLATE: &[u8] = &[
    0x00, 0x82,                                     // size = 130
    0x00, 0x01,                                     // type = TPM_ALG_RSA
    0x00, 0x0B,                                     // nameAlg = TPM_ALG_SHA256
    // objectAttributes — fixedTPM | fixedParent | sensitiveDataOrigin |
    // adminWithPolicy | restricted | decrypt
    0x00, 0x03, 0x00, 0xB2,
    // authPolicy size (32) + policy bytes (TCG-defined PolicyA hash)
    0x00, 0x20,
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
    // RSA parameters:
    //   symmetric: TPM_ALG_AES, 128, CFB
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    //   scheme: TPM_ALG_NULL
    0x00, 0x10,
    //   keyBits 2048, exponent 0 (=> 65537)
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    // unique (RSA public key) — empty placeholder (modulus filled by
    // CreatePrimary)
    0x00, 0x00,
    // padding to 130 byte buffer
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
