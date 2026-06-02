//! CPU vendor detection via CPUID leaf 0.

use raw_cpuid::CpuId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    AuthenticAmd,
    GenuineIntel,
    Other,
}

impl Vendor {
    /// Vendor name as it appears in CPUID leaf 0 (EBX:EDX:ECX).
    pub fn as_str(&self) -> &'static str {
        match self {
            Vendor::AuthenticAmd => "AuthenticAMD",
            Vendor::GenuineIntel => "GenuineIntel",
            Vendor::Other        => "Other",
        }
    }
}

pub fn host_vendor() -> Vendor {
    let id = CpuId::new();
    match id.get_vendor_info().map(|v| v.as_str().to_string()) {
        Some(s) if s == "AuthenticAMD" => Vendor::AuthenticAmd,
        Some(s) if s == "GenuineIntel" => Vendor::GenuineIntel,
        _                              => Vendor::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_strs_match_cpuid_format() {
        // CPUID returns these 12-char ASCII strings literally; spelling matters
        // for the eventual cpu/vendor write-back inside the CPUID intercept.
        assert_eq!(Vendor::AuthenticAmd.as_str(), "AuthenticAMD");
        assert_eq!(Vendor::GenuineIntel.as_str(), "GenuineIntel");
        for v in [Vendor::AuthenticAmd, Vendor::GenuineIntel] {
            assert_eq!(v.as_str().len(), 12);
        }
    }
}
