//! Per-peripheral delivery mode: how a device reaches the guest.
//!
//! `Emulated`   — veneer presents a synthetic device; identity comes from
//!                this component's `spec`/`instance` and emitters render it.
//! `Passthrough`— the real host device is routed to the guest; identity is
//!                reflected from real hardware, with selected fields possibly
//!                overridden on interceptable surfaces. (mechanism not yet
//!                implemented; the tag reserves the shape so the model is final)
//! `Absent`     — the device is not presented to the guest at all.
//!
//! Stored as a `repr(transparent)` `u8` rather than a bare enum so that
//! loading an arbitrary NVRAM byte can never be UB (an out-of-range
//! discriminant is just an unknown mode, treated as Emulated).

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct DeliveryMode(u8);

impl DeliveryMode {
    pub const EMULATED: Self = Self(0);
    pub const PASSTHROUGH: Self = Self(1);
    pub const ABSENT: Self = Self(2);

    pub const fn raw(self) -> u8 {
        self.0
    }

    pub fn is_emulated(self) -> bool {
        // Unknown bytes fall back to emulated — the only implemented mode.
        self.0 != Self::PASSTHROUGH.0 && self.0 != Self::ABSENT.0
    }
    pub fn is_passthrough(self) -> bool {
        self.0 == Self::PASSTHROUGH.0
    }
    pub fn is_absent(self) -> bool {
        self.0 == Self::ABSENT.0
    }
}

impl Default for DeliveryMode {
    fn default() -> Self {
        Self::EMULATED
    }
}
