//! Interactive boot-time profile menu (Style B — modern CLI).
//!
//! Two distinct screens:
//!   - **No-cache screen** — first boot, NVRAM is empty. User picks a
//!     quick policy or jumps to advanced. Timeout default = config.policy.default.
//!   - **Cached screen** — subsequent boots, NVRAM holds a profile.
//!     User can continue, regenerate, switch policy, jump to advanced,
//!     or wipe cache. Timeout default = continue cached.
//!
//! Input model: 1-line key-press polling with a countdown that updates
//! the status bar every 100 ms. Pressing nothing leaves the default
//! selection in place when the timer expires — safe for unattended /
//! remote boots.
//!
//! All UI goes through the UEFI text console (ConOut), so the menu is
//! visible on the firmware screen and in serial-redirected consoles.
//! Color highlight uses the standard 16-color VGA palette; falling back
//! gracefully if a firmware ignores `set_color`.

use uefi::boot;
use uefi::proto::console::text::{Color, Key, ScanCode};
use uefi::system::{with_stdin, with_stdout};
use uefi::print;

use veneer_vmm::hardware::identity::active;
use veneer_vmm::infra::config::{Config, QuickPolicy};
use veneer_vmm::hardware::identity::profile::Profile;

// ───── public API ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum MenuChoice {
    /// Use whatever profile is currently in the active slot (cached).
    UseActive,
    /// Drop the cached profile, generate a fresh one from this policy.
    GenerateFresh(QuickPolicy),
    /// Switch active profile to a different policy (regenerate IDs too).
    SwitchPolicy(QuickPolicy),
    /// Enter the advanced-settings sub-menu (Config editor).
    Advanced,
    /// Wipe the NVRAM profile, then proceed with the freshly-generated
    /// one from config.policy.default.
    WipeAndDefault,
    /// Reserved for future TOML load (batch 1c). For now == UseActive.
    LoadToml,
}

// ───── screen layout constants ──────────────────────────────────────────

const COL_INDENT: usize = 2;
const ROW_BANNER: usize = 1;
const ROW_SEPARATOR: usize = 2;
const ROW_BODY_START: usize = 4;
const COUNTDOWN_BAR_WIDTH: usize = 12;

// ───── low-level helpers ────────────────────────────────────────────────

fn clear_and_reset() {
    let _ = with_stdout(|s| {
        let _ = s.set_color(Color::White, Color::Black);
        let _ = s.clear();
    });
}

fn at(col: usize, row: usize) {
    let _ = with_stdout(|s| s.set_cursor_position(col, row));
}

fn color(fg: Color, bg: Color) {
    let _ = with_stdout(|s| s.set_color(fg, bg));
}

fn reset_color() {
    color(Color::White, Color::Black);
}

fn try_read_key() -> Option<Key> {
    with_stdin(|stdin| stdin.read_key().ok().flatten())
}

/// Poll the keyboard with a countdown. `on_tick` is called every ~100 ms
/// with the seconds-remaining so the caller can update the status bar.
/// Returns `Some(key)` on a keypress, `None` on timeout.
fn poll_with_countdown<F: FnMut(u32)>(timeout_secs: u32, mut on_tick: F) -> Option<Key> {
    let total_ms = timeout_secs * 1000;
    let tick_ms = 100u32;
    let mut elapsed_ms: u32 = 0;
    on_tick(timeout_secs);
    loop {
        if let Some(k) = try_read_key() {
            return Some(k);
        }
        if elapsed_ms >= total_ms {
            // Final tick at 0 so the visible state ends on "0s" and the
            // bar fills completely before the caller transitions out.
            on_tick(0);
            return None;
        }
        boot::stall((tick_ms as usize) * 1000);
        elapsed_ms += tick_ms;
        let remaining_ms = total_ms.saturating_sub(elapsed_ms);
        let remaining_s = (remaining_ms + 999) / 1000;
        on_tick(remaining_s);
    }
}

// ───── banner + status helpers ──────────────────────────────────────────

fn draw_banner(subtitle: &str) {
    at(0, ROW_BANNER);
    color(Color::LightCyan, Color::Black);
    print!("  veneer · ");
    color(Color::White, Color::Black);
    print!("{}", subtitle);
    at(0, ROW_SEPARATOR);
    color(Color::DarkGray, Color::Black);
    print!("  ");
    for _ in 0..60 {
        print!("─");
    }
    reset_color();
}

fn draw_keymap(row: usize, hint: &str) {
    at(0, row);
    color(Color::DarkGray, Color::Black);
    print!("  {}", hint);
    reset_color();
}

fn draw_countdown(row: usize, remaining_s: u32, total_s: u32, label: &str) {
    at(0, row);
    // Clear the line first (write spaces over previous content).
    print!("                                                                              ");
    at(0, row);
    color(Color::DarkGray, Color::Black);
    print!("  ");
    color(Color::Yellow, Color::Black);
    print!("{} in {}s ", label, remaining_s);
    // Progress bar — filled cells proportional to elapsed.
    let filled = if total_s == 0 {
        0
    } else {
        (COUNTDOWN_BAR_WIDTH * (total_s.saturating_sub(remaining_s)) as usize) / total_s as usize
    };
    color(Color::LightGreen, Color::Black);
    for _ in 0..filled {
        print!("█");
    }
    color(Color::DarkGray, Color::Black);
    for _ in filled..COUNTDOWN_BAR_WIDTH {
        print!("░");
    }
    reset_color();
}

fn draw_menu_row(row: usize, selected: bool, hotkey: &str, label: &str, desc: &str) {
    at(0, row);
    if selected {
        color(Color::Black, Color::Cyan);
        print!(" › ");
    } else {
        color(Color::White, Color::Black);
        print!("   ");
    }
    color(Color::LightCyan, if selected { Color::Cyan } else { Color::Black });
    print!("{:>2}  ", hotkey);
    color(if selected { Color::Black } else { Color::White },
          if selected { Color::Cyan } else { Color::Black });
    print!("{:<24}", label);
    color(if selected { Color::Black } else { Color::DarkGray },
          if selected { Color::Cyan } else { Color::Black });
    print!("  {}", desc);
    reset_color();
}

// ───── no-cache screen ─────────────────────────────────────────────────

const POLICY_ENTRIES: &[(QuickPolicy, &str, &str, char)] = &[
    (QuickPolicy::IntelLaptop, "Intel laptop",  "Lenovo ThinkPad T14 Gen 3",      '1'),
    (QuickPolicy::AmdDesktop,  "AMD desktop",   "ASUSTeK ROG STRIX X670E-E",      '2'),
    (QuickPolicy::RyzenNuc,    "Ryzen NUC",     "ASUS NUC w/ Ryzen 7 7840HS",     '3'),
];

const EXTRA_ENTRY_ADVANCED: usize = 3;
const EXTRA_ENTRY_TOML: usize = 4;
const N_ENTRIES: usize = 5;

fn default_index(default_policy: QuickPolicy) -> usize {
    match default_policy {
        QuickPolicy::IntelLaptop => 0,
        QuickPolicy::AmdDesktop => 1,
        QuickPolicy::RyzenNuc => 2,
    }
}

fn entry_choice(idx: usize) -> MenuChoice {
    match idx {
        0 => MenuChoice::GenerateFresh(QuickPolicy::IntelLaptop),
        1 => MenuChoice::GenerateFresh(QuickPolicy::AmdDesktop),
        2 => MenuChoice::GenerateFresh(QuickPolicy::RyzenNuc),
        EXTRA_ENTRY_ADVANCED => MenuChoice::Advanced,
        EXTRA_ENTRY_TOML => MenuChoice::LoadToml,
        _ => MenuChoice::GenerateFresh(QuickPolicy::AmdDesktop),
    }
}

fn draw_no_cache(selected: usize) {
    clear_and_reset();
    draw_banner("profile setup");
    at(0, ROW_BODY_START);
    color(Color::White, Color::Black);
    print!("  No cached profile found.");
    at(0, ROW_BODY_START + 1);
    color(Color::DarkGray, Color::Black);
    print!("  Pick a quick policy below. Identity fields are random per boot.");
    reset_color();

    let body_top = ROW_BODY_START + 3;
    for (i, e) in POLICY_ENTRIES.iter().enumerate() {
        let mut hot = [0u8; 2];
        hot[0] = e.3 as u8;
        let hot_s = core::str::from_utf8(&hot[..1]).unwrap_or("");
        draw_menu_row(body_top + i, selected == i, hot_s, e.1, e.2);
    }
    draw_menu_row(body_top + 3, selected == EXTRA_ENTRY_ADVANCED, "A",
        "Advanced settings", "Edit Config (intercept flags, timing, log...)");
    draw_menu_row(body_top + 4, selected == EXTRA_ENTRY_TOML, "T",
        "Load profile.toml", "Read \\EFI\\BOOT\\profile.toml (batch 1c)");

    draw_keymap(body_top + 7,
        "[1-3] policy   [A]dvanced   [T]oml   [↑↓] navigate   [Enter] confirm   [Esc] default");
}

/// Final transition screen — clear the menu and show what's happening
/// next. Called by callers right after a terminal menu choice so the
/// user sees a clear "moving on" cue instead of a frozen menu.
pub fn draw_transition(line1: &str, line2: &str) {
    clear_and_reset();
    draw_banner("starting hypervisor");
    at(0, ROW_BODY_START);
    color(Color::LightGreen, Color::Black);
    print!("  ✓ {}", line1);
    at(0, ROW_BODY_START + 2);
    color(Color::DarkGray, Color::Black);
    print!("  {}", line2);
    at(0, ROW_BODY_START + 4);
    color(Color::DarkGray, Color::Black);
    print!("  Detailed VMRUN trace on serial port (COM1).");
    reset_color();
    // Brief settle so a quick eye still catches the transition before
    // the firmware-text console scrolls / clears for the kernel handoff.
    boot::stall(800_000);
}

pub fn run_no_cache_menu(config: &Config) -> MenuChoice {
    let mut sel = default_index(config.policy.default);
    let total = config.menu.timeout_secs as u32;
    let body_top = ROW_BODY_START + 3;
    let countdown_row = body_top + 9;

    if !config.policy.prompt_on_miss {
        // Silent default — used by config.policy.prompt_on_miss=false.
        return MenuChoice::GenerateFresh(config.policy.default);
    }

    draw_no_cache(sel);

    loop {
        let result = poll_with_countdown(total, |r| {
            draw_countdown(countdown_row, r, total, "auto-select default");
        });
        match result {
            None => return MenuChoice::GenerateFresh(config.policy.default),
            Some(Key::Special(sc)) => match sc {
                ScanCode::UP => {
                    sel = if sel == 0 { N_ENTRIES - 1 } else { sel - 1 };
                    draw_no_cache(sel);
                }
                ScanCode::DOWN => {
                    sel = (sel + 1) % N_ENTRIES;
                    draw_no_cache(sel);
                }
                ScanCode::ESCAPE => {
                    return MenuChoice::GenerateFresh(config.policy.default);
                }
                _ => {}
            },
            Some(Key::Printable(c)) => {
                let ch: char = c.into();
                match ch {
                    '1' => return entry_choice(0),
                    '2' => return entry_choice(1),
                    '3' => return entry_choice(2),
                    'a' | 'A' => return MenuChoice::Advanced,
                    't' | 'T' => return MenuChoice::LoadToml,
                    '\r' | '\n' => return entry_choice(sel),
                    _ => {}
                }
            }
        }
    }
}

// ───── cached screen ───────────────────────────────────────────────────

const CACHED_ENTRY_CONTINUE: usize = 0;
const CACHED_ENTRY_REGEN: usize = 1;
const CACHED_ENTRY_SWITCH: usize = 2;
const CACHED_ENTRY_ADVANCED: usize = 3;
const CACHED_ENTRY_WIPE: usize = 4;
const N_CACHED_ENTRIES: usize = 5;

fn cached_choice(idx: usize, current_policy: QuickPolicy) -> MenuChoice {
    match idx {
        CACHED_ENTRY_CONTINUE => MenuChoice::UseActive,
        CACHED_ENTRY_REGEN => MenuChoice::GenerateFresh(current_policy),
        CACHED_ENTRY_SWITCH => MenuChoice::SwitchPolicy(next_policy(current_policy)),
        CACHED_ENTRY_ADVANCED => MenuChoice::Advanced,
        CACHED_ENTRY_WIPE => MenuChoice::WipeAndDefault,
        _ => MenuChoice::UseActive,
    }
}

fn next_policy(p: QuickPolicy) -> QuickPolicy {
    match p {
        QuickPolicy::IntelLaptop => QuickPolicy::AmdDesktop,
        QuickPolicy::AmdDesktop => QuickPolicy::RyzenNuc,
        QuickPolicy::RyzenNuc => QuickPolicy::IntelLaptop,
    }
}

fn policy_label(p: QuickPolicy) -> &'static str {
    match p {
        QuickPolicy::IntelLaptop => "intel_laptop",
        QuickPolicy::AmdDesktop => "amd_desktop",
        QuickPolicy::RyzenNuc => "ryzen_nuc",
    }
}

fn draw_cached(profile: &Profile, current_policy: QuickPolicy, selected: usize) {
    clear_and_reset();
    draw_banner("profile setup");

    // Snapshot the packed-struct fields via read_unaligned to dodge
    // misaligned-reference UB.
    let name = unsafe { core::ptr::addr_of!(profile.name).read_unaligned() };
    let cpu = unsafe { core::ptr::addr_of!(profile.hardware.cpu).read_unaligned() };
    let smb = unsafe { core::ptr::addr_of!(profile.hardware.system).read_unaligned() };
    let net = unsafe { core::ptr::addr_of!(profile.hardware.network).read_unaligned() };
    let disk = unsafe { core::ptr::addr_of!(profile.hardware.storage).read_unaligned() };

    at(0, ROW_BODY_START);
    color(Color::White, Color::Black);
    print!("  Active profile: ");
    color(Color::LightGreen, Color::Black);
    print!("{}", name.as_str());
    color(Color::DarkGray, Color::Black);
    print!("  (cached from NVRAM)");
    reset_color();

    let info_top = ROW_BODY_START + 2;
    let pairs: &[(&str, &str)] = &[
        ("CPU",     cpu.spec.brand.as_str()),
        ("Vendor",  cpu.spec.vendor.as_str()),
        ("Vendor",  smb.spec.manufacturer.as_str()),
        ("Product", smb.spec.product.as_str()),
        ("Serial",  smb.instance.serial.as_str()),
        ("UUID",    smb.instance.uuid.as_str()),
        ("MAC",     net.instance.mac.as_str()),
        ("Disk",    disk.spec.model.as_str()),
    ];
    for (i, (k, v)) in pairs.iter().enumerate() {
        at(0, info_top + i);
        color(Color::DarkGray, Color::Black);
        print!("    {:<8} ", k);
        color(Color::White, Color::Black);
        print!("{}", v);
    }
    at(0, info_top + 8);
    color(Color::DarkGray, Color::Black);
    print!("    {:<8} ", "Disk SN");
    color(Color::White, Color::Black);
    print!("{}", disk.instance.serial.as_str());
    reset_color();

    let menu_top = info_top + 11;
    let next = policy_label(next_policy(current_policy));
    let entries: &[(&str, &str, &str)] = &[
        ("↵", "Continue with cached profile",       "no change (default)"),
        ("R", "Regenerate same policy",             "new random IDs, same template"),
        ("S", "Switch policy",                       next),
        ("A", "Advanced settings",                  "Config editor"),
        ("D", "Delete cache and start fresh",       "use config.policy.default next"),
    ];
    for (i, e) in entries.iter().enumerate() {
        draw_menu_row(menu_top + i, selected == i, e.0, e.1, e.2);
    }
    draw_keymap(menu_top + 6,
        "[↑↓] navigate   [Enter] confirm   [R/S/A/D] direct   [Esc] continue");
}

fn detect_policy(profile: &Profile) -> QuickPolicy {
    let name = unsafe { core::ptr::addr_of!(profile.name).read_unaligned() };
    match name.as_str() {
        "intel_laptop" => QuickPolicy::IntelLaptop,
        "ryzen_nuc" => QuickPolicy::RyzenNuc,
        _ => QuickPolicy::AmdDesktop,
    }
}

pub fn run_cached_menu(profile: &Profile, config: &Config) -> MenuChoice {
    let mut sel = CACHED_ENTRY_CONTINUE;
    let current_policy = detect_policy(profile);
    let total = config.menu.timeout_secs as u32;
    let countdown_row = 23;

    if config.menu.timeout_secs == 0 && !config.menu.force_show {
        return MenuChoice::UseActive;
    }

    draw_cached(profile, current_policy, sel);

    loop {
        let result = poll_with_countdown(total, |r| {
            draw_countdown(countdown_row, r, total, "continuing");
        });
        match result {
            None => return MenuChoice::UseActive,
            Some(Key::Special(sc)) => match sc {
                ScanCode::UP => {
                    sel = if sel == 0 { N_CACHED_ENTRIES - 1 } else { sel - 1 };
                    draw_cached(profile, current_policy, sel);
                }
                ScanCode::DOWN => {
                    sel = (sel + 1) % N_CACHED_ENTRIES;
                    draw_cached(profile, current_policy, sel);
                }
                ScanCode::ESCAPE => return MenuChoice::UseActive,
                _ => {}
            },
            Some(Key::Printable(c)) => {
                let ch: char = c.into();
                match ch {
                    'r' | 'R' => return cached_choice(CACHED_ENTRY_REGEN, current_policy),
                    's' | 'S' => return cached_choice(CACHED_ENTRY_SWITCH, current_policy),
                    'a' | 'A' => return MenuChoice::Advanced,
                    'd' | 'D' => return cached_choice(CACHED_ENTRY_WIPE, current_policy),
                    '\r' | '\n' => return cached_choice(sel, current_policy),
                    _ => {}
                }
            }
        }
    }
}

// ───── reach-into-active wrapper ────────────────────────────────────────

/// Convenience helper: decide which screen to show based on whether the
/// active slot already holds a profile.
pub fn run(config: &Config) -> MenuChoice {
    match active::PROFILE.get() {
        Some(p) => run_cached_menu(p, config),
        None => run_no_cache_menu(config),
    }
}

// ───── advanced sub-screen ──────────────────────────────────────────────

use veneer_vmm::infra::config::{LogLevel, VmwareBackdoorPolicy};

/// Each row in the advanced editor — a navigable + cyclable Config slot.
#[derive(Clone, Copy)]
enum AdvField {
    MenuForceShow,
    PolicyPromptOnMiss,
    PolicyDefault,
    LogSerial,
    LogConsole,
    InterceptLapic,
    InterceptVmwareBackdoor,
    InterceptApProbe,
    InterceptBspSelfTest,
    InterceptMultiVcpuVmrun,
    InterceptRdrandIntercept,
}

const ADV_FIELDS: &[AdvField] = &[
    AdvField::MenuForceShow,
    AdvField::PolicyPromptOnMiss,
    AdvField::PolicyDefault,
    AdvField::LogSerial,
    AdvField::LogConsole,
    AdvField::InterceptLapic,
    AdvField::InterceptVmwareBackdoor,
    AdvField::InterceptApProbe,
    AdvField::InterceptBspSelfTest,
    AdvField::InterceptMultiVcpuVmrun,
    AdvField::InterceptRdrandIntercept,
];

fn field_label(f: AdvField) -> (&'static str, &'static str) {
    match f {
        AdvField::MenuForceShow              => ("menu.force_show",        "show menu even on NVRAM hit"),
        AdvField::PolicyPromptOnMiss         => ("policy.prompt_on_miss",  "show menu on cache miss"),
        AdvField::PolicyDefault              => ("policy.default",         "policy used on auto-default"),
        AdvField::LogSerial                  => ("log.serial",             "serial log level"),
        AdvField::LogConsole                 => ("log.console",            "UEFI console log level"),
        AdvField::InterceptLapic             => ("intercept.lapic_emulation",  "trap LAPIC MMIO"),
        AdvField::InterceptVmwareBackdoor    => ("intercept.vmware_backdoor", "VMware port 0x5658 policy"),
        AdvField::InterceptApProbe           => ("intercept.ap_probe",      "run AP fingerprint probe"),
        AdvField::InterceptBspSelfTest       => ("intercept.bsp_self_test", "BSP runs AP VMCB pre-check"),
        AdvField::InterceptMultiVcpuVmrun    => ("intercept.multi_vcpu_vmrun", "dispatch VMRUN to APs"),
        AdvField::InterceptRdrandIntercept   => ("intercept.rdrand_intercept", "deterministic RDRAND"),
    }
}

fn field_value_str(f: AdvField, c: &Config) -> &'static str {
    // Use a small static table for enum/bool stringification. All
    // packed-struct reads via read_unaligned.
    unsafe {
        match f {
            AdvField::MenuForceShow => bool_str(core::ptr::addr_of!(c.menu.force_show).read_unaligned()),
            AdvField::PolicyPromptOnMiss => bool_str(core::ptr::addr_of!(c.policy.prompt_on_miss).read_unaligned()),
            AdvField::PolicyDefault => match core::ptr::addr_of!(c.policy.default).read_unaligned() {
                QuickPolicy::IntelLaptop => "intel_laptop",
                QuickPolicy::AmdDesktop => "amd_desktop",
                QuickPolicy::RyzenNuc => "ryzen_nuc",
            },
            AdvField::LogSerial => log_str(core::ptr::addr_of!(c.log.serial).read_unaligned()),
            AdvField::LogConsole => log_str(core::ptr::addr_of!(c.log.console).read_unaligned()),
            AdvField::InterceptLapic => bool_str(core::ptr::addr_of!(c.intercept.lapic_emulation).read_unaligned()),
            AdvField::InterceptVmwareBackdoor => match core::ptr::addr_of!(c.intercept.vmware_backdoor).read_unaligned() {
                VmwareBackdoorPolicy::Block => "block",
                VmwareBackdoorPolicy::Passthrough => "passthrough",
            },
            AdvField::InterceptApProbe => bool_str(core::ptr::addr_of!(c.intercept.ap_probe).read_unaligned()),
            AdvField::InterceptBspSelfTest => bool_str(core::ptr::addr_of!(c.intercept.bsp_self_test).read_unaligned()),
            AdvField::InterceptMultiVcpuVmrun => bool_str(core::ptr::addr_of!(c.intercept.multi_vcpu_vmrun).read_unaligned()),
            AdvField::InterceptRdrandIntercept => bool_str(core::ptr::addr_of!(c.intercept.rdrand_intercept).read_unaligned()),
        }
    }
}

fn bool_str(b: bool) -> &'static str { if b { "true" } else { "false" } }
fn log_str(l: LogLevel) -> &'static str {
    match l {
        LogLevel::None => "none",
        LogLevel::Minimal => "minimal",
        LogLevel::Verbose => "verbose",
    }
}

fn cycle_field(f: AdvField, c: &mut Config) {
    let c_ptr = c as *mut Config;
    unsafe {
        match f {
            AdvField::MenuForceShow => {
                let p = core::ptr::addr_of_mut!((*c_ptr).menu.force_show);
                p.write_unaligned(!p.read_unaligned());
            }
            AdvField::PolicyPromptOnMiss => {
                let p = core::ptr::addr_of_mut!((*c_ptr).policy.prompt_on_miss);
                p.write_unaligned(!p.read_unaligned());
            }
            AdvField::PolicyDefault => {
                let p = core::ptr::addr_of_mut!((*c_ptr).policy.default);
                let next = match p.read_unaligned() {
                    QuickPolicy::IntelLaptop => QuickPolicy::AmdDesktop,
                    QuickPolicy::AmdDesktop => QuickPolicy::RyzenNuc,
                    QuickPolicy::RyzenNuc => QuickPolicy::IntelLaptop,
                };
                p.write_unaligned(next);
            }
            AdvField::LogSerial => {
                let p = core::ptr::addr_of_mut!((*c_ptr).log.serial);
                p.write_unaligned(cycle_log(p.read_unaligned()));
            }
            AdvField::LogConsole => {
                let p = core::ptr::addr_of_mut!((*c_ptr).log.console);
                p.write_unaligned(cycle_log(p.read_unaligned()));
            }
            AdvField::InterceptLapic => toggle_bool(core::ptr::addr_of_mut!((*c_ptr).intercept.lapic_emulation)),
            AdvField::InterceptVmwareBackdoor => {
                let p = core::ptr::addr_of_mut!((*c_ptr).intercept.vmware_backdoor);
                let next = match p.read_unaligned() {
                    VmwareBackdoorPolicy::Block => VmwareBackdoorPolicy::Passthrough,
                    VmwareBackdoorPolicy::Passthrough => VmwareBackdoorPolicy::Block,
                };
                p.write_unaligned(next);
            }
            AdvField::InterceptApProbe => toggle_bool(core::ptr::addr_of_mut!((*c_ptr).intercept.ap_probe)),
            AdvField::InterceptBspSelfTest => toggle_bool(core::ptr::addr_of_mut!((*c_ptr).intercept.bsp_self_test)),
            AdvField::InterceptMultiVcpuVmrun => toggle_bool(core::ptr::addr_of_mut!((*c_ptr).intercept.multi_vcpu_vmrun)),
            AdvField::InterceptRdrandIntercept => toggle_bool(core::ptr::addr_of_mut!((*c_ptr).intercept.rdrand_intercept)),
        }
    }
}

unsafe fn toggle_bool(p: *mut bool) {
    unsafe { p.write_unaligned(!p.read_unaligned()); }
}

fn cycle_log(l: LogLevel) -> LogLevel {
    match l {
        LogLevel::None => LogLevel::Minimal,
        LogLevel::Minimal => LogLevel::Verbose,
        LogLevel::Verbose => LogLevel::None,
    }
}

fn draw_advanced_screen(config: &Config, selected: usize, dirty: bool) {
    clear_and_reset();
    draw_banner(if dirty { "advanced settings  [modified]" } else { "advanced settings" });
    at(0, ROW_BODY_START);
    color(Color::DarkGray, Color::Black);
    print!("  Toggle a row with Enter/Space. S saves to NVRAM. X discards.");

    let body_top = ROW_BODY_START + 2;
    for (i, &f) in ADV_FIELDS.iter().enumerate() {
        let row = body_top + i;
        let (label, desc) = field_label(f);
        let value = field_value_str(f, config);
        at(0, row);
        if i == selected {
            color(Color::Black, Color::Cyan);
            print!(" › ");
        } else {
            color(Color::White, Color::Black);
            print!("   ");
        }
        color(if i == selected { Color::Black } else { Color::White },
              if i == selected { Color::Cyan } else { Color::Black });
        print!("{:<32}", label);
        color(if i == selected { Color::Black } else { Color::LightCyan },
              if i == selected { Color::Cyan } else { Color::Black });
        print!("  {:<12}", value);
        color(if i == selected { Color::Black } else { Color::DarkGray },
              if i == selected { Color::Cyan } else { Color::Black });
        print!("  {}", desc);
        reset_color();
    }
    draw_keymap(body_top + ADV_FIELDS.len() + 1,
        "[↑↓] navigate   [Enter/Space] toggle   [S]ave+exit   [X] discard   [R]eset DEFAULT");
}

pub fn run_advanced(config: &mut Config) {
    let mut selected = 0usize;
    let mut dirty = false;
    let original = *config;

    draw_advanced_screen(config, selected, dirty);
    loop {
        // No countdown — explicit Save/Discard required. Poll every
        // 50 ms for keystrokes.
        let key = loop {
            if let Some(k) = try_read_key() {
                break k;
            }
            boot::stall(50_000);
        };
        match key {
            Key::Special(sc) => match sc {
                ScanCode::UP => {
                    selected = if selected == 0 { ADV_FIELDS.len() - 1 } else { selected - 1 };
                }
                ScanCode::DOWN => {
                    selected = (selected + 1) % ADV_FIELDS.len();
                }
                ScanCode::ESCAPE => {
                    // Same as Discard.
                    *config = original;
                    return;
                }
                _ => continue,
            },
            Key::Printable(c) => {
                let ch: char = c.into();
                match ch {
                    '\r' | '\n' | ' ' => {
                        cycle_field(ADV_FIELDS[selected], config);
                        dirty = true;
                    }
                    's' | 'S' => {
                        // Persist to NVRAM and return.
                        match crate::host::nvram_io::save_config(config) {
                            Ok(()) => sprintln!("[adv ] config saved to NVRAM"),
                            Err(e) => sprintln!("[adv ] config save failed: {:?}", e),
                        }
                        veneer_vmm::hardware::identity::active::CONFIG.set(*config);
                        return;
                    }
                    'x' | 'X' => {
                        *config = original;
                        return;
                    }
                    'r' | 'R' => {
                        *config = veneer_vmm::infra::config::DEFAULT;
                        dirty = true;
                    }
                    _ => continue,
                }
            }
        }
        draw_advanced_screen(config, selected, dirty);
    }
}

#[allow(dead_code)]
const _COMPILE_TIME_CHECK_ENTRIES: () = {
    assert!(POLICY_ENTRIES.len() == 3);
};
