# veneer — architecture

What veneer is, how it is structured today, and the architecture that is
planned but not yet built. Status markers: `[x]` built · `[~]` partial ·
`[ ]` planned. The plain to-do list lives in [TODO.md](TODO.md); this file is
the structural/design reference.

---

## 1. Goal

veneer is a minimal **Type-1 hypervisor** in Rust. It boots before the guest
OS, runs the guest (OVMF firmware → Windows / Linux), and presents a *fully
synthetic, host-independent PC identity* to it: CPU brand, SMBIOS, disk/NIC,
TPM, ACPI — all driven by a `Profile`, with no observable footprint from
inside.

It is also the research substrate for the anti-cheat work: because veneer sits
at L1 (below the guest OS), it can read, translate, and intercept guest memory
beneath in-guest defenses (PatchGuard, HVCI) to study `vgk` / `vgc` and feed
`fake_vgc`.

```
+--------------------------------------------------+
|  guest OS (L2)  — sees a synthetic "real PC"     |
+--------------------------------------------------+
|  veneer (L1) Type-1 hypervisor                   |
|  — device emulation + intercepts from a Profile  |
|  — VMI + stealth hooks for research              |
+--------------------------------------------------+
|  VMware Workstation (L0, nested) or bare-metal   |
+--------------------------------------------------+
|  host hardware                                   |
+--------------------------------------------------+
```

Design north star: **OS-agnostic, general-purpose fidelity.** No per-OS stubs;
where a classic-hypervisor technique has a gap vs real hardware, close the gap
with accurate device emulation rather than a shortcut.

---

## 2. Workspace structure

A Cargo workspace of three crates, split on the `no_std` / `std` axis.

```
veneer/
├── Cargo.toml                      # workspace
├── assets/                         # non-code inputs
│   ├── firmware/                   #   OVMF (guest UEFI firmware) + variants/
│   ├── profiles/                   #   intel_laptop.toml / amd_desktop.toml
│   ├── config/veneer.toml          #   veneer behavior config
│   └── shellx64.efi                #   UEFI shell (diagnostic boot target)
├── tools/                          # python/ps build + boot scripts
└── crates/
    ├── veneer-profile/   (no_std lib)   shared Profile schema + TOML parser
    ├── veneer-uefi/      (no_std bin)   the hypervisor (.efi)
    └── host/veneer-probe/(std bin)      host-side pre-flight tool
```

- **`veneer-profile`** — the single source of truth for the synthetic-PC
  schema (`#[repr(C, packed)]`, NVRAM-layout) + the schema-driven TOML parser.
  Used by both the hypervisor and the host tool, so they validate the exact
  same schema.
- **`veneer-uefi`** — the actual hypervisor, loaded by firmware as
  `\EFI\BOOT\BOOTX64.EFI`. Everything below lives here.
- **`veneer-probe`** — host-side utility (`inspect` / `plan` / `profile-check`).
  Runs on the real host before deploying; reads the real CPU via CPUID, picks
  the backend, validates profiles. Not a runtime layer.

Build:
```
cd crates/veneer-uefi && cargo build --release      # → target/.../veneer-uefi.efi
python tools/make_disk.py                            # from repo root, builds the ESP disk
cd crates/host/veneer-probe && cargo build           # → veneer.exe (inspect/plan/profile-check)
```

---

## 3. veneer-uefi module map

Domain folders (file = responsibility, folder = module boundary, DAG only).

```
crates/veneer-uefi/src/
├── main.rs            UEFI entry + boot orchestration (composition root)
│
│  Layers are grouped by architectural ROLE. Boundary rule per bucket below;
│  the dependency graph is a DAG: infra ← {hypervisor → hardware, guest} ←
│  {introspect, diag}. (Where a file goes: ask which one-line rule it matches.)
│
├── infra/             "shared low-level primitive used across layers"
│   ├── arch.rs        raw x86-64: cpuid/rdmsr/wrmsr/in/out/cr/hlt (HAL)
│   ├── clock/         monotonic virtual TSC, host_tick, tsc_freq
│   ├── config/        Config schema + TOML dispatch
│   └── serial.rs      COM1 log transport + sprint!/sprintln! macros
├── hypervisor/        "runs/traps the guest (the VMM core)"
│   ├── svm/           vmcb, vmrun, npt, msrpm, iopm, smp, vcpu_pool, gprs,
│   │                  + arm_exec_trap (NX hook primitive)
│   └── vmexit/        dispatch + handlers: decode, lengths, cpuid, msr, cr, dr,
│                      dt, exception, hlt, rdtsc, vmmcall, stealth, io, npf
├── hardware/          "virtual hardware/tables the guest perceives"
│   ├── devices/       irq/{lapic,ioapic,pic,pit,hpet,rtc,inject},
│   │                  bus/{pci,xhci,vga,nic}, storage/{ahci,nvme,backend,
│   │                  host_ahci}, tpm/*, (root) acpi_pm,kvmclock,fwcfg,i8042
│   ├── acpi/          RSDP/XSDT/FADT/MADT/HPET tables, acpi_fwcfg, aml
│   └── identity/      profile, profile_gen, smbios, nvram_io, uefi_vars, active
├── guest/             "loads/launches the guest, manages guest RAM"
│   └── boot/          chain_load, esp_io, guest_blob, guest_mem, linux_loader,
│                      menu, uefi_config
├── introspect/        "observes/rewrites guest state from L1 (research/spoof)"
│   ├── translate, mem VMI read/translate foundation
│   └── hook/          stealth exec-hook engine (built on the VMI foundation)
└── diag/              "developer diagnostics; removable without behavior change"
                       serial_kd (WinDbg KD bridge), validator, report
```

---

## 4. Boot / VMEXIT flow (SVM)

```
firmware loads veneer-uefi.efi
  └── probe CPU (AMD SVM) → enable EFER.SVME → alloc HSAVE
        └── build NPT (identity / translated) → install MMIO trap regions
              └── load Profile + Config (NVRAM → ESP TOML overlay)
                    └── set up VMCB (intercepts, guest CS:RIP, CR0/3/4, EFER)
                          └── chain-load guest: OVMF firmware → Windows / Linux
                                └── VMRUN loop:
                                      VMRUN ──► guest runs until a sensitive
                                                event → VMEXIT (HW saves to VMCB)
                                      ◄── dispatch on VMCB.exit_code:
                                            CPUID/MSR/CR/DR/IOIO/NPF/EXCP/…
                                            handler mutates VMCB.state, advances
                                            RIP (NRIPS or length table), returns
                                            Resume / Halt / Abort
```

Exit dispatch is `vmexit/mod.rs::dispatch`. RIP advance prefers hardware NRIPS,
falling back to a length table. A spin detector + virtual-clock floor keep
busy-wait delay loops converging despite VMware's host-TSC throttle.

- [x] SVM bring-up, NPT, VMCB, VMRUN loop, multi-vCPU pool
- [x] Intercepts: CPUID, MSR, CR/DR, IOIO, exceptions, RDTSC(native+filtered),
      VMMCALL, NPF, INVD/WBINVD/MONITOR/MWAIT/RDPMC/PUSHF-POPF (stealth)
- [x] Host preemption tick (LAPIC timer + INTR intercept) for periodic VMEXIT
- [ ] Intel VT-x / EPT backend (AMD SVM only today)

## 5. NPT design

Identity- or translated-map of guest physical → host physical, isolating guest
RAM from veneer's own UEFI memory. MMIO addresses are left not-present (or
exec-trapped) so accesses fault into NPF and route to a device emulator.
Page-table format = long-mode 4-level (PML4→PDPT→PD→PT), 1 GiB/2 MiB huge pages
split to 4 KiB on demand. `svm/npt.rs`.

**Writable-shadow MMIO (perf exception).** Trapping is the default, but a hot,
side-effect-light device can instead be backed by a writable host page
(`npt::map_backing_page`) so the guest's reads/writes hit RAM with no #VMEXIT;
veneer reconciles the emulated state lazily from the dispatcher. This is how the
HPET dodges its per-tick `HalpHpetArmTimer` NPF storm (§6) — decisive because
each NPF is ~155 µs under VMware nested SVM. Only safe where stale-by-one-tick
reads and a periodic write-back are acceptable (no read-to-clear / write-1-clear
hot registers); the LAPIC, with EOI/ICR side effects, stays trapped.

---

## 6. Device emulation (the synthetic PC)

veneer presents a coherent fake machine. Each device class is its own module.

- [x] **IRQ/timers**: LAPIC, IO-APIC, 8259 PIC, 8254 PIT, HPET, RTC/CMOS,
      interrupt injection. HPET uses a **writable-shadow MMIO page** (§5) +
      lazy `shadow_tick` reconcile to avoid the per-tick clock-arm NPF storm;
      it stays interrupt-capable so the HAL clock init doesn't bugcheck 0x5C.
- [x] **Bus/IO**: PCI config space (CF8/CFC + ECAM), xHCI, VGA, NIC (BAR trap)
- [x] **Storage**: NVMe + AHCI (MMIO BAR emulation, host-backed disk)
- [x] **Platform**: ACPI (RSDP/XSDT/FADT/MADT/HPET/MCFG), SMBIOS, fw_cfg,
      i8042 (PS/2 kbd), ACPI PM timer, kvmclock
- [~] **TPM 2.0** (CRB): presence + measured boot today; full crypto planned
      (see §9)

PCI IDs, SMBIOS strings, disk/NIC identity, ACPI OEM IDs are all profile-driven
(no hard-coded fingerprints; per-instance fields are RDRAND-randomized and
persisted in NVRAM).

---

## 7. Identity / Profile

`veneer-profile` defines the `#[repr(C, packed)]` schema (CPU, SMBIOS, board,
memory, GPU, audio, network, disk + software/OS fields). `identity/profile_gen`
generates a profile from a policy template + RDRAND per-instance fields;
`identity/nvram_io` + `uefi_vars` persist it across boots; `identity/active`
holds the live Profile/Config that device emulators read.

The same schema + parser is reused by the host `veneer-probe` (so what it
validates is exactly what the hypervisor consumes).

---

## 8. VMI + stealth-hook engine (research)

veneer is L1, below PatchGuard/HVCI (in-guest defenses that detect tampering by
*reading* memory). The engine leverages that position.

**`introspect/` — Virtual Machine Introspection**
- [x] `translate` — guest virtual → physical via a software walk of the guest's
      own page tables (rooted at the guest CR3), large pages handled
- [x] `mem` — read/write guest physical and virtual, `read_struct<T>`
- [ ] `process` — EPROCESS / PsLoadedModuleList walk → process CR3, module base
      (the "semantic gap": bytes → OS objects; version-specific struct offsets)

**`hook/` — stealth execution hooks**
- [x] NX exec-trap (`svm::arm_exec_trap`): page stays readable/writable with the
      real bytes (PatchGuard/HVCI reads pass) but instruction fetch faults into
      NPF — no byte is patched, so integrity scans have nothing to detect
- [x] registry + NPF dispatch + **single-step re-arm** (disarm → RFLAGS.TF one
      step → re-arm via a #DB intercepted only for that step; captures every
      execution; guest's own #DB untouched)
- [ ] argument capture (decode calling convention, read register/stack args)
- [ ] INT3 exec-split primitive (instruction-granular vs page-granular)
- [ ] hide RFLAGS.TF from guest reads during the step
- [ ] HVCI-on (nested) NPT reconciliation (HVCI-off works today)

Scope of the PatchGuard property: not a PatchGuard-specific patch and not
Windows-specific — a general invisibility to any in-guest *read-based*
integrity monitor (PatchGuard, HVCI CI, anti-cheat self-checks, EDR scanners).
Limits: timing checks (VMEXIT overhead), anti-VM detection (separate spoofing
mission), HVCI-on nesting.

## 9. TPM 2.0 (planned full implementation)

Today a measurement TPM (presence, PCR, RNG, hash, read-only NV). Full build
makes BitLocker / Windows Hello / attestation work. Crypto = vetted no_std
RustCrypto (`rsa`, `p256`), seeded from RDRAND (`devices/tpm/crypto.rs`). All
contained in `devices/tpm/`.

- [x] **P0** crypto foundation compiles for UEFI no_std (de-risked)
- [x] presence (CRB), Startup/SelfTest, GetCapability, GetRandom, ReadClock,
      PCR_Read/Extend, Hash, NV_ReadPublic/Read, FlushContext
- [ ] **P1** object model (TPM2B / TPMT_PUBLIC/SENSITIVE / hierarchies / handle
      table) + NV persisted in NVRAM + NV_DefineSpace/Write
- [ ] **P2** CreatePrimary / Create / Load / EvictControl
- [ ] **P3** real HMAC + policy sessions (today `StartAuthSession` is a skeleton)
- [ ] **P4** Sign / Quote / Certify / RSA_Decrypt / ECDH
- [ ] **P5** Unseal + sealed objects → BitLocker / Hello complete

## 10. Hypercall channel (planned)

- [ ] `bridge/` — veneer ↔ guest user-process channel: magic CPUID leaf
      doorbell (ring-3 capable; CPUID already intercepted) + a shared-memory
      buffer read/written via `introspect`. Synchronous, OS-independent (vgk
      can't interfere; it is below the OS). For a cooperating guest agent and
      guest-triggered VMI (read/write/inject). Note: veneer can also inject
      memory / manually-map a driver directly via `introspect::write_virt` with
      no guest agent (more stealthy; vgk can't see a process that isn't there).

---

## 11. Host tool (veneer-probe)

Std binary run on the real host (not a runtime layer):
- `inspect` — probe the host CPU (vendor, SVM/VMX, NPT, MSRs) via real CPUID
- `plan` — pick the backend, report per-guest memory requirements
- `profile-check <toml>` — validate a profile against the shared schema

---

## 12. Current state (2026-06-03)

Boots OVMF firmware and runs Windows (tiny11) into kernel init. The active
focus is **boot time** under VMware nested SVM, where every #VMEXIT costs
~155 µs so any MMIO-poll storm dominates. The HPET clock-arm NPF storm is fixed
with a writable-shadow MMIO page (§5/§6); QPC runs on RDTSC (invariant-TSC +
TSC-deadline advertised). The prior `KxWaitForSpinLockAndAcquire` kernel-init
deadlock is no longer hit (boot progresses past it). Remaining boot-time cost:
an early LAPIC xAPIC MMIO storm before the guest enables x2APIC ([TODO.md](TODO.md)
§0). Runs nested under VMware Workstation (AMD SVM, `vhv=true`); host
hard-freeze during nested-virt work is mitigated (vCPU affinity pin + headless +
`mks.enable3d=FALSE`).
