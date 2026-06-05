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

A Cargo workspace of four crates. The hypervisor core is split from its UEFI
environment: `veneer-vmm` carries no UEFI dependency and reaches the environment
(memory, NVRAM, host I/O, console, MP) only through traits a host installs, so a
UEFI app, a bare-metal loader, or a test harness can all drive the same core.

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
    ├── veneer-profile/   (no_std lib)   Profile schema + parts catalog + TOML parser
    ├── veneer-vmm/       (no_std lib)   OS/firmware-agnostic VMM core (no UEFI dep)
    ├── veneer-uefi/      (no_std bin)   UEFI adapter + boot orchestration (the .efi)
    └── host/veneer-probe/(std bin)      host-side pre-flight tool
```

- **`veneer-profile`** — the single source of truth for the synthetic-PC schema
  (`#[repr(C, packed)]`, NVRAM-layout) + the parts catalog (known CPUs / boards /
  disks / dies, incl. verified per-die IOMMU values) + the schema-driven TOML
  parser. Shared by the core and the host tool, so they validate one schema.
- **`veneer-vmm`** — the VMM core: SVM, vmexit dispatch, device emulation,
  introspection, identity emitters. No UEFI dependency; the host supplies memory,
  NVRAM, host I/O backends, console, and MP services through the `platform` /
  `HostStorage` traits.
- **`veneer-uefi`** — the UEFI adapter: boot orchestration + the host-facing
  backends (`host/`), loaded by firmware as `\EFI\BOOT\BOOTX64.EFI`. Implements
  the core's environment traits over UEFI Boot/Runtime/MP Services.
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

## 3. Module map

Domain folders (file = responsibility, folder = module boundary, DAG only). The
core is `veneer-vmm`; `veneer-uefi` boots it and implements its environment
traits. The crate boundary is the core ↔ environment line: nothing in the core
names a UEFI symbol.

**`veneer-vmm` (core, no UEFI).** DAG: infra ← {hypervisor → hardware} ←
{introspect, diag}; `platform`/`guest_mem` are leaf primitives.
```
crates/veneer-vmm/src/
├── lib.rs             crate root + re-exports
├── platform.rs        environment seam: alloc_pages / stall / MP services,
│                      installed once by the host (Platform trait + slot)
├── guest_mem.rs       guest-physical → host translation + guest RAM layout
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
│   ├── devices/       registry (MmioDevice/PortDevice role traits + dispatch),
│   │                  irq/{lapic,ioapic,pic,pit,hpet,rtc,inject},
│   │                  bus/{pci,xhci,vga,nic}, storage/{nvme,ahci} + HostStorage
│   │                  trait, iommu/{mod,command} (AMD-Vi), tpm/*,
│   │                  (root) acpi_pm,kvmclock,fwcfg,i8042
│   ├── acpi/          RSDP/XSDT/FADT/MADT/HPET/MCFG/IVRS tables, acpi_fwcfg, aml
│   └── identity/      profile, profile_gen, smbios, active
├── introspect/        "observes/rewrites guest state from L1 (research/spoof)"
│   ├── translate, mem VMI read/translate foundation
│   └── hook/          stealth exec-hook engine (built on the VMI foundation)
└── diag/              "developer diagnostics; removable without behavior change"
                       serial_kd (WinDbg KD bridge), snapshot (guest-state +
                       bugcheck decode), thread_walk (read-only VMI census),
                       validator, report
```

**`veneer-uefi` (UEFI adapter).** Boot orchestration + the UEFI implementations
of the core's traits.
```
crates/veneer-uefi/src/
├── main.rs            UEFI entry + boot orchestration (composition root);
│                      installs the platform + host-storage backends at startup
├── guest/boot/        chain_load, esp_io, guest_blob, linux_loader, menu,
│                      uefi_config  (loads/launches the guest)
└── host/              UEFI impls of the core's traits:
                       platform (alloc/stall/MP), input (PS/2 from host console),
                       storage_backend + host_ahci (host disk), nvram_io, uefi_vars
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

veneer presents a coherent fake machine. Each device class is its own module
behind a role trait (`MmioDevice` / `PortDevice`); the vmexit dispatcher routes a
trapped access to the device that claims it, so adding, deepening, or swapping a
device (emulated ↔ passthrough) is local to one module plus one registry entry.

- [x] **IRQ/timers**: LAPIC, IO-APIC, 8259 PIC, 8254 PIT, HPET, RTC/CMOS,
      interrupt injection. HPET uses a **writable-shadow MMIO page** (§5) +
      lazy `shadow_tick` reconcile to avoid the per-tick clock-arm NPF storm;
      it stays interrupt-capable so the HAL clock init doesn't bugcheck 0x5C.
- [x] **Bus/IO**: PCI config space (CF8/CFC + ECAM), xHCI, VGA, NIC (BAR trap)
- [x] **Storage**: NVMe + AHCI (MMIO BAR emulation, host-backed disk)
- [~] **IOMMU (AMD-Vi)**: IVRS/IVHD + MMIO registers + command buffer, with the
      EFR (feature register) taken from the profile's CPU die (a real per-die
      value). veneer decodes remappable IO-APIC/MSI entries through the guest IR
      tables (Device Table → IRTE) to the real vector for injection — not a
      functional DMA remapper (single vCPU; veneer injects directly). The
      desktop-chiplet dies report no x2APIC interrupt remapping (EFR XTSup clear),
      which the forced-x2APIC boot path needs — see TODO §0.
- [x] **Platform**: ACPI (RSDP/XSDT/FADT/MADT/HPET/MCFG/IVRS), SMBIOS, fw_cfg,
      i8042 (PS/2 kbd), ACPI PM timer, kvmclock
- [~] **TPM 2.0** (CRB): presence + measured boot today; full crypto planned
      (see §9)

PCI IDs, SMBIOS strings, disk/NIC identity, ACPI OEM IDs are all profile-driven
(no hard-coded fingerprints; per-instance fields are RDRAND-randomized and
persisted in NVRAM).

---

## 7. Identity / Profile

`veneer-profile` defines the `#[repr(C, packed)]` model, organized by component
(CPU + on-die IOMMU, memory, system/board/firmware, GPU, audio, network, storage
+ software/OS fields). Each component separates model-class facts (`spec`, from
the catalog) from per-unit identifiers (`instance`, generated); peripherals also
carry a delivery mode (emulated / passthrough / absent). The parts `catalog`
composes a profile from real parts (CPUs, boards, disks, per-die IOMMU values),
and a `coherence` validator checks cross-surface invariants (e.g. CPU vendor ↔
IOMMU EFR). `identity/profile_gen` fills the per-instance fields (RDRAND); the
adapter's `nvram_io` + `uefi_vars` persist the profile across boots;
`identity/active` holds the live Profile/Config the emitters read.

The same schema + catalog + parser is reused by the host `veneer-probe` (so what
it validates is exactly what the core consumes).

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

## 12. Performance note — nested-virt VMEXIT cost

Under VMware nested SVM every guest #VMEXIT costs on the order of 100–200 µs
(L0 handles it before veneer does), so an MMIO-poll storm dominates boot time.
This is why the HPET clock timer is backed by a writable-shadow MMIO page
(§5/§6) rather than trapped — its per-tick `HalpHpetArmTimer` re-arm would
otherwise be ~7 NPF #VMEXITs every couple of ms. The same pressure shapes the
rest of the design: prefer native RDTSC (invariant-TSC + TSC-deadline
advertised) over trapped timer MMIO, and reserve trapping for genuinely
side-effecting registers.

Build / boot / VM setup is in [SETUP.md](SETUP.md); open work in [TODO.md](TODO.md).
