# veneer — TODO

Open task list. Design/structure context is in [ARCHITECTURE.md](ARCHITECTURE.md);
completed work is in the git history.

## 0. Boot performance + input
- [ ] xAPIC LAPIC MMIO is the boot wall-clock cost: early accesses (`0xFEE00xxx`:
  LVT timer / init-count / current-count / EOI / SVR) are each an NPF #VMEXIT. The
  LAPIC can't be naively RAM-backed like the HPET (EOI/ICR/timer have side
  effects). Option: selectively cheapen the hot register(s) (likely the timer
  current-count 0x390 calibration read).
- [ ] x2APIC profiles (APU / server dies, where the IOMMU has XTSup) need device
  MSI/MSI-X decoded through the IRTE (`iommu::remap_vector` on the `pci.rs` / NVMe
  paths, resolved at injection time). Not needed for desktop-die (xAPIC) profiles.
- [ ] Mouse input: the guest gets keyboard (i8042 PS/2 kbd, IRQ1) but no mouse
  at all in Setup. Add the i8042 AUX port (PS/2 mouse): aux enable (0xA8) /
  write-to-aux (0xD4) / the mouse command set (reset→0xAA 0x00, 0xF4 enable,
  sample-rate, resolution) + feed 3-byte movement packets on IRQ12 from a host
  mouse source. Simpler + Setup-native vs a USB-HID mouse on the emulated xHCI.

## 1. TPM 2.0 (full)
- [ ] P1: object model (TPM2B / TPMT_PUBLIC/SENSITIVE / hierarchies / handle table) + NV persisted in NVRAM + NV_DefineSpace / NV_Write
- [ ] P2: CreatePrimary / Create / Load / EvictControl / real FlushContext
- [ ] P3: real HMAC + policy sessions (replace `StartAuthSession` skeleton)
- [ ] P4: Sign / VerifySignature / Quote / Certify / RSA_Decrypt / ECDH
- [ ] P5: Unseal + sealed objects → BitLocker / Hello
- [ ] Remove `devices/tpm/crypto::_smoke` once real commands link crypto

## 2. VMI + hook engine
- [ ] hook: argument capture (decode calling convention, read register/stack args) — `hook/mod.rs:139`
- [ ] introspect: `process.rs` — EPROCESS / PsLoadedModuleList walk (process CR3, module base)
- [ ] host: offline offset extractor (ntoskrnl / vgk PE → function RVAs, exports, vgk verify site IAT 0xA3028)
- [ ] hook: INT3 exec-split primitive (instruction-granular)
- [ ] hook: hide RFLAGS.TF from guest during single-step
- [ ] hook: HVCI-on (nested) NPT reconciliation
- [ ] hook: `set_npt` for the `build_translated` paths (main.rs ~820 / ~1110)
- [ ] introspect: promote main.rs `dump_pagewalk` / `dump_kernel_stuck` into `introspect/dump.rs`
- [ ] diag/: spin/stall trigger → VMI snapshot (guest GPRs, RIP+RVA, stack walk, lock word, effective IRQL) + hardware-invariant assertions. First brick of the formalized diagnostic chain, replacing ad-hoc sprintln (closes the "guest IRQL/state invisible from L1" gap). (built on introspect/)

## 3. Hypercall channel
- [ ] `bridge/` — magic CPUID doorbell + shared-memory buffer (veneer ↔ guest user process)

## 4. Structure / cleanup
- [x] src/ reorganized into role-based layers (`infra/ hypervisor/ hardware/ guest/ introspect/ diag/`); root holds only `main.rs`; `arch.rs` → `infra/arch.rs` (root uniformity achieved this way). Per-layer boundary rule in ARCHITECTURE.md. (2026-06-03)
- [ ] Deploy artifacts (`target/veneer-esp-flat.vmdk`, `veneer.iso`, `veneer-esp.vmdk`) → `dist/` (touches make_disk.py / make_iso.py / patch_vmx.py / 2 ps1 / VM `.vmx`)
- [ ] Remove the remaining post-boot diagnostic logging ([prof] / [pw] / [pci-scan] /
  [hostapic] / [kd] / [npf-spin] / [npf-rd] / ahci-trace / [tscjump] / [ltmr] /
  [inject] / [perf]) once the boot reaches Setup and the storms are settled

## 5. Build / infra
- [x] git init + first commit (branch `main`, 59180a9)
- [x] `.gitignore` — `/target`, `__pycache__/`, `*.pyc`
- [x] All warnings → 0 across all crates
- [ ] (optional) gitignore `assets/firmware/variants/` if the repo should be leaner

## 6. Fingerprints / fidelity
- [ ] Verify Crucial T700 fingerprints (`veneer-profile catalog/disks.rs`): Micron
  IEEE OUI + a real firmware-rev string (capture from `nvme id-ctrl`). SN850X /
  980 PRO controller IDs + OUIs are verified.
- [ ] `devices/storage/ahci.rs:502` — make INQUIRY optical-drive string profile-driven
