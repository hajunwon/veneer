# veneer — TODO

Plain task list. Design/structure context is in [ARCHITECTURE.md](ARCHITECTURE.md).
Last updated 2026-06-03.

## 0. Core boot (blocker = boot-time storms, not the old deadlock)
- [x] HPET writable-shadow MMIO (commit `perf(hpet):…`): back the HPET MMIO page
  with a writable host page so the guest's per-~2 ms `HalpHpetArmTimer` re-arms
  hit RAM instead of faulting (~7 NPF/arm × ~155 µs each under nested SVM = the
  dominant boot storm). veneer reconciles counter/comparator lazily in
  `hpet::shadow_tick` (every #VMEXIT). Steady-state HPET NPF: ~183k → ~2k per
  250k-exit window. HPET stays present + interrupt-capable.
- [x] CONFIRMED: removing the HPET's interrupt-routing cap (`TN_INT_ROUTE_CAP=0`)
  does NOT cure the storm — it BUGCHECKS `0x5C HAL_INITIALIZATION_FAILED`
  (args 0x110,_,0x14,0xC0000001). The HAL has no interrupt-capable clock timer
  to fall back to and does NOT switch to the LAPIC/TSC-deadline on its own. So
  the HPET must stay; the storm is cured by making its MMIO cheap (above), not
  by removing it. (Masking-clean: no Hyper-V enlightenment exposed.)
- [x] TSC-deadline (CPUID.1 ECX[24]) + invariant TSC (0x80000007 EDX[8]) advertised
  + jump-free `tsc_offset` (commit `perf(clock):…`): QPC runs on RDTSC, not HPET MMIO.
- [x] COM2 phantom-DR boot wedge fixed (commit `fix(kd):…`): KD-off COM2 was
  returning 0xFFFFFFFF (LSR DR stuck set → KdReceivePacket spun on phantom
  bytes); now a quiescent idle 16550. Was hidden behind the slow boot until the
  HPET storm shrank.
- [ ] **NEXT blocker: early LAPIC xAPIC MMIO storm** (`0xFEE00xxx`: LVT timer
  0x320 / init-count 0x380 / EOI / SVR, before the guest switches to x2APIC).
  ~90 s in one window. The LAPIC can't be naively RAM-backed (EOI/ICR/timer
  have side effects veneer must emulate) — needs a different fix (encourage
  early x2APIC adoption, or selectively cheapen the hot timer registers).
- [~] `KxWaitForSpinLockAndAcquire` / VPPT self-deadlock (prior blocker): NOT hit
  in 2026-06-03 boots (HPET present + writable-shadow, 1- and 2-vCPU both
  progress through early kernel init). The high-IRQL stalls seen while
  diagnosing were the 0x5C bugcheck from the (reverted) HPET-removal experiment,
  not the VPPT lock; the committed V_IRQ/V_TPR injection (inject.rs) is the
  intended guard. Re-confirm it stays resolved once the boot reaches Setup.
- [x] Host freeze/BSOD gating resolved: vCPU affinity pin (`sched.cpu.affinity`)
  for the CPU-starvation freeze; headless boot + `mks.enable3d=FALSE` for the
  host nvlddmkm `0x3B` BSOD (VMware GUI 3D render path through the NVIDIA driver).

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
- [ ] diag/: spin/stall trigger → VMI snapshot (guest GPRs, RIP+RVA, stack walk, lock word, effective IRQL) + hardware-invariant assertions. First brick of the formalized diagnostic chain, replacing ad-hoc sprintln. Resolves the §0 deadlock's "guest IRQL invisible" gap. (built on introspect/)

## 3. Hypercall channel
- [ ] `bridge/` — magic CPUID doorbell + shared-memory buffer (veneer ↔ guest user process)

## 4. Structure / cleanup
- [x] src/ reorganized into role-based layers (`infra/ hypervisor/ hardware/ guest/ introspect/ diag/`); root holds only `main.rs`; `arch.rs` → `infra/arch.rs` (root uniformity achieved this way). Per-layer boundary rule in ARCHITECTURE.md. (2026-06-03)
- [ ] Deploy artifacts (`target/veneer-esp-flat.vmdk`, `veneer.iso`, `veneer-esp.vmdk`) → `dist/` (touches make_disk.py / make_iso.py / patch_vmx.py / 2 ps1 / VM `.vmx`)
- [x] Removed the boot-time-storm diagnostic scaffolding (2026-06-03): `[io-sample]`
  (io.rs), `[pci-poll]` (pci.rs), `[hpet-prof]` access/arm-delta profiler (hpet.rs),
  and the `diag/winstorage` scanner + 8.4 MB `winstorage_ref.bin` (it confirmed the
  "0.3 GB/s leak" was the benign zero-page thread).
- [ ] Remove the remaining post-boot diagnostic logging ([prof] / [pw] / [pci-scan] /
  [hostapic] / [kd] / [npf-spin] / [npf-rd] / ahci-trace / [tscjump] / [ltmr] /
  [inject] / [perf]) once the boot reaches Setup and the storms are settled

## 5. Build / infra
- [x] git init + first commit (branch `main`, 59180a9)
- [x] `.gitignore` — `/target`, `__pycache__/`, `*.pyc`
- [x] All warnings → 0 across all three crates (removed linux_loader PVH/bzImage
      dead path ~413 lines; fixed a real msr.rs unreachable arm that would have
      leaked host syscall/FSGS MSRs; crate-level allow(dead_code) for spec maps)
- [x] Add a remote + push (`origin` = github.com/hajunwon/veneer.git; `main` tracks `origin/main`)
- [ ] (optional) gitignore `assets/firmware/variants/` if the repo should be leaner

## 6. Fingerprints / fidelity
- [ ] Verify `identity/profile_gen.rs` firmware revs: SN850X "620361WD", T700 "PACR5111"
- [ ] `devices/storage/ahci.rs:502` — make INQUIRY optical-drive string profile-driven
