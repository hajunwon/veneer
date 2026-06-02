# veneer — TODO

Plain task list. Design/structure context is in [ARCHITECTURE.md](ARCHITECTURE.md).
Last updated 2026-06-03.

## 0. Core boot (blocker)
- [ ] Resolve `KxWaitForSpinLockAndAcquire` deadlock — ROOT-CAUSED (KD callstack 2026-06-03): HAL clock init (HalpTimerInitializeClock → HalpVpptArmTimer → HalpHpetSetMatchValue) holds the VPPT high-level spinlock while arming the HPET; the clock IRQ veneer delivers re-enters HalpVpptAcknowledgeInterrupt → the same lock → 1-CPU self-deadlock. Tried: IRQL gate on V_TPR (disproven — the guest doesn't write CR8 at this phase; IRQL is in no veneer-visible register); HPET future-arm (kept, correct but insufficient). NEXT: diag/ VMI probe of the guest's IRQL / masking state, then gate injection or re-pace HPET delivery.
- [x] Host freeze/BSOD gating resolved: vCPU affinity pin (numvcpus=2 + `sched.cpu.affinity`) for the CPU-starvation freeze; headless boot + `mks.enable3d=FALSE` for the host nvlddmkm `0x3B` BSOD (VMware GUI 3D render path through the NVIDIA driver).

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
- [ ] Remove post-boot diagnostic logging ([prof] / [pw] / [pci-scan] / [hostapic] / [kd] / [npf-spin] / ahci-trace / [tscjump] / [ltmr] / [inject] / [hpet] T0 arm-trace / [perf]); also the `hpet.rs` CMP_TRACE added during spinlock diagnosis

## 5. Build / infra
- [x] git init + first commit (branch `main`, 59180a9)
- [x] `.gitignore` — `/target`, `__pycache__/`, `*.pyc`
- [x] All warnings → 0 across all three crates (removed linux_loader PVH/bzImage
      dead path ~413 lines; fixed a real msr.rs unreachable arm that would have
      leaked host syscall/FSGS MSRs; crate-level allow(dead_code) for spec maps)
- [ ] Add a remote + push (`git remote add origin <url>` && `git push -u origin main`)
- [ ] (optional) gitignore `assets/firmware/variants/` if the repo should be leaner

## 6. Fingerprints / fidelity
- [ ] Verify `identity/profile_gen.rs` firmware revs: SN850X "620361WD", T700 "PACR5111"
- [ ] `devices/storage/ahci.rs:502` — make INQUIRY optical-drive string profile-driven
