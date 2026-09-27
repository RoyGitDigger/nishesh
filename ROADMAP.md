# ROADMAP

Phase 1 is done and runs. Everything below is ordered by a single rule: **the
next thing built should be the thing that would most embarrass us if a judge
asked about it.**

---

## Phase 1 — foundation ✅ COMPLETE

- [x] `Device` trait with a file backend; three-valued capacity model
      (user / native / DCO) so hidden regions are first-class
- [x] Software write blocking enforced by type, not by convention
- [x] FAT12/16/32 parser: BPB, FAT width derived from cluster count, directory
      entries, deleted-entry detection
- [x] FAT16 **builder** — ground-truth corpora with no root and no loop devices
- [x] Recovery of deleted files with byte-exact SHA-256 grading
- [x] File-slack extraction
- [x] Aho-Corasick automaton, 25 signature patterns, single-pass scan
- [x] Format-native validators: JPEG marker chain, PNG per-chunk CRC32, ZIP
      central directory, PDF structure
- [x] Shannon entropy triage and wipe block classification
- [x] Sanitization policy engine mapping media class → NIST 800-88 Rev 2 level
      and IEEE 2883 technique, with recorded rationale
- [x] Refusal path: flash without firmware erase is never overwritten
- [x] Statistical verification with the rule-of-three bound and a recorded seed
- [x] **Adversarial verification** — the recovery engine re-run on the wipe
- [x] RFC 8785 canonical JSON; HMAC-SHA256 development signer
- [x] Hash-chained append-only log; RFC 6962 Merkle tree with O(log n)
      inclusion proofs; offline certificate verifier
- [x] 44 tests including FIPS 180-4 and RFC 4231 vectors
- [x] CLI, terminal presentation layer, demo script, CI

---

## Phase 2 — the two things a judge will ask about first

### 2.1 NTFS (`src/ntfs.rs`) — highest priority

The forensically important filesystem and the one NTRO cares about.

- [ ] Boot sector: note that clusters-per-MFT-record at offset 0x40 is
      **signed** — a negative value means the record size is 2^|n| bytes
- [ ] **Update Sequence Array fixup.** Every FILE record has the last two bytes
      of each sector replaced by a sequence number, with the originals in the
      USA. Restore them *before* parsing anything. Skipping this silently
      corrupts every run list that crosses a sector boundary, and it is the
      single most common NTFS parser bug
- [ ] Attribute chain walk: read type, read length, jump, until 0xFFFFFFFF
- [ ] Resident vs non-resident `$DATA`. Small deleted files live inside the MFT
      record and come back intact even after their clusters were reused
- [ ] **Data run list decoding** — variable-width signed deltas, each run's
      offset relative to the previous run's start
- [ ] Deleted detection: bit 0 of the flags at 0x16
- [ ] `$Bitmap` for unallocated cluster identification
- [ ] Unit tests building synthetic MFT records in-test

### 2.2 Physical devices (`src/device/linux.rs`, feature `linux-device`)

- [ ] `SG_IO` ioctl with the `ATA_16` (0x85) SCSI opcode wrapping ATA taskfiles
- [ ] `IDENTIFY DEVICE` (0xEC) → model, serial, firmware, word 128 security
      status, words 82–87 feature sets, words 100–103 max LBA
- [ ] `READ NATIVE MAX ADDRESS EXT` (0x27) → HPA detection
- [ ] `DEVICE CONFIGURATION IDENTIFY` (0xB1 / 0xC2) → DCO detection
- [ ] `SET MAX ADDRESS EXT` (0x37) with the **volatility bit set**, so unlocking
      an HPA reverts on power cycle and does not permanently alter evidence
- [ ] `NVME_IOCTL_ADMIN_CMD` → Identify Controller (0x06 / CNS 0x01), reading
      OACS, SANICAP and FNA
- [ ] TCG Discovery 0 over `SECURITY PROTOCOL IN` (0xA2) for Opal
- [ ] Transport detection so `passthrough_blocked` is probed, not assumed
- [ ] All `unsafe` confined to this file, every invariant documented

---

## Phase 3 — execution and evidence handling

- [ ] ATA security **state machine** SEC0–SEC5 with the frozen-state escape:
      suspend-to-RAM resets the controller without power-cycling the host
- [ ] `SANITIZE DEVICE` (0xB4) with the feature-specific key, asynchronous
      progress polling
- [ ] NVMe Sanitize (0x84) with SANACT selection and Sanitize Status log page
      (0x81) polling, including exiting the failure mode after a failed sanitize
- [ ] Opal PSID revert via the label password
- [ ] Real retry → escalate → Destroy execution driving `sanitize::escalate`
- [ ] Hard interlock: refuse any mounted filesystem or the running root device
- [ ] Imaging to E01 with per-chunk CRCs; AFF4 after that
- [ ] BLAKE3 alongside SHA-256 for fast parallel hashing
- [ ] ext4: superblock, group descriptors, extent trees, jbd2 journal replay
- [ ] NTFS journals: `$LogFile` undo records, `$UsnJrnl:$J` timeline

---

## Phase 4 — proof hardening

- [ ] `Ed25519Signer` behind the `ed25519` feature using `ed25519-dalek`;
      `non_repudiation` becomes true only on this path
- [ ] TPM 2.0 key storage via `tss-esapi`, so the private key never enters
      process memory; quote binding the event to the machine that performed it
- [ ] Signed, device-bound entitlement file — offline licensing with no
      activation server
- [ ] Consistency proofs between Merkle tree versions (RFC 6962 §2.1.2), so an
      auditor can prove the log was append-only between two snapshots
- [ ] Optional external anchoring of the daily Merkle root — 32 bytes, no
      device data, no user data

---

## Phase 5 — performance and scale

- [ ] `rayon` for parallel carving across cores, with chunk overlap equal to
      the longest pattern so boundary matches survive
- [ ] `O_DIRECT` reads to bypass the page cache on multi-terabyte media
- [ ] `memmap2` for image-backed access
- [ ] Bifragment gap carving for the two-fragment case
- [ ] Sparse image support

---

## Phase 6 — delivery

- [ ] Tauri + React dual-mode GUI over the existing CLI verbs
- [ ] Debian `live-build` bootable ISO — required because a machine cannot
      sanitize its own running system drive
- [ ] PDF report rendering
- [ ] Benchmark harness running PhotoRec, foremost and `tsk_recover` over the
      same corpora and emitting the comparison table for the deck
- [ ] NIST CFReDS and Digital Corpora integration for external validation

---

## Explicitly out of scope

- Chip-off recovery. Requires hardware we do not have and does not belong in
  software.
- Claiming to read unmapped NAND. We state the limitation instead.
- Any technique that would let a certificate be issued without verification.
