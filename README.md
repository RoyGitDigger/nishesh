# NISHESH — निःशेष

**Integrated secure data erasure and advanced file recovery for digital
forensics and data sanitization.**

Smart India Hackathon 2026 · Problem Statement **SIH26149** · National
Technical Research Organisation · Team Unallocated, National Forensic Sciences
University, Dharwad.

---

## The problem

Every commercial erasure product on the market works the same way. It sends the
drive an erase command, the drive replies *done*, and the software prints a
certificate based on that reply.

In 2011 a team at UC San Diego desoldered the flash chips off twelve SSDs after
running the manufacturer's own secure-erase command and read the raw silicon
directly. **Eight of the twelve still held data.** Some had reported success.
On single-file overwrites, 4–75% of file content survived on SATA drives and up
to 84.9% on USB.¹

Blancco later bought 159 used drives on eBay: 42% still held sensitive data,
15% held personally identifiable data. Every seller believed they had erased
them.²

Meanwhile the tools that *could* check — Autopsy, The Sleuth Kit, PhotoRec —
sit on the other side of the industry. They recover deleted data for
investigators. They have never been pointed at a wiping tool.

**The market has tools that erase and tools that recover. The two have never
met.**

## What NISHESH does

One engine, two directions.

```
                         TARGET MEDIA
                              │
                    M1 · DEVICE ACCESS
         identify · unlock HPA/DCO · write-block · image + hash
                              │
                          ◇ MODE ?
              ┌───────────────┴───────────────┐
        INVESTIGATOR                     DISPOSAL
              │                               │
    M2 · RECOVERY ENGINE            M3 · SANITIZATION ENGINE
  metadata · carve · slack       policy → firmware purge by class
              │                               │
      FORENSIC REPORT              M2 · RE-RUN ON THE WIPED DRIVE
                                     (the same code, now the verifier)
                                              │
                                    ◇ RESIDUAL FOUND ?
                                  yes │             │ no
                                 ESCALATE      M4 · CERTIFICATE
                            retry → alt Purge   Ed25519 + Merkle,
                            → Destroy, no cert  verifiable offline
```

A certificate is signed only when a full forensic attack on the wiped medium
comes back empty. The certificate does not say *the drive told us it worked*.
It says *we tried to get the data back, with everything we have, and got
nothing* — with a statistical bound and a plain statement of what could not be
reached.

## Quick start

No dependencies to install. Rust stable and nothing else.

```bash
cargo build --release

# 1. build an evidence image with known ground truth
./target/release/nishesh testgen --out demo/evidence.img

# 2. what is this device really, and is it hiding capacity?
./target/release/nishesh identify demo/evidence.img --as sata-ssd --hpa 2048 --dco 1024

# 3. recover the deleted files, graded by SHA-256 against the manifest
./target/release/nishesh recover demo/evidence.img \
    --manifest demo/evidence.manifest.json --out demo/recovered

# 4. the loop: wipe, then attack the wipe
cp demo/evidence.img demo/target.img
./target/release/nishesh sanitize demo/target.img --as sata-ssd \
    --hpa 2048 --dco 1024 --execute --confirm --samples 3000 \
    --cert demo/certificate.json --log demo/chain.jsonl

# 5. verify the certificate offline, with nothing but the file
./target/release/nishesh verify-cert demo/certificate.json --log demo/chain.jsonl
```

Or run the whole thing: `./demo/demo.sh`

## Measured results

From `nishesh selftest` on the generated corpus:

| Metric | Result |
|---|---|
| Byte-exact recovery of deleted files | **100% (5/5)**, SHA-256 identical |
| Independent carve confirmation | JPEG, PNG, PDF, ZIP all validator-confirmed |
| File slack payload recovered | yes |
| Artifacts recoverable before wipe → after | **12 → 0** |
| Hidden sectors unlocked and swept | 3072 (HPA + DCO) |
| Statistical residual bound | < 0.1% at 95% confidence (n = 3000) |
| Certificate tamper detection | one altered field → rejected |

Every one of these is reproduced by `./demo/demo.sh --fast` and by CI.

## Why there are no dependencies

`Cargo.toml` has an empty `[dependencies]` section and that is deliberate.

The deployment target is air-gapped — forensic labs, defence disposal bays,
CPSU IT rooms. An organisation accrediting this tool has to audit its entire
software bill of materials. So every algorithm is implemented in-tree against
its published specification and covered by published test vectors:

| Algorithm | Specification | Location |
|---|---|---|
| SHA-256 | FIPS 180-4 | `src/hash.rs` |
| HMAC-SHA256 | RFC 2104, vectors from RFC 4231 | `src/hash.rs` |
| Aho-Corasick | Aho & Corasick, CACM 18(6), 1975 | `src/carve.rs` |
| CRC-32/ISO-HDLC | as used by PNG and ZIP | `src/carve.rs` |
| JSON canonicalisation | RFC 8785 (JCS) | `src/json.rs` |
| Merkle log | RFC 6962 §2 | `src/proof.rs` |
| FAT12/16/32 on-disk | MS EFI FAT32 spec 1.03, ECMA-107 | `src/fat.rs` |

**One exception is planned and documented.** Ed25519 (RFC 8032) is *not*
hand-rolled — hand-rolling asymmetric cryptography is malpractice. It arrives
in Phase 2 behind the `proof::Signer` trait using `ed25519-dalek`, with the
private key held in a TPM 2.0 or a smartcard. Until then the development signer
uses HMAC-SHA256 and every certificate it produces says so, in the certificate
itself, and reports `non_repudiation: false`.

## Standards

- **NIST SP 800-88 Rev. 2** (26 September 2025) — Clear / Purge / Destroy, and
  the requirement that sanitization be *verified*, which Rev. 2 made mandatory
  rather than optional.
- **IEEE Std 2883-2022** — per-media technique selection, and the
  retry-and-escalate flow that `sanitize::escalate` implements.
- **RFC 8785** JSON Canonicalization Scheme — the bytes the signature covers.
- **RFC 6962** Certificate Transparency — the Merkle log construction.

The policy engine's mapping from media class to technique is a pure function in
`sanitize::plan`, and it is tested. Notably:

- A hard disk without SANITIZE support gets a **single-pass** overwrite at Clear
  level. One pass. Multi-pass schemes such as DoD 5220.22-M and Gutmann are
  retired and add nothing on magnetic media.
- Solid-state media with no device-internal erase command is **refused**, not
  overwritten. Flash cannot be sanitized from the host.
- **NVMe Format NVM is not NVMe Sanitize.** Format is recorded as Clear;
  conflating the two is the most common standards error in this category.

## Honest limitations

Stated here and on every certificate the tool issues.

1. No software reads unmapped physical NAND pages retained by a flash
   translation layer. Nothing short of chip-off can. What NISHESH establishes
   is that every addressable byte, every unlocked hidden region, all file slack
   and all unallocated space are clean, and that the firmware technique
   appropriate to the media class executed and reported success.
2. Complete verification is impossible by construction. The residual bound is
   statistical, computed by the rule of three, and the sample seed is recorded
   so an auditor can reproduce the exact sample set.
3. Physical-device execution (real ATA/NVMe command issue) is Phase 2. The
   policy engine, state-machine handling and verification loop are
   transport-independent and complete today.
4. NTFS support is Phase 2. FAT12/16/32 is complete in both directions.
5. Entropy analysis cannot distinguish encrypted data from random. It is used
   for triage and for the zero-check, and the tool says so rather than
   overclaiming.

## Documents

- `CLAUDE.md` — working agreement for continued development
- `ROADMAP.md` — phase plan from here to a deployable system

---

¹ M. Wei, L. Grupp, F. Spada, S. Swanson, "Reliably Erasing Data from
Flash-Based Solid State Drives," USENIX FAST '11, pp. 105–117.

² Blancco and Ontrack, "Privacy for Sale: Data Security Risks in the Second-Hand
IT Asset Marketplace," 2019.

Licensed under Apache-2.0.
