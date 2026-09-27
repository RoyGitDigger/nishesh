# CLAUDE.md — working agreement for Claude Code on this repository

Read this before changing anything.

## What this is

NISHESH implements SIH 2026 problem statement **SIH26149** (NTRO): an
integrated secure data erasure and advanced file recovery tool for digital
forensics and data sanitization.

The architectural thesis, and the thing that must never be diluted:

> The forensic recovery engine is the verifier for the sanitizer. After a wipe,
> the same code that recovers evidence is turned on the wiped medium and told
> to attack it. A certificate is signed only when that attack comes back empty.

Commercial products verify a wipe by reading back the addressable range and
trusting the drive's own success code. Wei et al. (USENIX FAST '11) desoldered
the flash off twelve SSDs after running the built-in secure erase: eight still
held data, some having reported success. That gap is the product.

## Hard rules

1. **No third-party crates in the core.** The dependency list in `Cargo.toml`
   is empty and stays empty. This is an auditability property for air-gapped
   accreditation, not an accident. If you believe a dependency is genuinely
   required, say so and wait — do not add it.
   - The ONE planned exception is `ed25519-dalek` behind `proof::Signer`,
     because hand-rolling asymmetric cryptography is malpractice. It goes
     behind a cargo feature, not in the default build.

2. **Never hand-roll asymmetric cryptography.** Symmetric primitives with
   published test vectors (SHA-256, HMAC, CRC32, Merkle) are fine and are
   already covered by vectors in the tests. Signatures, key exchange and
   elliptic curves are not.

3. **Never fall back to software overwrite on flash.** If a firmware sanitize
   cannot be issued, the correct behaviour is to REFUSE and escalate to
   physical destruction. `sanitize::plan` enforces this and
   `ssd_without_firmware_erase_is_refused_never_overwritten` guards it. If a
   change makes that test fail, the change is wrong.

4. **Every claim is testable.** No number reaches the user that was not
   measured. Recovery rates are graded by SHA-256 against a manifest written
   before deletion. If you add a capability, add the test that proves it.

5. **Honesty over polish in output.** The certificate states its own
   limitations — that no software reads unmapped NAND pages, that the
   development signer is a MAC and not a signature. Do not remove those
   statements to make the output look stronger.

6. **`unsafe` is denied** at the crate level. Keep it that way. When the Linux
   ioctl layer lands it will need a tightly scoped `unsafe` block; isolate it
   in `device/linux.rs` with an `#[allow]` on that module only, and document
   every invariant.

## Layout

```
src/hash.rs      SHA-256 (FIPS 180-4), HMAC (RFC 2104), hex
src/json.rs      RFC 8785 canonical JSON — the bytes the signature covers
src/device.rs    Device trait, DeviceInfo, ImageDevice, three-valued capacity
src/fat.rs       FAT12/16/32 parser AND builder (the corpus generator)
src/carve.rs     Aho-Corasick automaton, signature DB, format validators
src/artifact.rs  Artifact record, Shannon entropy, wipe block classification
src/sanitize.rs  Policy engine, execution, statistical + adversarial verify
src/proof.rs     Signer trait, Merkle tree, hash chain, certificates
src/testgen.rs   Ground-truth corpus construction
src/report.rs    Terminal presentation
src/main.rs      CLI
```

The dependency direction is strictly downward. `sanitize` may call `carve`;
`carve` must never call `sanitize`.

## Build and check

```bash
cargo build --release
cargo test                # must stay green; 40+ tests
cargo clippy -- -D warnings
cargo fmt
./target/release/nishesh selftest
./demo/demo.sh --fast     # full pipeline, no pauses
```

## How to ask for work

Give one phase at a time. This codebase rewards depth over breadth — a
half-finished NTFS parser is worth less than a complete FAT one.

Good prompts, roughly in the order they should be tackled:

> Read ROADMAP.md Phase 2.1 and implement the NTFS boot sector and `$MFT`
> parser in a new `src/ntfs.rs`. Handle the Update Sequence Array fixup before
> parsing any record — every FILE record has the last two bytes of each sector
> replaced by a sequence number and the originals stashed in the USA, and
> skipping that step silently corrupts run lists. Decode the data run list as
> variable-width signed deltas. Add unit tests using a synthetic MFT record
> built in the test, and wire it into `run_recovery` beside the FAT path.

> Implement `device/linux.rs` behind a `linux-device` cargo feature: `SG_IO`
> ATA passthrough for `IDENTIFY DEVICE` (0xEC), `READ NATIVE MAX ADDRESS EXT`
> (0x27) and `DEVICE CONFIGURATION IDENTIFY` (0xB1/0xC2), plus
> `NVME_IOCTL_ADMIN_CMD` for Identify Controller. Populate `DeviceInfo`
> honestly — where a value cannot be probed, mark it unknown rather than
> guessing. Keep every `unsafe` block in that file and document its invariants.

> Add `src/proof/ed25519.rs` behind an `ed25519` feature implementing the
> `Signer` trait over `ed25519-dalek`. Keep `DevSigner` as the default so the
> zero-dependency build still works. Make `non_repudiation` true only for the
> Ed25519 path.

Bad prompts: "make it better", "add more features", "optimise everything".

## Things that will be tempting and are wrong

- Adding `serde` because hand-rolling JSON feels primitive. The canonical
  serialiser *is* the signature format; a second serialiser is a second source
  of truth and a bug waiting to happen.
- Making the policy engine "more helpful" by overwriting flash when no firmware
  erase is available. See rule 3.
- Rounding a confidence score up, or dropping the `unconfirmed` label, because
  the table looks better with all green. The labels are the point.
- Deleting the limitation text from the certificate.

## Before you commit

- `cargo test` green
- `cargo clippy -- -D warnings` clean
- `./demo/demo.sh --fast` runs end to end
- New behaviour has a test that would fail without it
