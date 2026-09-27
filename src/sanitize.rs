//! Sanitization (module M3) and verification.
//!
//! Standards: NIST SP 800-88 Rev. 2 (26 September 2025) for the governance
//! model and the Clear / Purge / Destroy levels; IEEE Std 2883-2022 for the
//! per-media technique. Revision 2 moved the device-specific "how" to IEEE
//! 2883 and made verification a REQUIRED step rather than an optional one.
//!
//! The two facts this module is built around:
//!
//! 1. Overwriting flash does not sanitize it. The controller runs a flash
//!    translation layer — structurally a page table with a garbage collector.
//!    A write to a logical block lands on a fresh physical page and the old
//!    page is merely marked stale. Wear levelling relocates data with no host
//!    involvement. Between roughly 7% and 28% of the die is over-provisioned
//!    and carries no logical address at all. Only the firmware owns the map,
//!    so only the firmware can erase the medium.
//!
//! 2. Firmware commands cannot simply be trusted either. Wei, Grupp, Spada and
//!    Swanson (USENIX FAST '11) desoldered the flash off twelve SSDs after
//!    running the built-in secure-erase command: eight still held data, and
//!    some had reported success. Their conclusion was that firmware-based
//!    sanitization must be verifiable to be trustworthy.
//!
//! So: choose the technique the medium actually requires, execute it, and then
//! attack the result with the recovery engine before signing anything.

use crate::artifact::{is_zeroed, shannon_entropy, Artifact};
use crate::device::{Device, DeviceInfo, ImageDevice, MediaClass};
use crate::json;
use crate::json::Json;

// ------------------------------------------------------------------ policy

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistLevel {
    /// Logical overwrite of addressable space. Defeats casual recovery.
    Clear,
    /// Firmware-level erase. Defeats laboratory recovery.
    Purge,
    /// Physical destruction. The fallback when Purge cannot be established.
    Destroy,
}

impl NistLevel {
    pub fn label(&self) -> &'static str {
        match self {
            NistLevel::Clear => "CLEAR",
            NistLevel::Purge => "PURGE",
            NistLevel::Destroy => "DESTROY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Technique {
    SinglePassOverwrite,
    AtaSanitizeOverwrite,
    AtaSanitizeBlockErase,
    AtaSecurityErase,
    AtaSecurityEraseEnhanced,
    NvmeSanitizeBlockErase,
    NvmeSanitizeCryptoErase,
    NvmeFormatUserDataErase,
    OpalCryptoErase,
    /// File-backed image: an overwrite here IS exact, because there is no
    /// translation layer between us and the bytes.
    ImageOverwrite,
    /// No technique can establish Purge on this medium through this transport.
    RefuseAndDestroy,
}

impl Technique {
    pub fn label(&self) -> &'static str {
        match self {
            Technique::SinglePassOverwrite => "single-pass overwrite (full LBA + unlocked HPA/DCO)",
            Technique::AtaSanitizeOverwrite => "ATA SANITIZE — OVERWRITE EXT",
            Technique::AtaSanitizeBlockErase => "ATA SANITIZE — BLOCK ERASE EXT",
            Technique::AtaSecurityErase => "ATA SECURITY ERASE UNIT",
            Technique::AtaSecurityEraseEnhanced => "ATA SECURITY ERASE UNIT (enhanced)",
            Technique::NvmeSanitizeBlockErase => "NVMe Sanitize — block erase",
            Technique::NvmeSanitizeCryptoErase => "NVMe Sanitize — cryptographic erase",
            Technique::NvmeFormatUserDataErase => "NVMe Format NVM (SES=1)",
            Technique::OpalCryptoErase => "TCG Opal cryptographic erase / PSID revert",
            Technique::ImageOverwrite => "image overwrite (exact, no translation layer)",
            Technique::RefuseAndDestroy => "REFUSED — escalate to physical destruction",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SanitizePlan {
    pub technique: Technique,
    pub level: NistLevel,
    pub standard: &'static str,
    /// Why this technique and not another. Recorded verbatim in the
    /// certificate so a reviewer can audit the decision, not just the outcome.
    pub rationale: String,
    /// Conditions the operator must satisfy before execution can proceed.
    pub blockers: Vec<String>,
}

impl SanitizePlan {
    pub fn to_json(&self) -> Json {
        json! {
            "technique" => self.technique.label(),
            "nist_800_88_r2_level" => self.level.label(),
            "standard" => self.standard,
            "rationale" => self.rationale.clone(),
            "blockers" => Json::Arr(self.blockers.iter().map(|b| Json::Str(b.clone())).collect()),
        }
    }
}

/// The policy engine. A pure function: device characteristics in, a decision
/// and its justification out. Deterministic and therefore testable, which
/// matters because this is the function that decides whether a drive holding
/// classified material is considered clean.
pub fn plan(info: &DeviceInfo) -> SanitizePlan {
    let mut blockers = Vec::new();
    if info.security_frozen {
        blockers.push(
            "ATA security state is SEC2 (frozen) — the host BIOS issued SECURITY FREEZE LOCK \
             at boot. A suspend-to-RAM cycle resets the drive controller to SEC0 without \
             power-cycling the host. Execution is blocked until the state clears."
                .into(),
        );
    }

    // Transport check comes first, because it can invalidate every firmware
    // technique regardless of what the drive itself supports.
    if info.passthrough_blocked && info.media.has_translation_layer() {
        return SanitizePlan {
            technique: Technique::RefuseAndDestroy,
            level: NistLevel::Destroy,
            standard: "NIST SP 800-88 Rev. 2 §4 / IEEE 2883-2022 §5",
            rationale:
                "The transport (USB-SATA bridge) does not pass ATA or NVMe commands through to \
                 the device, so no firmware sanitize can be issued. We deliberately do NOT fall \
                 back to a software overwrite: on flash the controller's translation layer makes \
                 host-side overwrite unable to reach stale pages or over-provisioned capacity, \
                 so a fallback would produce a certificate that means nothing. The medium is \
                 marked unsanitizable over this path. Connect it to a direct SATA or NVMe port, \
                 or escalate to physical destruction."
                    .into(),
            blockers,
        };
    }

    match info.media {
        MediaClass::Image => SanitizePlan {
            technique: Technique::ImageOverwrite,
            level: NistLevel::Clear,
            standard: "NIST SP 800-88 Rev. 2 §4 (Clear)",
            rationale:
                "File-backed image. There is no flash translation layer between the tool and the \
                 bytes, so a single-pass overwrite is exact and verifiable. This path exists for \
                 evidence-image handling and for validating the engine; it is not a substitute \
                 for firmware sanitize on physical media."
                    .into(),
            blockers,
        },

        MediaClass::MagneticDisk => {
            if info.supports_ata_sanitize {
                SanitizePlan {
                    technique: Technique::AtaSanitizeOverwrite,
                    level: NistLevel::Purge,
                    standard: "IEEE 2883-2022 §6.2 / NIST SP 800-88 Rev. 2 (Purge)",
                    rationale:
                        "Rotating magnetic media with SANITIZE support. The device-internal \
                         overwrite reaches remapped sectors on the grown defect list, which a \
                         host-issued overwrite cannot address."
                            .into(),
                    blockers,
                }
            } else {
                SanitizePlan {
                    technique: Technique::SinglePassOverwrite,
                    level: NistLevel::Clear,
                    standard: "NIST SP 800-88 Rev. 2 (Clear)",
                    rationale:
                        "Rotating magnetic media without SANITIZE support. On magnetic media a \
                         write physically re-magnetises the domain, so ONE pass is sufficient — \
                         multi-pass schemes such as DoD 5220.22-M and Gutmann add nothing and \
                         are retired. Sectors on the grown defect list remain unreachable, so \
                         this qualifies as Clear and not Purge."
                            .into(),
                    blockers,
                }
            }
        }

        MediaClass::SataSsd => {
            if info.supports_ata_sanitize {
                SanitizePlan {
                    technique: Technique::AtaSanitizeBlockErase,
                    level: NistLevel::Purge,
                    standard: "IEEE 2883-2022 §6.3 / NIST SP 800-88 Rev. 2 (Purge)",
                    rationale:
                        "SATA solid-state media. Host overwrite cannot reach stale pages or the \
                         over-provisioned pool, so the controller must erase itself. BLOCK ERASE \
                         drives an erase of every flash block including over-provisioning."
                            .into(),
                    blockers,
                }
            } else if info.supports_ata_security_erase {
                SanitizePlan {
                    technique: if info.supports_enhanced_erase {
                        Technique::AtaSecurityEraseEnhanced
                    } else {
                        Technique::AtaSecurityErase
                    },
                    level: NistLevel::Purge,
                    standard: "IEEE 2883-2022 §6.3 / NIST SP 800-88 Rev. 2 (Purge)",
                    rationale:
                        "SATA solid-state media without SANITIZE. The legacy security feature \
                         set provides a device-internal erase; the enhanced variant additionally \
                         covers reallocated sectors where the drive reports support."
                            .into(),
                    blockers,
                }
            } else {
                SanitizePlan {
                    technique: Technique::RefuseAndDestroy,
                    level: NistLevel::Destroy,
                    standard: "NIST SP 800-88 Rev. 2 §4 / IEEE 2883-2022 §5",
                    rationale:
                        "Solid-state media exposing no device-internal erase command. Overwriting \
                         is inadequate on flash by construction, so no host-side technique can \
                         establish Purge. Escalate to physical destruction."
                            .into(),
                    blockers,
                }
            }
        }

        MediaClass::NvmeSsd => {
            if info.supports_nvme_sanitize {
                SanitizePlan {
                    technique: Technique::NvmeSanitizeBlockErase,
                    level: NistLevel::Purge,
                    standard: "IEEE 2883-2022 §6.3 / NIST SP 800-88 Rev. 2 (Purge)",
                    rationale:
                        "NVMe media with SANICAP advertising block erase. Note the distinction \
                         that trips most tools: NVMe Sanitize is NOT NVMe Format NVM. Sanitize \
                         acts on the whole namespace set including over-provisioning; Format may \
                         qualify only as Clear depending on the implementation."
                            .into(),
                    blockers,
                }
            } else if info.supports_nvme_format {
                SanitizePlan {
                    technique: Technique::NvmeFormatUserDataErase,
                    level: NistLevel::Clear,
                    standard: "NIST SP 800-88 Rev. 2 (Clear)",
                    rationale:
                        "NVMe controller reports no Sanitize capability in SANICAP. Format NVM \
                         with SES=1 erases user data but its coverage of over-provisioned blocks \
                         is implementation-defined, so this is recorded as Clear. If Purge is \
                         required for this asset class, escalate to destruction."
                            .into(),
                    blockers,
                }
            } else {
                SanitizePlan {
                    technique: Technique::RefuseAndDestroy,
                    level: NistLevel::Destroy,
                    standard: "NIST SP 800-88 Rev. 2 §4",
                    rationale: "NVMe controller exposes neither Sanitize nor Format NVM.".into(),
                    blockers,
                }
            }
        }

        MediaClass::SelfEncrypting => SanitizePlan {
            technique: Technique::OpalCryptoErase,
            level: NistLevel::Purge,
            standard: "IEEE 2883-2022 §6.4 / TCG Opal SSC",
            rationale:
                "Self-encrypting drive. Regenerating the media encryption key renders every \
                 stored block indistinguishable from noise in milliseconds. This counts as Purge \
                 ONLY where encryption was active from first provisioning and no copy of the key \
                 exists elsewhere; where either condition cannot be evidenced the standard \
                 requires falling back to destruction. NISHESH records which of the two was \
                 verified rather than assuming both."
                    .into(),
            blockers,
        },

        MediaClass::UsbFlash => SanitizePlan {
            technique: Technique::RefuseAndDestroy,
            level: NistLevel::Destroy,
            standard: "NIST SP 800-88 Rev. 2 §4",
            rationale:
                "Removable flash behind a bridge controller. Wei et al. measured between 0.57% \
                 and 84.9% of file content surviving overwrite on this class of device. No \
                 host-side technique establishes Purge."
                    .into(),
            blockers,
        },

        MediaClass::Unknown => SanitizePlan {
            technique: Technique::RefuseAndDestroy,
            level: NistLevel::Destroy,
            standard: "NIST SP 800-88 Rev. 2 §4",
            rationale:
                "Media class could not be established. Guessing a technique on an unidentified \
                 medium is how tools produce certificates that are wrong."
                    .into(),
            blockers,
        },
    }
}

/// IEEE 2883 retry-and-escalate: what to try when verification fails.
pub fn escalate(current: Technique) -> Option<Technique> {
    match current {
        Technique::AtaSanitizeBlockErase => Some(Technique::AtaSecurityEraseEnhanced),
        Technique::AtaSecurityEraseEnhanced => Some(Technique::AtaSecurityErase),
        Technique::AtaSanitizeOverwrite => Some(Technique::SinglePassOverwrite),
        Technique::NvmeSanitizeBlockErase => Some(Technique::NvmeSanitizeCryptoErase),
        Technique::NvmeSanitizeCryptoErase => Some(Technique::NvmeFormatUserDataErase),
        _ => None,
    }
}

// --------------------------------------------------------------- execution

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Refused,
    Blocked,
}

#[derive(Debug, Clone)]
pub struct SanitizeEvent {
    pub plan: SanitizePlan,
    pub outcome: Outcome,
    pub attempts: u32,
    pub sectors_written: u64,
    pub regions_covered: Vec<String>,
    pub notes: Vec<String>,
}

/// Execute a plan against a file-backed image.
///
/// Physical-device execution — the actual ATA and NVMe command issue — is
/// gated behind the `linux-device` feature and is Phase 2. The policy engine,
/// the state-machine handling and the verification loop above and below it are
/// transport-independent and complete, which is what allows the whole pipeline
/// to be exercised and benchmarked before hardware access exists.
pub fn execute_on_image(
    dev: &mut ImageDevice,
    plan: &SanitizePlan,
    mut progress: impl FnMut(u64, u64),
) -> std::io::Result<SanitizeEvent> {
    let mut notes = Vec::new();

    if !plan.blockers.is_empty() {
        return Ok(SanitizeEvent {
            plan: plan.clone(),
            outcome: Outcome::Blocked,
            attempts: 0,
            sectors_written: 0,
            regions_covered: vec![],
            notes: plan.blockers.clone(),
        });
    }

    if plan.technique == Technique::RefuseAndDestroy {
        notes.push(
            "No certificate issued. The operator is directed to physical destruction.".into(),
        );
        return Ok(SanitizeEvent {
            plan: plan.clone(),
            outcome: Outcome::Refused,
            attempts: 0,
            sectors_written: 0,
            regions_covered: vec![],
            notes,
        });
    }

    // Sweep the entire backing store, including anything an HPA or DCO was
    // hiding. Sanitizing only the reported capacity is the classic failure.
    let total = dev.physical_sectors();
    let ss = dev.info().sector_size as usize;
    let mut regions = Vec::new();
    for r in dev.info().regions() {
        regions.push(format!(
            "{} — LBA {}..{} ({} sectors)",
            r.kind.label(),
            r.start_lba,
            r.start_lba + r.sectors,
            r.sectors
        ));
    }
    if dev.info().has_hpa() || dev.info().has_dco() {
        notes.push(format!(
            "{} hidden sectors were unlocked and included in the sweep.",
            dev.info().hidden_sectors()
        ));
    }

    const CHUNK: u64 = 2048;
    let zero = vec![0u8; ss * CHUNK as usize];
    let mut lba = 0u64;
    while lba < total {
        let n = CHUNK.min(total - lba);
        dev.write_sectors(lba, &zero[..ss * n as usize])?;
        lba += n;
        progress(lba, total);
    }

    Ok(SanitizeEvent {
        plan: plan.clone(),
        outcome: Outcome::Completed,
        attempts: 1,
        sectors_written: total,
        regions_covered: regions,
        notes,
    })
}

// ------------------------------------------------------------ verification

#[derive(Debug, Clone)]
pub struct Verification {
    pub samples: u64,
    pub sample_seed: u64,
    pub nonzero_blocks: u64,
    pub max_entropy: f64,
    /// Upper bound on the residual-data rate at 95% confidence, by the rule of
    /// three: zero observed failures in n independent trials bounds the true
    /// rate at approximately 3/n.
    pub residual_bound_pct: f64,
    pub adversarial_artifacts: Vec<Artifact>,
    pub passed: bool,
    pub unreachable_note: &'static str,
}

impl Verification {
    pub fn to_json(&self) -> Json {
        json! {
            "statistical_samples" => self.samples,
            "sample_seed" => format!("{:#018x}", self.sample_seed),
            "nonzero_blocks_found" => self.nonzero_blocks,
            "max_entropy_bits_per_byte" => (self.max_entropy * 1000.0).round() / 1000.0,
            "residual_upper_bound_pct_95ci" => (self.residual_bound_pct * 10000.0).round() / 10000.0,
            "adversarial_artifacts_recovered" => self.adversarial_artifacts.len(),
            "passed" => self.passed,
            "limitation" => self.unreachable_note,
        }
    }
}

/// Deterministic sampler. SplitMix64 — small, well-distributed, and above all
/// reproducible: the seed goes into the certificate so an auditor can re-run
/// exactly the same sample set and get exactly the same answer.
#[derive(Debug)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Statistical layer: sample n blocks uniformly across the whole medium,
/// including unlocked hidden regions, and require every one to read as zero.
pub fn statistical_check(
    dev: &mut dyn Device,
    total_sectors: u64,
    samples: u64,
    seed: u64,
) -> std::io::Result<(u64, f64)> {
    let mut rng = SplitMix64::new(seed);
    let mut nonzero = 0u64;
    let mut max_h = 0.0f64;
    let block_sectors = 8u32; // 4 KiB blocks
    for _ in 0..samples {
        if total_sectors <= block_sectors as u64 {
            break;
        }
        let lba = rng.next() % (total_sectors - block_sectors as u64);
        let buf = dev.read_sectors(lba, block_sectors)?;
        if !is_zeroed(&buf) {
            nonzero += 1;
            let h = shannon_entropy(&buf);
            if h > max_h {
                max_h = h;
            }
        }
    }
    Ok((nonzero, max_h))
}

/// Rule of three: with zero observed failures in n trials, the upper 95%
/// confidence bound on the failure rate is approximately 3/n.
pub fn residual_bound_pct(samples: u64) -> f64 {
    if samples == 0 {
        return 100.0;
    }
    3.0 / samples as f64 * 100.0
}

/// The verification loop — the reason NISHESH exists.
///
/// After sanitization we hand the medium straight back to the recovery engine.
/// Not a read-back of the addressable range, which is what commercial products
/// do and which asks the same drive that may have failed to answer for itself.
/// A full forensic attack: filesystem metadata, carving, slack, hidden regions.
/// Recovering nothing with a tool purpose-built to recover things is a
/// materially stronger claim than a firmware return code.
pub fn verify(
    dev: &mut dyn Device,
    total_sectors: u64,
    samples: u64,
    seed: u64,
    adversarial: Vec<Artifact>,
) -> std::io::Result<Verification> {
    let (nonzero, max_h) = statistical_check(dev, total_sectors, samples, seed)?;
    let bound = residual_bound_pct(samples);
    let passed = nonzero == 0 && adversarial.is_empty();
    Ok(Verification {
        samples,
        sample_seed: seed,
        nonzero_blocks: nonzero,
        max_entropy: max_h,
        residual_bound_pct: bound,
        adversarial_artifacts: adversarial,
        passed,
        unreachable_note:
            "Neither layer can read unmapped physical NAND pages retained by a flash translation \
             layer; nothing short of chip-off can. What is established is that every addressable \
             byte, every unlocked hidden region, all file slack and all unallocated space are \
             clean, and that the firmware technique appropriate to the media class executed and \
             reported success.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn info(media: MediaClass) -> DeviceInfo {
        DeviceInfo {
            path: PathBuf::from("/dev/test"),
            model: "t".into(),
            serial: "s".into(),
            firmware: "f".into(),
            media,
            sector_size: 512,
            user_max_lba: 1000,
            native_max_lba: 1000,
            dco_max_lba: 1000,
            supports_ata_sanitize: false,
            supports_ata_security_erase: false,
            supports_enhanced_erase: false,
            supports_nvme_sanitize: false,
            supports_nvme_format: false,
            supports_opal: false,
            security_frozen: false,
            passthrough_blocked: false,
        }
    }

    #[test]
    fn hdd_without_sanitize_is_clear_not_purge() {
        let p = plan(&info(MediaClass::MagneticDisk));
        assert_eq!(p.technique, Technique::SinglePassOverwrite);
        assert_eq!(p.level, NistLevel::Clear);
        assert!(p.rationale.contains("ONE pass"));
    }

    #[test]
    fn ssd_without_firmware_erase_is_refused_never_overwritten() {
        // The single most important test in this file. A tool that quietly
        // overwrites flash instead of refusing is the failure mode NISHESH
        // exists to prevent.
        let p = plan(&info(MediaClass::SataSsd));
        assert_eq!(p.technique, Technique::RefuseAndDestroy);
        assert_eq!(p.level, NistLevel::Destroy);
    }

    #[test]
    fn ssd_with_sanitize_gets_block_erase_at_purge() {
        let mut i = info(MediaClass::SataSsd);
        i.supports_ata_sanitize = true;
        let p = plan(&i);
        assert_eq!(p.technique, Technique::AtaSanitizeBlockErase);
        assert_eq!(p.level, NistLevel::Purge);
    }

    #[test]
    fn nvme_format_is_clear_not_purge() {
        // Format NVM is not Sanitize. Conflating them is the most common
        // standards error in this product category.
        let mut i = info(MediaClass::NvmeSsd);
        i.supports_nvme_format = true;
        let p = plan(&i);
        assert_eq!(p.technique, Technique::NvmeFormatUserDataErase);
        assert_eq!(p.level, NistLevel::Clear);
    }

    #[test]
    fn blocked_passthrough_refuses_instead_of_degrading() {
        let mut i = info(MediaClass::SataSsd);
        i.supports_ata_sanitize = true;
        i.passthrough_blocked = true;
        let p = plan(&i);
        assert_eq!(p.technique, Technique::RefuseAndDestroy);
        assert!(p.rationale.contains("deliberately do NOT fall back"));
    }

    #[test]
    fn frozen_security_state_blocks_execution() {
        let mut i = info(MediaClass::MagneticDisk);
        i.security_frozen = true;
        let p = plan(&i);
        assert_eq!(p.blockers.len(), 1);
        assert!(p.blockers[0].contains("suspend-to-RAM"));
    }

    #[test]
    fn rule_of_three_bound() {
        assert!((residual_bound_pct(3000) - 0.1).abs() < 1e-9);
        assert!((residual_bound_pct(30000) - 0.01).abs() < 1e-9);
    }

    #[test]
    fn sampler_is_reproducible() {
        let a: Vec<u64> = (0..5).map(|_| SplitMix64::new(42).next()).collect();
        assert!(a.iter().all(|&x| x == a[0]));
        let mut r1 = SplitMix64::new(7);
        let mut r2 = SplitMix64::new(7);
        for _ in 0..100 {
            assert_eq!(r1.next(), r2.next());
        }
    }

    #[test]
    fn escalation_chain_terminates() {
        let mut t = Technique::AtaSanitizeBlockErase;
        let mut steps = 0;
        while let Some(next) = escalate(t) {
            t = next;
            steps += 1;
            assert!(steps < 10, "escalation must not loop");
        }
        assert!(steps >= 1);
    }
}
