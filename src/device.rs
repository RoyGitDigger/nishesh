//! Device access layer (module M1).
//!
//! The single most important design decision in NISHESH lives here: every
//! downstream module — the recovery engine, the sanitizer, the verifier —
//! talks to storage through one narrow trait. A real block device and a disk
//! image satisfy it identically.
//!
//! Two consequences:
//!   * the recovery engine can be developed and benchmarked with no hardware,
//!     against synthetic images with known ground truth
//!   * the sanitizer can hand a wiped device to the recovery engine for
//!     verification without either module knowing which backend it holds
//!
//! The capacity model is deliberately three-valued. Drives lie about their own
//! size, and a tool that believes the reported capacity sanitizes a subset of
//! the platter while reporting success.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_SECTOR: u32 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaClass {
    /// Rotating magnetic media. Overwrite is a real physical operation here.
    MagneticDisk,
    /// SATA/SAS solid state. Overwrite is theatre; only firmware can erase.
    SataSsd,
    /// NVMe solid state.
    NvmeSsd,
    /// Removable flash behind a bridge chip. Passthrough is frequently blocked.
    UsbFlash,
    /// Self-encrypting drive. Crypto-erase is available if the MEK is live.
    SelfEncrypting,
    /// A file-backed image. Not a physical medium; overwrite is exact.
    Image,
    Unknown,
}

impl MediaClass {
    pub fn label(&self) -> &'static str {
        match self {
            MediaClass::MagneticDisk => "magnetic disk (HDD)",
            MediaClass::SataSsd => "SATA solid-state",
            MediaClass::NvmeSsd => "NVMe solid-state",
            MediaClass::UsbFlash => "USB flash",
            MediaClass::SelfEncrypting => "self-encrypting drive",
            MediaClass::Image => "disk image (file-backed)",
            MediaClass::Unknown => "unknown",
        }
    }

    /// Does this medium keep a private logical-to-physical map that makes
    /// host-side overwrite unreliable? This one predicate drives the whole
    /// sanitization policy engine.
    pub fn has_translation_layer(&self) -> bool {
        matches!(
            self,
            MediaClass::SataSsd | MediaClass::NvmeSsd | MediaClass::UsbFlash
        )
    }
}

/// A span of the medium, classified by whether the host can address it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Visible to the operating system.
    Addressable,
    /// Host Protected Area — hidden by a SET MAX ADDRESS command.
    Hpa,
    /// Device Configuration Overlay — hidden at the factory-config level.
    Dco,
    /// Physically present, permanently unaddressable: remapped sectors,
    /// over-provisioned flash. Recorded so the certificate can state plainly
    /// what was and was not reachable.
    Unreachable,
}

impl Region {
    pub fn label(&self) -> &'static str {
        match self {
            Region::Addressable => "addressable",
            Region::Hpa => "HPA (hidden)",
            Region::Dco => "DCO (hidden)",
            Region::Unreachable => "unreachable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegionSpan {
    pub kind: Region,
    pub start_lba: u64,
    pub sectors: u64,
}

/// Everything the policy engine needs to decide how to sanitize a medium.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: PathBuf,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub media: MediaClass,
    pub sector_size: u32,

    /// Sectors the OS is permitted to address.
    pub user_max_lba: u64,
    /// Sectors the drive reports as its native maximum. Greater than
    /// `user_max_lba` means a Host Protected Area is hiding capacity.
    pub native_max_lba: u64,
    /// Factory configuration maximum. Greater than `native_max_lba` means a
    /// Device Configuration Overlay is hiding capacity.
    pub dco_max_lba: u64,

    pub supports_ata_sanitize: bool,
    pub supports_ata_security_erase: bool,
    pub supports_enhanced_erase: bool,
    pub supports_nvme_sanitize: bool,
    pub supports_nvme_format: bool,
    pub supports_opal: bool,
    /// Set when the ATA security state machine is in SEC2 (frozen) and an
    /// erase command would be rejected until a suspend/resume cycle.
    pub security_frozen: bool,
    /// True when the transport is known to swallow ATA/NVMe passthrough —
    /// most USB-SATA bridge chips. This does NOT cause a fallback to software
    /// overwrite; it causes a refusal. See sanitize::policy.
    pub passthrough_blocked: bool,
}

impl DeviceInfo {
    pub fn total_bytes(&self) -> u64 {
        self.user_max_lba.saturating_mul(self.sector_size as u64)
    }

    pub fn has_hpa(&self) -> bool {
        self.native_max_lba > self.user_max_lba
    }

    pub fn has_dco(&self) -> bool {
        self.dco_max_lba > self.native_max_lba
    }

    pub fn hidden_sectors(&self) -> u64 {
        self.dco_max_lba.saturating_sub(self.user_max_lba)
    }

    pub fn regions(&self) -> Vec<RegionSpan> {
        let mut v = vec![RegionSpan {
            kind: Region::Addressable,
            start_lba: 0,
            sectors: self.user_max_lba,
        }];
        if self.has_hpa() {
            v.push(RegionSpan {
                kind: Region::Hpa,
                start_lba: self.user_max_lba,
                sectors: self.native_max_lba - self.user_max_lba,
            });
        }
        if self.has_dco() {
            v.push(RegionSpan {
                kind: Region::Dco,
                start_lba: self.native_max_lba,
                sectors: self.dco_max_lba - self.native_max_lba,
            });
        }
        v
    }
}

/// The contract. Implemented by `ImageDevice` here and by `LinuxBlockDevice`
/// in Phase 2; nothing downstream needs to know which it holds.
pub trait Device {
    fn info(&self) -> &DeviceInfo;

    /// Read `count` sectors starting at `lba`. Short reads at the end of the
    /// medium are zero-filled so callers never see a partial buffer.
    fn read_sectors(&mut self, lba: u64, count: u32) -> std::io::Result<Vec<u8>>;

    /// Write sectors. Returns `PermissionDenied` when the device is
    /// write-blocked, which is the default for anything opened for analysis.
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> std::io::Result<()>;

    fn is_write_blocked(&self) -> bool;

    /// Read an arbitrary byte range, crossing sector boundaries.
    fn read_at(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let ss = self.info().sector_size as u64;
        let first = offset / ss;
        let skew = (offset % ss) as usize;
        let sectors = ((skew + len) as u64).div_ceil(ss) as u32;
        let buf = self.read_sectors(first, sectors)?;
        let end = (skew + len).min(buf.len());
        let mut out = buf[skew.min(buf.len())..end].to_vec();
        out.resize(len, 0);
        Ok(out)
    }
}

/// File-backed device. Used for evidence images, for the synthetic corpora the
/// benchmark harness generates, and for every unit test in the tree.
#[derive(Debug)]
pub struct ImageDevice {
    file: File,
    info: DeviceInfo,
    write_blocked: bool,
}

impl ImageDevice {
    /// Open read-only with software write blocking engaged. This is the only
    /// constructor the analysis paths use.
    pub fn open_readonly(path: &Path) -> std::io::Result<Self> {
        Self::open_inner(path, false)
    }

    /// Open writable. Reserved for the sanitizer and the corpus generator;
    /// both require an explicit operator confirmation upstream.
    pub fn open_writable(path: &Path) -> std::io::Result<Self> {
        Self::open_inner(path, true)
    }

    fn open_inner(path: &Path, writable: bool) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(writable).open(path)?;
        let len = file.metadata()?.len();
        let sector_size = DEFAULT_SECTOR;
        let sectors = len / sector_size as u64;
        let digest = short_id(path, len);
        Ok(ImageDevice {
            file,
            info: DeviceInfo {
                path: path.to_path_buf(),
                model: "NISHESH image backend".into(),
                serial: digest,
                firmware: "n/a".into(),
                media: MediaClass::Image,
                sector_size,
                user_max_lba: sectors,
                native_max_lba: sectors,
                dco_max_lba: sectors,
                supports_ata_sanitize: false,
                supports_ata_security_erase: false,
                supports_enhanced_erase: false,
                supports_nvme_sanitize: false,
                supports_nvme_format: false,
                supports_opal: false,
                security_frozen: false,
                passthrough_blocked: false,
            },
            write_blocked: !writable,
        })
    }

    /// Present the image as if it were a given class of physical medium, so the
    /// policy engine can be exercised and demonstrated without the hardware.
    /// The certificate records that the class was asserted rather than probed.
    pub fn simulate_media(&mut self, class: MediaClass) {
        self.info.media = class;
        match class {
            MediaClass::MagneticDisk => {
                self.info.supports_ata_security_erase = true;
                self.info.supports_ata_sanitize = true;
                self.info.model = "SIMULATED magnetic disk".into();
            }
            MediaClass::SataSsd => {
                self.info.supports_ata_sanitize = true;
                self.info.supports_ata_security_erase = true;
                self.info.supports_enhanced_erase = true;
                self.info.model = "SIMULATED SATA SSD".into();
            }
            MediaClass::NvmeSsd => {
                self.info.supports_nvme_sanitize = true;
                self.info.supports_nvme_format = true;
                self.info.model = "SIMULATED NVMe SSD".into();
            }
            MediaClass::UsbFlash => {
                self.info.passthrough_blocked = true;
                self.info.model = "SIMULATED USB flash behind a bridge".into();
            }
            MediaClass::SelfEncrypting => {
                self.info.supports_opal = true;
                self.info.model = "SIMULATED Opal SED".into();
            }
            _ => {}
        }
    }

    /// Simulate hidden capacity so the HPA/DCO detection path is demonstrable
    /// on a file. On real hardware these numbers come from IDENTIFY DEVICE and
    /// DEVICE CONFIGURATION IDENTIFY.
    pub fn simulate_hidden(&mut self, hpa_sectors: u64, dco_sectors: u64) {
        let visible = self
            .info
            .user_max_lba
            .saturating_sub(hpa_sectors + dco_sectors);
        self.info.user_max_lba = visible;
        self.info.native_max_lba = visible + hpa_sectors;
        self.info.dco_max_lba = visible + hpa_sectors + dco_sectors;
    }

    pub fn set_frozen(&mut self, frozen: bool) {
        self.info.security_frozen = frozen;
    }

    /// Total sectors physically present in the backing file, ignoring any
    /// simulated hiding. The verifier needs this to prove it swept the
    /// unlocked regions too.
    pub fn physical_sectors(&self) -> u64 {
        self.info.dco_max_lba
    }
}

impl Device for ImageDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_sectors(&mut self, lba: u64, count: u32) -> std::io::Result<Vec<u8>> {
        let ss = self.info.sector_size as usize;
        let mut buf = vec![0u8; ss * count as usize];
        self.file.seek(SeekFrom::Start(lba * ss as u64))?;
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.file.read(&mut buf[filled..]) {
                Ok(0) => break, // short read at end of medium; remainder stays zero
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(buf)
    }

    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> std::io::Result<()> {
        if self.write_blocked {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "device is write-blocked",
            ));
        }
        let ss = self.info.sector_size as u64;
        self.file.seek(SeekFrom::Start(lba * ss))?;
        self.file.write_all(data)?;
        Ok(())
    }

    fn is_write_blocked(&self) -> bool {
        self.write_blocked
    }
}

fn short_id(path: &Path, len: u64) -> String {
    let mut h = crate::hash::Sha256::new();
    h.update(path.to_string_lossy().as_bytes());
    h.update(&len.to_le_bytes());
    crate::hash::hex(&h.finalize()[..6]).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_image(bytes: &[u8]) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "nishesh-test-{}-{}.img",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let mut f = File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn read_at_crosses_sector_boundaries() {
        let mut data = vec![0u8; 2048];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let p = tmp_image(&data);
        let mut d = ImageDevice::open_readonly(&p).unwrap();
        let got = d.read_at(500, 100).unwrap();
        assert_eq!(got, data[500..600]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn write_blocking_is_enforced() {
        let p = tmp_image(&vec![0u8; 512]);
        let mut d = ImageDevice::open_readonly(&p).unwrap();
        assert!(d.is_write_blocked());
        let err = d.write_sectors(0, &[1u8; 512]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn hidden_capacity_is_reported() {
        let p = tmp_image(&vec![0u8; 512 * 100]);
        let mut d = ImageDevice::open_readonly(&p).unwrap();
        d.simulate_hidden(10, 5);
        assert!(d.info().has_hpa());
        assert!(d.info().has_dco());
        assert_eq!(d.info().hidden_sectors(), 15);
        assert_eq!(d.info().regions().len(), 3);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn translation_layer_predicate() {
        assert!(MediaClass::SataSsd.has_translation_layer());
        assert!(MediaClass::NvmeSsd.has_translation_layer());
        assert!(!MediaClass::MagneticDisk.has_translation_layer());
    }
}
