//! FAT12/16/32 on-disk structures — parser and image builder.
//!
//! Reference: Microsoft Extensible Firmware Initiative FAT32 File System
//! Specification 1.03, plus ECMA-107 for the shared BPB layout.
//!
//! Why FAT first, when NTFS is the forensically interesting one: FAT is small
//! enough to implement in both directions. Being able to *build* a filesystem
//! means the benchmark harness can generate corpora with exact ground truth —
//! every byte of every file known, every deletion deliberate — on any machine,
//! with no root, no loop devices and no external tooling. Every recovery-rate
//! number NISHESH publishes is checkable against a manifest produced here.
//!
//! What deletion does on FAT, and therefore what recovery can and cannot do:
//! the directory entry's first byte is overwritten with 0xE5 and the cluster
//! chain in the FAT is zeroed. The entry keeps its starting cluster, its size
//! and its timestamps. So the file's *location* survives, but the chain that
//! described its layout does not — which is why FAT recovery assumes contiguity
//! and why the first character of the name is unrecoverable. We report that
//! honestly rather than guessing a letter.

use crate::artifact::{Artifact, Method};
use crate::device::{Device, Region};
use crate::hash::sha256;

pub const DIR_ENTRY_SIZE: usize = 32;
pub const DELETED_MARKER: u8 = 0xE5;
pub const ATTR_LFN: u8 = 0x0F;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

impl FatKind {
    pub fn label(&self) -> &'static str {
        match self {
            FatKind::Fat12 => "FAT12",
            FatKind::Fat16 => "FAT16",
            FatKind::Fat32 => "FAT32",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FatBpb {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub root_entries: u32,
    pub total_sectors: u64,
    pub fat_size_sectors: u64,
    pub root_cluster: u32,
    pub kind: FatKind,
    pub volume_label: String,
}

impl FatBpb {
    pub fn parse(boot: &[u8]) -> Option<FatBpb> {
        if boot.len() < 512 || boot[510] != 0x55 || boot[511] != 0xAA {
            return None;
        }
        let bytes_per_sector = le16(boot, 0x0B) as u32;
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return None;
        }
        let sectors_per_cluster = boot[0x0D] as u32;
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return None;
        }
        let reserved_sectors = le16(boot, 0x0E) as u32;
        if reserved_sectors == 0 {
            return None;
        }
        let num_fats = boot[0x10] as u32;
        if num_fats == 0 || num_fats > 4 {
            return None;
        }
        let root_entries = le16(boot, 0x11) as u32;
        let total16 = le16(boot, 0x13) as u64;
        let total32 = le32(boot, 0x20) as u64;
        let total_sectors = if total16 != 0 { total16 } else { total32 };
        let fat16_size = le16(boot, 0x16) as u64;
        let fat_size_sectors = if fat16_size != 0 {
            fat16_size
        } else {
            le32(boot, 0x24) as u64
        };
        if total_sectors == 0 || fat_size_sectors == 0 {
            return None;
        }

        // Cluster count decides the FAT width. This is the rule from the
        // Microsoft specification and it is the *only* correct way to tell
        // FAT12/16/32 apart — the filesystem-type string is advisory and is
        // routinely wrong on real media.
        let root_dir_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
        let data_sectors = total_sectors
            .saturating_sub(reserved_sectors as u64)
            .saturating_sub(num_fats as u64 * fat_size_sectors)
            .saturating_sub(root_dir_sectors as u64);
        let cluster_count = data_sectors / sectors_per_cluster as u64;
        let kind = if cluster_count < 4085 {
            FatKind::Fat12
        } else if cluster_count < 65525 {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        };

        let label_off = if kind == FatKind::Fat32 { 0x47 } else { 0x2B };
        let volume_label = String::from_utf8_lossy(&boot[label_off..label_off + 11])
            .trim_end()
            .to_string();

        Some(FatBpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entries,
            total_sectors,
            fat_size_sectors,
            root_cluster: if kind == FatKind::Fat32 {
                le32(boot, 0x2C)
            } else {
                0
            },
            kind,
            volume_label,
        })
    }

    pub fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    pub fn root_dir_sectors(&self) -> u64 {
        (self.root_entries * 32).div_ceil(self.bytes_per_sector) as u64
    }

    pub fn first_data_sector(&self) -> u64 {
        self.reserved_sectors as u64
            + self.num_fats as u64 * self.fat_size_sectors
            + self.root_dir_sectors()
    }

    pub fn root_dir_sector(&self) -> u64 {
        self.reserved_sectors as u64 + self.num_fats as u64 * self.fat_size_sectors
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u64 {
        self.first_data_sector() + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }

    pub fn cluster_count(&self) -> u64 {
        let data = self.total_sectors.saturating_sub(self.first_data_sector());
        data / self.sectors_per_cluster as u64
    }
}

/// One 32-byte directory entry, decoded.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub raw_offset: u64,
    pub name: String,
    pub deleted: bool,
    pub attr: u8,
    pub first_cluster: u32,
    pub size: u32,
}

impl DirEntry {
    fn parse(buf: &[u8], raw_offset: u64) -> Option<DirEntry> {
        if buf.len() < DIR_ENTRY_SIZE || buf[0] == 0x00 {
            return None;
        }
        let attr = buf[0x0B];
        if attr == ATTR_LFN || attr & ATTR_VOLUME_ID != 0 {
            return None;
        }
        let deleted = buf[0] == DELETED_MARKER;
        let mut base = String::new();
        // On a deleted entry the first character is genuinely gone — the 0xE5
        // overwrote it. We mark it rather than inventing a letter.
        for (i, &c) in buf[0..8].iter().enumerate() {
            if i == 0 && deleted {
                base.push('_');
                continue;
            }
            if c == b' ' {
                break;
            }
            base.push(c as char);
        }
        let mut ext = String::new();
        for &c in &buf[8..11] {
            if c == b' ' {
                break;
            }
            ext.push(c as char);
        }
        let name = if ext.is_empty() {
            base
        } else {
            format!("{base}.{ext}")
        };
        let first_cluster = ((le16(buf, 0x14) as u32) << 16) | le16(buf, 0x1A) as u32;
        Some(DirEntry {
            raw_offset,
            name,
            deleted,
            attr,
            first_cluster,
            size: le32(buf, 0x1C),
        })
    }

    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
}

pub struct FatVolume {
    pub bpb: FatBpb,
    pub partition_offset_sectors: u64,
}

impl FatVolume {
    /// Probe for a FAT volume at the given sector.
    pub fn probe(dev: &mut dyn Device, at_sector: u64) -> Option<FatVolume> {
        let boot = dev.read_sectors(at_sector, 1).ok()?;
        let bpb = FatBpb::parse(&boot)?;
        Some(FatVolume {
            bpb,
            partition_offset_sectors: at_sector,
        })
    }

    fn abs_sector(&self, s: u64) -> u64 {
        self.partition_offset_sectors + s
    }

    /// Read every directory entry in the fixed root directory (FAT12/16) or
    /// the root cluster chain (FAT32).
    pub fn read_root_entries(&self, dev: &mut dyn Device) -> std::io::Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        if self.bpb.kind == FatKind::Fat32 {
            let sec = self.bpb.cluster_to_sector(self.bpb.root_cluster);
            self.scan_dir_sectors(dev, sec, self.bpb.sectors_per_cluster as u64, &mut out)?;
        } else {
            self.scan_dir_sectors(
                dev,
                self.bpb.root_dir_sector(),
                self.bpb.root_dir_sectors(),
                &mut out,
            )?;
        }
        Ok(out)
    }

    fn scan_dir_sectors(
        &self,
        dev: &mut dyn Device,
        start_sector: u64,
        count: u64,
        out: &mut Vec<DirEntry>,
    ) -> std::io::Result<()> {
        let ss = self.bpb.bytes_per_sector as usize;
        for i in 0..count {
            let abs = self.abs_sector(start_sector + i);
            let buf = dev.read_sectors(abs, 1)?;
            for (j, chunk) in buf.chunks(DIR_ENTRY_SIZE).enumerate() {
                if chunk.len() < DIR_ENTRY_SIZE {
                    break;
                }
                let off = abs * ss as u64 + (j * DIR_ENTRY_SIZE) as u64;
                if let Some(e) = DirEntry::parse(chunk, off) {
                    out.push(e);
                }
            }
        }
        Ok(())
    }

    /// Recover every deleted file whose directory entry survives.
    ///
    /// The FAT chain is gone, so we read `size` bytes starting at the recorded
    /// first cluster and treat the file as contiguous. That assumption holds
    /// for the large majority of files on FAT media and fails loudly rather
    /// than silently: the extracted bytes go through the carve validators, and
    /// an artifact whose validator rejects it is reported with low confidence
    /// instead of being presented as a clean recovery.
    pub fn recover_deleted(&self, dev: &mut dyn Device) -> std::io::Result<Vec<Artifact>> {
        let entries = self.read_root_entries(dev)?;
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| e.deleted && !e.is_dir()) {
            if e.first_cluster < 2 || e.size == 0 {
                continue;
            }
            let start_sector = self.abs_sector(self.bpb.cluster_to_sector(e.first_cluster));
            let sectors = (e.size as u64).div_ceil(self.bpb.bytes_per_sector as u64);
            if sectors > 1 << 20 {
                continue; // implausible; corrupt entry
            }
            let buf = dev.read_sectors(start_sector, sectors as u32)?;
            let data = &buf[..(e.size as usize).min(buf.len())];
            let (file_type, validated) = crate::carve::identify_and_validate(data);
            out.push(Artifact {
                offset: start_sector * self.bpb.bytes_per_sector as u64,
                size: data.len() as u64,
                name: Some(e.name.clone()),
                method: Method::DirEntry,
                confidence: if validated { 0.95 } else { 0.55 },
                sha256: sha256(data),
                region: Region::Addressable,
                file_type,
                validated,
            });
        }
        Ok(out)
    }

    /// Extract file slack: the unused tail of the last cluster of every
    /// allocated file. This is internal fragmentation, which an operating
    /// systems course teaches as a space-efficiency problem. It is also a
    /// security problem, because that tail still holds whatever the previous
    /// occupant of the cluster left there, and no wiping tool touches it —
    /// the filesystem believes the cluster is in use.
    pub fn extract_slack(&self, dev: &mut dyn Device) -> std::io::Result<Vec<Artifact>> {
        let entries = self.read_root_entries(dev)?;
        let cluster_bytes = self.bpb.cluster_bytes();
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| !e.deleted && !e.is_dir()) {
            if e.size == 0 || e.first_cluster < 2 {
                continue;
            }
            let used_in_last = e.size as u64 % cluster_bytes;
            if used_in_last == 0 {
                continue; // exact multiple; no slack
            }
            let slack_len = cluster_bytes - used_in_last;
            let clusters_used = (e.size as u64).div_ceil(cluster_bytes);
            let last_cluster = e.first_cluster as u64 + clusters_used - 1;
            let sec = self.abs_sector(self.bpb.cluster_to_sector(last_cluster as u32));
            let base = sec * self.bpb.bytes_per_sector as u64;
            let slack_off = base + used_in_last;
            let data = dev.read_at(slack_off, slack_len as usize)?;
            if crate::artifact::is_zeroed(&data) {
                continue; // nothing left behind
            }
            out.push(Artifact {
                offset: slack_off,
                size: slack_len,
                name: Some(format!("slack-of:{}", e.name)),
                method: Method::Slack,
                confidence: 0.40,
                sha256: sha256(&data),
                region: Region::Addressable,
                file_type: None,
                validated: false,
            });
        }
        Ok(out)
    }
}

// ============================================================ image builder

/// Builds a spec-compliant FAT16 volume in a byte buffer, so corpora can be
/// produced deterministically on any machine without privileges.
#[derive(Debug)]
pub struct FatBuilder {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub total_sectors: u64,
    fat: Vec<u16>,
    root: Vec<[u8; DIR_ENTRY_SIZE]>,
    data: Vec<u8>,
    next_free_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    root_entries: u32,
    fat_size_sectors: u64,
}

impl FatBuilder {
    /// `target_bytes` is rounded to produce a cluster count inside the FAT16
    /// range (4085..65525), so the result is a valid FAT16 volume and not a
    /// malformed one that only our own parser accepts.
    pub fn new(target_bytes: u64) -> FatBuilder {
        let bytes_per_sector = 512u32;
        let sectors_per_cluster = 8u32; // 4 KiB clusters
        let cluster_bytes = (bytes_per_sector * sectors_per_cluster) as u64;
        let mut clusters = (target_bytes / cluster_bytes).max(4200);
        clusters = clusters.min(65_000);
        let reserved_sectors = 1u32;
        let num_fats = 2u32;
        let root_entries = 512u32;
        let root_dir_sectors = (root_entries * 32).div_ceil(bytes_per_sector) as u64;
        // Two bytes per FAT16 entry.
        let fat_size_sectors = ((clusters + 2) * 2).div_ceil(bytes_per_sector as u64);
        let total_sectors = reserved_sectors as u64
            + num_fats as u64 * fat_size_sectors
            + root_dir_sectors
            + clusters * sectors_per_cluster as u64;

        FatBuilder {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            fat: vec![0u16; (clusters + 2) as usize],
            root: Vec::new(),
            data: vec![0u8; (clusters * cluster_bytes) as usize],
            next_free_cluster: 2,
            reserved_sectors,
            num_fats,
            root_entries,
            fat_size_sectors,
        }
    }

    fn cluster_bytes(&self) -> usize {
        (self.bytes_per_sector * self.sectors_per_cluster) as usize
    }

    /// Add a file with an 8.3 name. Returns the first cluster it occupies.
    pub fn add_file(&mut self, name83: &str, content: &[u8]) -> u32 {
        let cb = self.cluster_bytes();
        let need = content.len().div_ceil(cb).max(1);
        let first = self.next_free_cluster;
        for i in 0..need {
            let c = first + i as u32;
            let off = (c as usize - 2) * cb;
            let chunk_start = i * cb;
            let chunk_end = ((i + 1) * cb).min(content.len());
            if chunk_start < content.len() {
                self.data[off..off + (chunk_end - chunk_start)]
                    .copy_from_slice(&content[chunk_start..chunk_end]);
            }
            self.fat[c as usize] = if i + 1 == need {
                0xFFFF
            } else {
                (c + 1) as u16
            };
        }
        self.next_free_cluster += need as u32;

        let mut e = [0u8; DIR_ENTRY_SIZE];
        write_83(&mut e[0..11], name83);
        e[0x0B] = 0x20; // archive
        e[0x14..0x16].copy_from_slice(&(((first >> 16) as u16).to_le_bytes()));
        e[0x1A..0x1C].copy_from_slice(&((first as u16).to_le_bytes()));
        e[0x1C..0x20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        self.root.push(e);
        first
    }

    /// Delete a file exactly the way the filesystem driver does: stamp 0xE5
    /// over the first name byte and release the cluster chain. The data itself
    /// is not touched, which is the entire reason recovery works.
    pub fn delete_file(&mut self, name83: &str) -> bool {
        let mut target = [0u8; 11];
        write_83(&mut target, name83);
        for e in self.root.iter_mut() {
            if e[0] != DELETED_MARKER && e[0..11] == target {
                let first = ((le16(e, 0x14) as u32) << 16) | le16(e, 0x1A) as u32;
                e[0] = DELETED_MARKER;
                let mut c = first;
                while c >= 2 && (c as usize) < self.fat.len() {
                    let next = self.fat[c as usize] as u32;
                    self.fat[c as usize] = 0;
                    if !(2..0xFFF8).contains(&next) {
                        break;
                    }
                    c = next;
                }
                return true;
            }
        }
        false
    }

    /// Write bytes into the tail of an allocated file's last cluster,
    /// simulating a previous occupant whose remains survive in file slack.
    pub fn plant_slack(&mut self, name83: &str, payload: &[u8]) -> bool {
        let mut target = [0u8; 11];
        write_83(&mut target, name83);
        let cb = self.cluster_bytes();
        for e in self.root.iter() {
            if e[0..11] == target {
                let first = ((le16(e, 0x14) as u32) << 16) | le16(e, 0x1A) as u32;
                let size = le32(e, 0x1C) as usize;
                let used_in_last = size % cb;
                if used_in_last == 0 {
                    return false;
                }
                let clusters_used = size.div_ceil(cb);
                let last = first as usize + clusters_used - 1;
                let off = (last - 2) * cb + used_in_last;
                let n = payload.len().min(cb - used_in_last);
                self.data[off..off + n].copy_from_slice(&payload[..n]);
                return true;
            }
        }
        false
    }

    pub fn build(&self) -> Vec<u8> {
        let ss = self.bytes_per_sector as usize;
        let root_dir_sectors = (self.root_entries * 32).div_ceil(self.bytes_per_sector) as usize;
        let mut img = vec![0u8; self.total_sectors as usize * ss];

        // ---- boot sector / BPB
        let b = &mut img[0..ss];
        b[0] = 0xEB;
        b[1] = 0x3C;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"NISHESH ");
        b[0x0B..0x0D].copy_from_slice(&(self.bytes_per_sector as u16).to_le_bytes());
        b[0x0D] = self.sectors_per_cluster as u8;
        b[0x0E..0x10].copy_from_slice(&(self.reserved_sectors as u16).to_le_bytes());
        b[0x10] = self.num_fats as u8;
        b[0x11..0x13].copy_from_slice(&(self.root_entries as u16).to_le_bytes());
        if self.total_sectors < 0x10000 {
            b[0x13..0x15].copy_from_slice(&(self.total_sectors as u16).to_le_bytes());
        } else {
            b[0x20..0x24].copy_from_slice(&(self.total_sectors as u32).to_le_bytes());
        }
        b[0x15] = 0xF8;
        b[0x16..0x18].copy_from_slice(&(self.fat_size_sectors as u16).to_le_bytes());
        b[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        b[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        b[0x24] = 0x80;
        b[0x26] = 0x29; // extended boot signature
        b[0x27..0x2B].copy_from_slice(&0x4E495348u32.to_le_bytes());
        b[0x2B..0x36].copy_from_slice(b"NISHESH EVD");
        b[0x36..0x3E].copy_from_slice(b"FAT16   ");
        b[510] = 0x55;
        b[511] = 0xAA;

        // ---- FATs (two identical copies, as the BPB declares)
        let mut fat_bytes = vec![0u8; self.fat_size_sectors as usize * ss];
        let mut fat = self.fat.clone();
        fat[0] = 0xFFF8;
        fat[1] = 0xFFFF;
        for (i, v) in fat.iter().enumerate() {
            let o = i * 2;
            if o + 2 <= fat_bytes.len() {
                fat_bytes[o..o + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
        for n in 0..self.num_fats as usize {
            let start = (self.reserved_sectors as usize + n * self.fat_size_sectors as usize) * ss;
            img[start..start + fat_bytes.len()].copy_from_slice(&fat_bytes);
        }

        // ---- root directory
        let root_start = (self.reserved_sectors as usize
            + self.num_fats as usize * self.fat_size_sectors as usize)
            * ss;
        for (i, e) in self.root.iter().enumerate() {
            let o = root_start + i * DIR_ENTRY_SIZE;
            img[o..o + DIR_ENTRY_SIZE].copy_from_slice(e);
        }

        // ---- data region
        let data_start = root_start + root_dir_sectors * ss;
        let n = self.data.len().min(img.len() - data_start);
        img[data_start..data_start + n].copy_from_slice(&self.data[..n]);
        img
    }
}

fn write_83(dst: &mut [u8], name: &str) {
    dst.iter_mut().for_each(|b| *b = b' ');
    let up = name.to_ascii_uppercase();
    let (base, ext) = match up.split_once('.') {
        Some((b, e)) => (b, e),
        None => (up.as_str(), ""),
    };
    for (i, c) in base.bytes().take(8).enumerate() {
        dst[i] = c;
    }
    for (i, c) in ext.bytes().take(3).enumerate() {
        dst[8 + i] = c;
    }
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_a_parseable_volume() {
        let mut b = FatBuilder::new(20 * 1024 * 1024);
        b.add_file("HELLO.TXT", b"hello world");
        let img = b.build();
        let bpb = FatBpb::parse(&img[..512]).expect("BPB should parse");
        assert_eq!(bpb.kind, FatKind::Fat16);
        assert_eq!(bpb.bytes_per_sector, 512);
        assert_eq!(bpb.sectors_per_cluster, 8);
        assert!(bpb.cluster_count() >= 4085 && bpb.cluster_count() < 65525);
    }

    #[test]
    fn deletion_preserves_the_data_and_the_start_cluster() {
        let content = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let mut b = FatBuilder::new(20 * 1024 * 1024);
        let first = b.add_file("SECRET.TXT", &content);
        assert!(b.delete_file("SECRET.TXT"));
        let img = b.build();

        let bpb = FatBpb::parse(&img[..512]).unwrap();
        let root_start = (bpb.root_dir_sector() * bpb.bytes_per_sector as u64) as usize;
        let e = &img[root_start..root_start + DIR_ENTRY_SIZE];
        assert_eq!(e[0], DELETED_MARKER, "entry must be stamped deleted");
        let recorded = ((le16(e, 0x14) as u32) << 16) | le16(e, 0x1A) as u32;
        assert_eq!(recorded, first, "start cluster survives deletion");

        let data_off = (bpb.cluster_to_sector(first) * bpb.bytes_per_sector as u64) as usize;
        assert_eq!(&img[data_off..data_off + content.len()], &content[..]);
    }

    #[test]
    fn slack_is_planted_beyond_the_declared_size() {
        let mut b = FatBuilder::new(20 * 1024 * 1024);
        b.add_file("REPORT.TXT", b"short file");
        assert!(b.plant_slack("REPORT.TXT", b"PREVIOUS TENANT DATA"));
        let img = b.build();
        let bpb = FatBpb::parse(&img[..512]).unwrap();
        let off = (bpb.cluster_to_sector(2) * 512) as usize + "short file".len();
        assert_eq!(&img[off..off + 20], b"PREVIOUS TENANT DATA");
    }
}
