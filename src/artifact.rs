//! The uniform output record of the recovery engine, and the entropy analysis
//! that drives scan triage and wipe verification.

use crate::device::Region;
use crate::hash::hex;
use crate::json;
use crate::json::Json;

/// How an artifact was found. This matters forensically: a file recovered from
/// an intact MFT record carries its original name and timestamps and is worth
/// far more in a report than an unnamed blob pulled out by signature match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Filesystem metadata that still describes the file.
    MftRecord,
    /// Metadata reconstructed from a journal's pre-change image.
    JournalReplay,
    /// Directory entry marked deleted (FAT family).
    DirEntry,
    /// Signature match over raw bytes; no metadata.
    Carve,
    /// Content in the unused tail of an allocated cluster.
    Slack,
}

impl Method {
    pub fn label(&self) -> &'static str {
        match self {
            Method::MftRecord => "mft-record",
            Method::JournalReplay => "journal-replay",
            Method::DirEntry => "dir-entry",
            Method::Carve => "carve",
            Method::Slack => "slack",
        }
    }

    /// Whether this method preserves the original filename and timestamps.
    pub fn carries_metadata(&self) -> bool {
        matches!(
            self,
            Method::MftRecord | Method::JournalReplay | Method::DirEntry
        )
    }
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub offset: u64,
    pub size: u64,
    pub name: Option<String>,
    pub method: Method,
    /// 0.0–1.0. Metadata-backed recoveries score high; carved fragments whose
    /// validator did not run score low. Never rounded up for presentation.
    pub confidence: f32,
    pub sha256: [u8; 32],
    pub region: Region,
    pub file_type: Option<&'static str>,
    /// Set when a format-native validator confirmed the extracted bytes really
    /// are a well-formed object of that type — the reassembly oracle.
    pub validated: bool,
}

impl Artifact {
    pub fn to_json(&self) -> Json {
        json! {
            "offset" => self.offset,
            "size" => self.size,
            "name" => self.name.clone().unwrap_or_else(|| "<unnamed>".into()),
            "method" => self.method.label(),
            "confidence" => (self.confidence as f64 * 100.0).round() / 100.0,
            "sha256" => hex(&self.sha256),
            "region" => self.region.label(),
            "type" => self.file_type.unwrap_or("unknown"),
            "validated" => self.validated,
        }
    }

    pub fn short_hash(&self) -> String {
        hex(&self.sha256[..8])
    }
}

/// Shannon entropy in bits per byte over the given block. Maximum is 8.0.
///
/// Three uses in NISHESH:
///   * scan triage — skip runs of zeros, focus on regions with structure
///   * encryption detection — a high-entropy region with no recognisable
///     filesystem is probably encrypted, which changes the recovery approach
///   * wipe verification — after sanitization every sampled block must read
///     as zero; anything with entropy above the floor is residual data
///
/// Honest limitation, stated because overclaiming here is how tools mislead:
/// entropy cannot distinguish AES ciphertext from a hardware random stream.
/// It tells you a block is not obviously structured. Nothing more.
pub fn shannon_entropy(block: &[u8]) -> f64 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let len = block.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockClass {
    /// All one byte value. Either never written or successfully wiped.
    Uniform,
    /// Recognisable structure — text, code, filesystem metadata.
    Structured,
    /// Statistically indistinguishable from random. Encrypted or compressed.
    HighEntropy,
}

pub fn classify(block: &[u8]) -> BlockClass {
    let h = shannon_entropy(block);
    if h < 0.5 {
        BlockClass::Uniform
    } else if h > 7.5 {
        BlockClass::HighEntropy
    } else {
        BlockClass::Structured
    }
}

/// Is this block entirely zero? The strictest wipe check, and the one the
/// verifier uses — not an entropy threshold, an exact test.
pub fn is_zeroed(block: &[u8]) -> bool {
    block.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_no_entropy() {
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
        assert_eq!(classify(&[0u8; 4096]), BlockClass::Uniform);
        assert!(is_zeroed(&[0u8; 4096]));
    }

    #[test]
    fn uniform_byte_distribution_saturates() {
        let mut block = Vec::with_capacity(4096);
        for i in 0..4096 {
            block.push((i % 256) as u8);
        }
        assert!((shannon_entropy(&block) - 8.0).abs() < 1e-9);
        assert_eq!(classify(&block), BlockClass::HighEntropy);
    }

    #[test]
    fn english_text_lands_in_the_structured_band() {
        let text = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs. \
                     How vexingly quick daft zebras jump!";
        let h = shannon_entropy(text);
        assert!(h > 3.0 && h < 6.0, "entropy was {h}");
        assert_eq!(classify(text), BlockClass::Structured);
    }

    #[test]
    fn a_single_nonzero_byte_fails_the_wipe_check() {
        let mut b = vec![0u8; 4096];
        b[2000] = 1;
        assert!(!is_zeroed(&b));
    }
}
