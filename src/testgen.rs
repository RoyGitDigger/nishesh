//! Ground-truth corpus generation.
//!
//! Every recovery-rate number NISHESH publishes has to be checkable. That
//! means building the evidence ourselves: a filesystem whose every file is
//! known byte-for-byte, whose deletions are deliberate, and whose manifest
//! records the SHA-256 of each file before it was deleted. Recovery is then
//! graded by hash comparison, not by eyeballing output.
//!
//! The generated files are STRUCTURALLY VALID — a real JPEG marker chain, a
//! PNG with correct per-chunk CRC32s, a ZIP with a real central directory.
//! Synthetic blobs with the right first three bytes would let the carver
//! report successes its validators never actually confirmed, which would make
//! the benchmark worthless.
//!
//! On any machine, with no privileges, no loop devices and no external tools.

use crate::carve::crc32;
use crate::fat::FatBuilder;
use crate::hash::{hex, sha256};
use crate::json;
use crate::json::Json;

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
    pub deleted: bool,
    pub kind: &'static str,
}

#[derive(Debug)]
pub struct Corpus {
    pub image: Vec<u8>,
    pub entries: Vec<CorpusEntry>,
    pub slack_planted: Option<String>,
}

impl Corpus {
    pub fn manifest(&self) -> Json {
        let files: Vec<Json> = self
            .entries
            .iter()
            .map(|e| {
                json! {
                    "name" => e.name.clone(),
                    "size" => e.size,
                    "sha256" => e.sha256.clone(),
                    "deleted" => e.deleted,
                    "kind" => e.kind,
                }
            })
            .collect();
        json! {
            "generator" => "nishesh testgen",
            "filesystem" => "FAT16",
            "image_bytes" => self.image.len(),
            "total_files" => self.entries.len(),
            "deleted_files" => self.entries.iter().filter(|e| e.deleted).count(),
            "slack_payload_in" => self.slack_planted.clone().unwrap_or_default(),
            "files" => Json::Arr(files),
        }
    }

    pub fn expected_recoverable(&self) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.deleted).collect()
    }
}

/// Deterministic pseudo-random bytes, so a corpus regenerates identically.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

// ------------------------------------------------------- file constructors

/// A JPEG with a real marker chain: SOI, APP0/JFIF, DQT, SOF0, DHT, SOS,
/// entropy-coded data, EOI. Walks cleanly through the validator.
pub fn make_jpeg(seed: u64, payload_len: usize) -> Vec<u8> {
    let mut r = Rng(seed);
    let mut d = vec![0xFF, 0xD8]; // SOI

    // APP0 / JFIF
    let app0: [u8; 14] = [b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0];
    d.extend_from_slice(&[0xFF, 0xE0]);
    d.extend_from_slice(&((app0.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&app0);

    // DQT — 64-entry luminance table
    let mut dqt = vec![0u8];
    dqt.extend(std::iter::repeat(16u8).take(64));
    d.extend_from_slice(&[0xFF, 0xDB]);
    d.extend_from_slice(&((dqt.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&dqt);

    // SOF0 — baseline, 64x64, one component
    let sof: [u8; 9] = [8, 0, 64, 0, 64, 1, 1, 0x11, 0];
    d.extend_from_slice(&[0xFF, 0xC0]);
    d.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&sof);

    // DHT — minimal table
    let mut dht = vec![0x00u8];
    dht.extend(std::iter::repeat(0u8).take(16));
    dht[1] = 1;
    dht.push(0x00);
    d.extend_from_slice(&[0xFF, 0xC4]);
    d.extend_from_slice(&((dht.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&dht);

    // SOS
    let sos: [u8; 6] = [1, 1, 0x00, 0, 63, 0];
    d.extend_from_slice(&[0xFF, 0xDA]);
    d.extend_from_slice(&((sos.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&sos);

    // Entropy-coded payload, byte-stuffed so no stray FF is read as a marker.
    for b in r.bytes(payload_len) {
        d.push(b);
        if b == 0xFF {
            d.push(0x00);
        }
    }
    d.extend_from_slice(&[0xFF, 0xD9]); // EOI
    d
}

/// A PNG with IHDR, IDAT and IEND, each chunk carrying a correct CRC32. The
/// carver's validator checks every one of them.
pub fn make_png(seed: u64, payload_len: usize) -> Vec<u8> {
    let mut r = Rng(seed);
    let mut d = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    let chunk = |d: &mut Vec<u8>, ctype: &[u8; 4], body: &[u8]| {
        d.extend_from_slice(&(body.len() as u32).to_be_bytes());
        d.extend_from_slice(ctype);
        d.extend_from_slice(body);
        let mut crc_in = ctype.to_vec();
        crc_in.extend_from_slice(body);
        d.extend_from_slice(&crc32(&crc_in).to_be_bytes());
    };

    let ihdr: [u8; 13] = [0, 0, 0, 32, 0, 0, 0, 32, 8, 2, 0, 0, 0];
    chunk(&mut d, b"IHDR", &ihdr);
    chunk(&mut d, b"IDAT", &r.bytes(payload_len));
    chunk(&mut d, b"IEND", &[]);
    d
}

/// A ZIP with one stored (uncompressed) member, a real central directory and
/// an EOCD whose offsets point where they claim to.
pub fn make_zip(name: &str, body: &[u8]) -> Vec<u8> {
    let crc = crc32(body);
    let n = name.as_bytes();
    let mut d = Vec::new();

    // local file header
    d.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    d.extend_from_slice(&20u16.to_le_bytes()); // version needed
    d.extend_from_slice(&0u16.to_le_bytes()); // flags
    d.extend_from_slice(&0u16.to_le_bytes()); // stored
    d.extend_from_slice(&0u16.to_le_bytes()); // time
    d.extend_from_slice(&0u16.to_le_bytes()); // date
    d.extend_from_slice(&crc.to_le_bytes());
    d.extend_from_slice(&(body.len() as u32).to_le_bytes());
    d.extend_from_slice(&(body.len() as u32).to_le_bytes());
    d.extend_from_slice(&(n.len() as u16).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(n);
    d.extend_from_slice(body);

    // central directory
    let cd_off = d.len();
    d.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
    d.extend_from_slice(&20u16.to_le_bytes());
    d.extend_from_slice(&20u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&crc.to_le_bytes());
    d.extend_from_slice(&(body.len() as u32).to_le_bytes());
    d.extend_from_slice(&(body.len() as u32).to_le_bytes());
    d.extend_from_slice(&(n.len() as u16).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    d.extend_from_slice(n);
    let cd_size = d.len() - cd_off;

    // end of central directory
    d.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&(cd_size as u32).to_le_bytes());
    d.extend_from_slice(&(cd_off as u32).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d
}

pub fn make_pdf(title: &str, body_len: usize) -> Vec<u8> {
    let mut r = Rng(0x5044_4600_0000_0001);
    let filler: String = r
        .bytes(body_len)
        .iter()
        .map(|b| (b'a' + (b % 26)) as char)
        .collect();
    format!(
        "%PDF-1.4\n\
         1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
         2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
         3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n\
         4 0 obj\n<< /Length {} >>\nstream\n{}\n{}\nendstream\nendobj\n\
         trailer\n<< /Root 1 0 R >>\n%%EOF\n",
        body_len + title.len() + 1,
        title,
        filler
    )
    .into_bytes()
}

// ---------------------------------------------------------------- assembly

/// Build the default demonstration corpus: a mix of file types, some left
/// allocated, some deleted, plus a payload planted in file slack.
pub fn build_corpus(size_mb: u64, seed: u64) -> Corpus {
    let mut b = FatBuilder::new(size_mb * 1024 * 1024);
    let mut entries = Vec::new();

    struct Spec {
        name: &'static str,
        kind: &'static str,
        delete: bool,
    }
    let specs = [
        Spec {
            name: "BRIEF01.JPG",
            kind: "JPEG image",
            delete: true,
        },
        Spec {
            name: "SURVEIL.PNG",
            kind: "PNG image",
            delete: true,
        },
        Spec {
            name: "DOSSIER.PDF",
            kind: "PDF document",
            delete: true,
        },
        Spec {
            name: "ARCHIVE.ZIP",
            kind: "ZIP archive",
            delete: true,
        },
        Spec {
            name: "NOTES.TXT",
            kind: "plain text",
            delete: true,
        },
        Spec {
            name: "MANIFEST.TXT",
            kind: "plain text",
            delete: false,
        },
        Spec {
            name: "READONLY.JPG",
            kind: "JPEG image",
            delete: false,
        },
        Spec {
            name: "KEEPME.PDF",
            kind: "PDF document",
            delete: false,
        },
    ];

    for (i, s) in specs.iter().enumerate() {
        let n = seed.wrapping_add(i as u64 * 7919);
        let content: Vec<u8> = match s.kind {
            "JPEG image" => make_jpeg(n, 6000 + i * 800),
            "PNG image" => make_png(n, 9000 + i * 500),
            "PDF document" => make_pdf(s.name, 4000 + i * 300),
            "ZIP archive" => make_zip(
                "classified/report.txt",
                b"CLASSIFIED PAYLOAD - NISHESH DEMONSTRATION CORPUS"
                    .repeat(40)
                    .as_slice(),
            ),
            _ => format!(
                "NISHESH demonstration corpus\nfile: {}\nindex: {}\n{}\n",
                s.name,
                i,
                "The quick brown fox jumps over the lazy dog. ".repeat(60)
            )
            .into_bytes(),
        };
        b.add_file(s.name, &content);
        entries.push(CorpusEntry {
            name: s.name.to_string(),
            size: content.len(),
            sha256: hex(&sha256(&content)),
            deleted: s.delete,
            kind: s.kind,
        });
    }

    // Plant a payload in the slack of an allocated file — the remains of a
    // previous occupant of that cluster, which no wiping tool touches because
    // the filesystem believes the cluster is in use.
    let slack_payload =
        b"RESIDUAL FROM PREVIOUS TENANT: operation codename ANVIL, contact +91-XXXXXXXXXX";
    let planted = b.plant_slack("MANIFEST.TXT", slack_payload);

    for s in specs.iter().filter(|s| s.delete) {
        b.delete_file(s.name);
    }

    Corpus {
        image: b.build(),
        entries,
        slack_planted: if planted {
            Some("MANIFEST.TXT".to_string())
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carve::validate;

    #[test]
    fn generated_files_pass_their_own_validators() {
        // If this fails the whole benchmark is meaningless — the carver would
        // be reporting successes its validators never confirmed.
        assert!(validate("jpg", &make_jpeg(1, 4096)), "JPEG must validate");
        assert!(validate("png", &make_png(1, 4096)), "PNG must validate");
        assert!(
            validate("zip", &make_zip("a.txt", b"hello world")),
            "ZIP must validate"
        );
        assert!(validate("pdf", &make_pdf("test", 512)), "PDF must validate");
    }

    #[test]
    fn corpus_is_deterministic() {
        let a = build_corpus(20, 42);
        let b = build_corpus(20, 42);
        assert_eq!(a.image, b.image, "same seed must give the same image");
        assert_eq!(
            a.entries
                .iter()
                .map(|e| e.sha256.clone())
                .collect::<Vec<_>>(),
            b.entries
                .iter()
                .map(|e| e.sha256.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn corpus_has_deleted_and_surviving_files_and_slack() {
        let c = build_corpus(20, 7);
        assert!(c.expected_recoverable().len() >= 4);
        assert!(c.entries.iter().any(|e| !e.deleted));
        assert!(c.slack_planted.is_some(), "slack payload must be planted");
    }
}
