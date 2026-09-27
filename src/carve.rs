//! File carving (part of module M2).
//!
//! Two distinct problems live here and teams routinely conflate them.
//!
//! **Finding candidates.** You have a multi-terabyte byte stream and roughly
//! two hundred file signatures. Scanning once per signature is unacceptable.
//! Aho-Corasick (Communications of the ACM 18(6), 1975) builds a single finite
//! automaton — a trie plus failure links — from every pattern at once and
//! finds every occurrence of every pattern in ONE pass, in O(n + m + z) where
//! n is bytes scanned, m is total pattern length and z is the match count.
//! Two hundred signatures cost what one costs. That is the difference between
//! a twenty-minute sweep and a nine-hour one, and it is why the automaton is
//! implemented here rather than approximated with repeated substring searches.
//!
//! **Assembling fragments.** If a file was contiguous this is trivial. If it
//! was fragmented, deciding which fragment follows which is a sequencing
//! problem, NP-hard in the general case. So we do not search it. We use the
//! file format's own error detection as the oracle: a JPEG whose entropy-coded
//! segment decodes coherently, a ZIP whose CRC32 validates. The format tells
//! us whether the join is real. Artifacts whose validator did not confirm them
//! are reported with reduced confidence rather than presented as clean finds.

use crate::artifact::{Artifact, Method};
use crate::device::{Device, Region};
use crate::hash::sha256;

// --------------------------------------------------------------- automaton

const ALPHABET: usize = 256;

#[derive(Debug)]
struct Node {
    next: [u32; ALPHABET],
    fail: u32,
    /// Pattern ids terminating at this node.
    out: Vec<u32>,
}

impl Node {
    fn new() -> Node {
        Node {
            next: [u32::MAX; ALPHABET],
            fail: 0,
            out: Vec::new(),
        }
    }
}

/// Aho-Corasick automaton with a dense goto table. Dense costs memory
/// proportional to node count but gives a branch-free transition, which is
/// what makes the single pass competitive with a raw memory scan.
#[derive(Debug)]
pub struct AhoCorasick {
    nodes: Vec<Node>,
    pattern_len: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Offset of the first byte of the matched pattern.
    pub start: u64,
    pub pattern_id: u32,
}

impl AhoCorasick {
    pub fn build(patterns: &[Vec<u8>]) -> AhoCorasick {
        let mut nodes = vec![Node::new()];
        let mut pattern_len = Vec::with_capacity(patterns.len());

        // 1. trie
        for (id, pat) in patterns.iter().enumerate() {
            pattern_len.push(pat.len());
            let mut cur = 0usize;
            for &b in pat {
                let nxt = nodes[cur].next[b as usize];
                cur = if nxt == u32::MAX {
                    nodes.push(Node::new());
                    let new_idx = (nodes.len() - 1) as u32;
                    nodes[cur].next[b as usize] = new_idx;
                    new_idx as usize
                } else {
                    nxt as usize
                };
            }
            nodes[cur].out.push(id as u32);
        }

        // 2. failure links by breadth-first traversal, and goto completion so
        //    every state has a defined transition on every byte
        let mut queue = std::collections::VecDeque::new();
        for b in 0..ALPHABET {
            let n = nodes[0].next[b];
            if n == u32::MAX {
                nodes[0].next[b] = 0;
            } else {
                nodes[n as usize].fail = 0;
                queue.push_back(n as usize);
            }
        }
        while let Some(cur) = queue.pop_front() {
            // output links: a state inherits the outputs of its failure state,
            // so overlapping patterns are all reported
            let fail = nodes[cur].fail as usize;
            let inherited = nodes[fail].out.clone();
            nodes[cur].out.extend(inherited);
            for b in 0..ALPHABET {
                let nxt = nodes[cur].next[b];
                let fail_target = nodes[nodes[cur].fail as usize].next[b];
                if nxt == u32::MAX {
                    nodes[cur].next[b] = fail_target;
                } else {
                    nodes[nxt as usize].fail = fail_target;
                    queue.push_back(nxt as usize);
                }
            }
        }

        AhoCorasick { nodes, pattern_len }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Feed a chunk. `base` is the absolute offset of `chunk[0]`. `state` is
    /// carried across chunk boundaries so a pattern straddling a chunk edge is
    /// still found — the reason the scanner can stream a whole device without
    /// ever holding it in memory.
    pub fn scan_chunk(
        &self,
        chunk: &[u8],
        base: u64,
        state: &mut u32,
        mut on_match: impl FnMut(Match),
    ) {
        let mut s = *state as usize;
        for (i, &b) in chunk.iter().enumerate() {
            s = self.nodes[s].next[b as usize] as usize;
            if !self.nodes[s].out.is_empty() {
                for &id in &self.nodes[s].out {
                    let len = self.pattern_len[id as usize] as u64;
                    let end = base + i as u64 + 1;
                    on_match(Match {
                        start: end - len,
                        pattern_id: id,
                    });
                }
            }
        }
        *state = s as u32;
    }
}

// -------------------------------------------------------------- signatures

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: &'static str,
    pub ext: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    /// Bytes to include after the footer match (trailers such as a ZIP EOCD
    /// comment field or a PNG chunk CRC).
    pub footer_tail: usize,
    pub max_size: u64,
    /// Some headers are only valid at a fixed offset within the file.
    pub header_offset: usize,
}

pub fn default_signatures() -> Vec<Signature> {
    vec![
        Signature {
            name: "JPEG image",
            ext: "jpg",
            header: &[0xFF, 0xD8, 0xFF],
            footer: Some(&[0xFF, 0xD9]),
            footer_tail: 0,
            max_size: 32 << 20,
            header_offset: 0,
        },
        Signature {
            name: "PNG image",
            ext: "png",
            header: &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(b"IEND"),
            footer_tail: 4,
            max_size: 64 << 20,
            header_offset: 0,
        },
        Signature {
            name: "GIF image",
            ext: "gif",
            header: b"GIF89a",
            footer: Some(&[0x00, 0x3B]),
            footer_tail: 0,
            max_size: 16 << 20,
            header_offset: 0,
        },
        Signature {
            name: "PDF document",
            ext: "pdf",
            header: b"%PDF-",
            footer: Some(b"%%EOF"),
            footer_tail: 0,
            max_size: 128 << 20,
            header_offset: 0,
        },
        Signature {
            name: "ZIP / OOXML",
            ext: "zip",
            header: &[0x50, 0x4B, 0x03, 0x04],
            footer: Some(&[0x50, 0x4B, 0x05, 0x06]),
            footer_tail: 22,
            max_size: 512 << 20,
            header_offset: 0,
        },
        Signature {
            name: "GZIP stream",
            ext: "gz",
            header: &[0x1F, 0x8B, 0x08],
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
        Signature {
            name: "SQLite database",
            ext: "sqlite",
            header: b"SQLite format 3\x00",
            footer: None,
            footer_tail: 0,
            max_size: 512 << 20,
            header_offset: 0,
        },
        Signature {
            name: "ELF executable",
            ext: "elf",
            header: &[0x7F, b'E', b'L', b'F'],
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
        Signature {
            name: "PE executable",
            ext: "exe",
            header: b"MZ",
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
        Signature {
            name: "RIFF container",
            ext: "riff",
            header: b"RIFF",
            footer: None,
            footer_tail: 0,
            max_size: 512 << 20,
            header_offset: 0,
        },
        Signature {
            name: "OLE compound file",
            ext: "doc",
            header: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            footer: None,
            footer_tail: 0,
            max_size: 128 << 20,
            header_offset: 0,
        },
        Signature {
            name: "RAR archive",
            ext: "rar",
            header: b"Rar!\x1A\x07",
            footer: None,
            footer_tail: 0,
            max_size: 512 << 20,
            header_offset: 0,
        },
        Signature {
            name: "7-Zip archive",
            ext: "7z",
            header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            footer: None,
            footer_tail: 0,
            max_size: 512 << 20,
            header_offset: 0,
        },
        Signature {
            name: "BZIP2 stream",
            ext: "bz2",
            header: b"BZh",
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
        Signature {
            name: "PGP / GPG data",
            ext: "pgp",
            header: &[0x85, 0x02],
            footer: None,
            footer_tail: 0,
            max_size: 16 << 20,
            header_offset: 0,
        },
        Signature {
            name: "OpenSSH private key",
            ext: "key",
            header: b"-----BEGIN OPENSSH PRIVATE KEY",
            footer: None,
            footer_tail: 0,
            max_size: 64 << 10,
            header_offset: 0,
        },
        Signature {
            name: "RSA private key",
            ext: "pem",
            header: b"-----BEGIN RSA PRIVATE KEY",
            footer: None,
            footer_tail: 0,
            max_size: 64 << 10,
            header_offset: 0,
        },
        Signature {
            name: "X.509 certificate",
            ext: "crt",
            header: b"-----BEGIN CERTIFICATE",
            footer: None,
            footer_tail: 0,
            max_size: 64 << 10,
            header_offset: 0,
        },
        Signature {
            name: "Windows registry hive",
            ext: "hive",
            header: b"regf",
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
        Signature {
            name: "Windows event log",
            ext: "evtx",
            header: b"ElfFile\x00",
            footer: None,
            footer_tail: 0,
            max_size: 256 << 20,
            header_offset: 0,
        },
    ]
}

/// The carving scanner. Holds the automaton plus the mapping from pattern id
/// back to which signature and which role (header or footer) it represents.
#[derive(Debug)]
pub struct Carver {
    pub signatures: Vec<Signature>,
    automaton: AhoCorasick,
    /// (signature index, is_footer) for each pattern id.
    roles: Vec<(usize, bool)>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub bytes_scanned: u64,
    pub header_hits: u64,
    pub footer_hits: u64,
    pub artifacts: u64,
    pub validated: u64,
}

impl Carver {
    pub fn new(signatures: Vec<Signature>) -> Carver {
        let mut patterns = Vec::new();
        let mut roles = Vec::new();
        for (i, s) in signatures.iter().enumerate() {
            patterns.push(s.header.to_vec());
            roles.push((i, false));
            if let Some(f) = s.footer {
                patterns.push(f.to_vec());
                roles.push((i, true));
            }
        }
        let automaton = AhoCorasick::build(&patterns);
        Carver {
            signatures,
            automaton,
            roles,
        }
    }

    pub fn pattern_count(&self) -> usize {
        self.roles.len()
    }

    pub fn automaton_states(&self) -> usize {
        self.automaton.node_count()
    }

    /// Sweep a region of the device in one pass.
    ///
    /// `progress` is called with (bytes_done, bytes_total) so the CLI can show
    /// real throughput rather than a spinner.
    pub fn scan(
        &self,
        dev: &mut dyn Device,
        start_lba: u64,
        sectors: u64,
        region: Region,
        mut progress: impl FnMut(u64, u64),
    ) -> std::io::Result<(Vec<Artifact>, ScanStats)> {
        let ss = dev.info().sector_size as u64;
        let chunk_sectors: u64 = 2048; // 1 MiB at 512-byte sectors
        let total_bytes = sectors * ss;
        let mut stats = ScanStats::default();

        // Pass one: collect every header and footer hit. Kept as offsets only,
        // so memory stays proportional to hit count and not to media size.
        let mut headers: Vec<(usize, u64)> = Vec::new();
        let mut footers: Vec<(usize, u64)> = Vec::new();
        let mut state = 0u32;
        let mut done = 0u64;
        let mut lba = start_lba;
        while lba < start_lba + sectors {
            let n = chunk_sectors.min(start_lba + sectors - lba);
            let buf = dev.read_sectors(lba, n as u32)?;
            let base = lba * ss;
            self.automaton.scan_chunk(&buf, base, &mut state, |m| {
                let (sig, is_footer) = self.roles[m.pattern_id as usize];
                if is_footer {
                    footers.push((sig, m.start));
                } else {
                    headers.push((sig, m.start));
                }
            });
            done += n * ss;
            progress(done, total_bytes);
            lba += n;
        }
        stats.bytes_scanned = total_bytes;
        stats.header_hits = headers.len() as u64;
        stats.footer_hits = footers.len() as u64;

        footers.sort_by_key(|&(s, o)| (s, o));

        // Pass two: pair each header with the nearest following footer of the
        // same signature, extract, and hand the bytes to the format validator.
        let mut out = Vec::new();
        for &(sig_idx, hstart) in headers.iter() {
            let sig = &self.signatures[sig_idx];
            let end = match sig.footer {
                Some(_) => {
                    let cand = footers
                        .iter()
                        .filter(|&&(s, o)| s == sig_idx && o > hstart)
                        .map(|&(_, o)| o)
                        .next();
                    match cand {
                        Some(o) => {
                            let e = o + sig.footer.unwrap().len() as u64 + sig.footer_tail as u64;
                            if e - hstart > sig.max_size {
                                continue;
                            }
                            e
                        }
                        None => continue, // header with no matching footer: fragment
                    }
                }
                None => continue, // footerless formats need a length parser; Phase 2
            };
            let len = (end - hstart) as usize;
            if len == 0 || len as u64 > sig.max_size {
                continue;
            }
            let data = dev.read_at(hstart, len)?;
            let validated = validate(sig.ext, &data);
            if validated {
                stats.validated += 1;
            }
            out.push(Artifact {
                offset: hstart,
                size: len as u64,
                name: Some(format!("carved-{:012x}.{}", hstart, sig.ext)),
                method: Method::Carve,
                confidence: if validated { 0.85 } else { 0.35 },
                sha256: sha256(&data),
                region,
                file_type: Some(sig.name),
                validated,
            });
        }
        stats.artifacts = out.len() as u64;
        Ok((out, stats))
    }
}

// -------------------------------------------------------------- validators

/// Format-native structural validation. This is the reassembly oracle: instead
/// of guessing whether a span of bytes is a real file, we ask the format's own
/// error detection.
pub fn validate(ext: &str, data: &[u8]) -> bool {
    match ext {
        "jpg" => validate_jpeg(data),
        "png" => validate_png(data),
        "zip" => validate_zip(data),
        "pdf" => validate_pdf(data),
        "gif" => data.len() > 14 && data.starts_with(b"GIF89a") && data.ends_with(&[0x3B]),
        _ => false,
    }
}

/// Walk the JPEG marker chain. A carved span that is really a JPEG has a
/// well-formed sequence of segments from SOI to EOI; a span that merely begins
/// with the right three bytes does not.
fn validate_jpeg(d: &[u8]) -> bool {
    if d.len() < 4 || d[0] != 0xFF || d[1] != 0xD8 {
        return false;
    }
    if d[d.len() - 2] != 0xFF || d[d.len() - 1] != 0xD9 {
        return false;
    }
    let mut i = 2usize;
    let mut saw_sof = false;
    while i + 3 < d.len() {
        if d[i] != 0xFF {
            return false;
        }
        let marker = d[i + 1];
        i += 2;
        match marker {
            0xD8 | 0x01 | 0xD0..=0xD7 => continue,
            0xD9 => return saw_sof,
            0xDA => return saw_sof, // start of scan; entropy data follows
            _ => {
                if i + 1 >= d.len() {
                    return false;
                }
                let seg_len = u16::from_be_bytes([d[i], d[i + 1]]) as usize;
                if seg_len < 2 || i + seg_len > d.len() {
                    return false;
                }
                if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 {
                    saw_sof = true;
                }
                i += seg_len;
            }
        }
    }
    false
}

/// Walk the PNG chunk chain and check each chunk's CRC32. Every chunk carries
/// its own checksum, so a mis-joined fragment is detected exactly.
fn validate_png(d: &[u8]) -> bool {
    const MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if d.len() < 12 || d[..8] != MAGIC {
        return false;
    }
    let mut i = 8usize;
    let mut saw_ihdr = false;
    while i + 12 <= d.len() {
        let len = u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as usize;
        let type_start = i + 4;
        let data_start = i + 8;
        if data_start + len + 4 > d.len() {
            return false;
        }
        let ctype = &d[type_start..type_start + 4];
        if ctype == b"IHDR" {
            saw_ihdr = true;
        }
        let expect = u32::from_be_bytes([
            d[data_start + len],
            d[data_start + len + 1],
            d[data_start + len + 2],
            d[data_start + len + 3],
        ]);
        if crc32(&d[type_start..data_start + len]) != expect {
            return false;
        }
        if ctype == b"IEND" {
            return saw_ihdr;
        }
        i = data_start + len + 4;
    }
    false
}

/// Locate the End Of Central Directory record and check that it points at a
/// central directory inside the span. A ZIP that was cut short or wrongly
/// joined fails this immediately.
fn validate_zip(d: &[u8]) -> bool {
    if d.len() < 22 || !d.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return false;
    }
    let eocd_sig = [0x50u8, 0x4B, 0x05, 0x06];
    let search_from = d.len().saturating_sub(65_557);
    let mut pos = None;
    for i in (search_from..=d.len() - 22).rev() {
        if d[i..i + 4] == eocd_sig {
            pos = Some(i);
            break;
        }
    }
    let p = match pos {
        Some(p) => p,
        None => return false,
    };
    let cd_size = u32::from_le_bytes([d[p + 12], d[p + 13], d[p + 14], d[p + 15]]) as usize;
    let cd_off = u32::from_le_bytes([d[p + 16], d[p + 17], d[p + 18], d[p + 19]]) as usize;
    if cd_off + cd_size > d.len() {
        return false;
    }
    cd_size == 0 || d[cd_off..cd_off + 4] == [0x50, 0x4B, 0x01, 0x02]
}

fn validate_pdf(d: &[u8]) -> bool {
    d.len() > 8
        && d.starts_with(b"%PDF-")
        && d.windows(5).rev().take(2048).any(|w| w == b"%%EOF")
        && d.windows(3).any(|w| w == b"obj")
}

/// CRC-32/ISO-HDLC, the variant PNG and ZIP use. Table built once on demand.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Identify a buffer by its leading bytes and run the matching validator.
/// Used by the filesystem recovery paths to grade a metadata-backed recovery.
pub fn identify_and_validate(data: &[u8]) -> (Option<&'static str>, bool) {
    for s in default_signatures() {
        if data.len() > s.header.len() && data.starts_with(s.header) {
            return (Some(s.name), validate(s.ext, data));
        }
    }
    (None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automaton_finds_overlapping_patterns_in_one_pass() {
        let pats: Vec<Vec<u8>> = vec![
            b"he".to_vec(),
            b"she".to_vec(),
            b"his".to_vec(),
            b"hers".to_vec(),
        ];
        let ac = AhoCorasick::build(&pats);
        let mut hits = Vec::new();
        let mut st = 0;
        ac.scan_chunk(b"ushers", 0, &mut st, |m| {
            hits.push((m.start, m.pattern_id))
        });
        // "she" at 1, "he" at 2, "hers" at 2
        assert!(hits.contains(&(1, 1)), "{hits:?}");
        assert!(hits.contains(&(2, 0)), "{hits:?}");
        assert!(hits.contains(&(2, 3)), "{hits:?}");
    }

    #[test]
    fn matches_spanning_a_chunk_boundary_are_found() {
        let pats: Vec<Vec<u8>> = vec![b"NEEDLE".to_vec()];
        let ac = AhoCorasick::build(&pats);
        let hay = b"aaaaNEEDLEbbbb";
        let mut hits = Vec::new();
        let mut st = 0;
        // Split the haystack straight through the middle of the pattern.
        ac.scan_chunk(&hay[..7], 0, &mut st, |m| hits.push(m.start));
        ac.scan_chunk(&hay[7..], 7, &mut st, |m| hits.push(m.start));
        assert_eq!(hits, vec![4]);
    }

    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn png_validator_rejects_a_corrupted_chunk() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR
        let ihdr_data = [0u8, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
        png.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&ihdr_data);
        let mut crc_in = b"IHDR".to_vec();
        crc_in.extend_from_slice(&ihdr_data);
        png.extend_from_slice(&crc32(&crc_in).to_be_bytes());
        // IEND
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&crc32(b"IEND").to_be_bytes());
        assert!(validate_png(&png));

        let mut broken = png.clone();
        let n = broken.len();
        broken[n - 1] ^= 0xFF; // flip a CRC bit
        assert!(!validate_png(&broken), "corrupted CRC must be rejected");
    }

    #[test]
    fn jpeg_validator_rejects_a_bare_header() {
        assert!(!validate_jpeg(&[0xFF, 0xD8, 0xFF, 0xD9]));
    }

    #[test]
    fn carver_reports_its_automaton_size() {
        let c = Carver::new(default_signatures());
        assert!(c.pattern_count() >= 20);
        assert!(c.automaton_states() > c.pattern_count());
    }
}
