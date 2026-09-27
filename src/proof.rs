//! Proof layer (module M4): certificates, tamper-evident logging, and the
//! signing abstraction.
//!
//! Design constraint that drives everything here: the deployment target is
//! air-gapped. Forensic labs, defence disposal bays and CPSU IT rooms have no
//! outbound network. So tamper-evidence has to be achievable offline, with a
//! single trusted operator, and verifiable by a third party who receives only
//! a certificate file.
//!
//! That rules out a live distributed ledger as the primary mechanism. What it
//! does not rule out is the construction underneath one:
//!
//!   * RFC 8785 canonical serialisation, so the signed bytes are deterministic
//!   * a hash-chained append-only log — altering entry N invalidates N+1..end
//!   * Merkle aggregation, so any single certificate carries an O(log n)
//!     inclusion proof against a root (the RFC 6962 Certificate Transparency
//!     construction, which is the one that actually runs at scale)
//!
//! An external ledger earns its place in exactly one place: anchoring the
//! periodic Merkle root — 32 bytes, no device serials, no user data — so an
//! auditor can establish that the log existed at a point in time and the
//! operator cannot backdate it. That is Phase 3 and optional by design.

use crate::hash::{hex, hmac_sha256, sha256, Sha256};
use crate::json::{parse, Json};
use crate::json;

// ------------------------------------------------------------------ signer

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// HMAC-SHA256 over the canonical bytes with a locally held key.
    ///
    /// This is a MESSAGE AUTHENTICATION CODE, not a digital signature. It
    /// proves the certificate was produced by a holder of the key; it does NOT
    /// let a third party verify authorship without that key, and it does not
    /// provide non-repudiation. It is labelled as such in every certificate it
    /// produces so no reviewer can mistake one for the other.
    HmacSha256Development,
    /// Ed25519 (RFC 8032). Phase 2.
    Ed25519,
}

impl SignatureScheme {
    pub fn label(&self) -> &'static str {
        match self {
            SignatureScheme::HmacSha256Development => "HMAC-SHA256 (development MAC, not a signature)",
            SignatureScheme::Ed25519 => "Ed25519 (RFC 8032)",
        }
    }
    pub fn provides_non_repudiation(&self) -> bool {
        matches!(self, SignatureScheme::Ed25519)
    }
}

/// Signing abstraction.
///
/// Note on scope, stated plainly because getting this wrong is malpractice:
/// asymmetric cryptography is NOT hand-rolled in this tree. The development
/// signer below uses HMAC-SHA256, which is safe to implement from RFC 2104 and
/// is verified against the RFC 4231 vectors. Ed25519 is wired in Phase 2 by
/// implementing this trait over `ed25519-dalek`, with the private key held in
/// a TPM 2.0 or a smartcard so it never exists in process memory.
pub trait Signer {
    fn scheme(&self) -> SignatureScheme;
    fn key_id(&self) -> String;
    fn sign(&self, canonical: &[u8]) -> Vec<u8>;
    fn verify(&self, canonical: &[u8], sig: &[u8]) -> bool;
}

#[derive(Debug)]
pub struct DevSigner {
    key: Vec<u8>,
}

impl DevSigner {
    pub fn from_key(key: Vec<u8>) -> Self {
        DevSigner { key }
    }
    /// Derive a stable key from a passphrase so a demo is reproducible across
    /// machines. Real deployments load from the TPM instead.
    pub fn from_passphrase(p: &str) -> Self {
        DevSigner { key: sha256(p.as_bytes()).to_vec() }
    }
}

impl Signer for DevSigner {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::HmacSha256Development
    }
    fn key_id(&self) -> String {
        hex(&sha256(&self.key)[..8])
    }
    fn sign(&self, canonical: &[u8]) -> Vec<u8> {
        hmac_sha256(&self.key, canonical).to_vec()
    }
    fn verify(&self, canonical: &[u8], sig: &[u8]) -> bool {
        let expect = hmac_sha256(&self.key, canonical);
        // Constant-time compare. Timing leaks in a verification path are how
        // MAC forgery oracles get built.
        if sig.len() != expect.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..sig.len() {
            diff |= sig[i] ^ expect[i];
        }
        diff == 0
    }
}

// ------------------------------------------------------------ merkle tree

/// RFC 6962 §2 hashing: leaves are prefixed 0x00, internal nodes 0x01. The
/// prefixes are what stop a second-preimage attack that reinterprets an
/// internal node as a leaf.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[0x00]);
    h.update(data);
    h.finalize()
}

pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[0x01]);
    h.update(l);
    h.update(r);
    h.finalize()
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf: [u8; 32],
    /// Sibling hashes bottom-up, with a flag for whether the sibling sits on
    /// the right. log2(n) entries: a thousand certificates, a ten-hash proof.
    pub path: Vec<([u8; 32], bool)>,
    pub root: [u8; 32],
}

impl InclusionProof {
    /// Recompute the root from the leaf and the path. A verifier needs nothing
    /// else — not the log, not the other entries.
    pub fn verify(&self) -> bool {
        let mut acc = self.leaf;
        for (sib, sib_is_right) in &self.path {
            acc = if *sib_is_right {
                node_hash(&acc, sib)
            } else {
                node_hash(sib, &acc)
            };
        }
        acc == self.root
    }

    pub fn to_json(&self) -> Json {
        json! {
            "index" => self.index as i64,
            "leaf" => hex(&self.leaf),
            "root" => hex(&self.root),
            "path" => Json::Arr(self.path.iter().map(|(h, r)| json! {
                "hash" => hex(h),
                "sibling_on_right" => *r,
            }).collect()),
        }
    }
}

impl MerkleTree {
    pub fn build(leaves: &[[u8; 32]]) -> MerkleTree {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![vec![]] };
        }
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(node_hash(&prev[i], &prev[i + 1]));
                } else {
                    // Odd node promotes unchanged, as in RFC 6962.
                    next.push(prev[i]);
                }
                i += 2;
            }
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn len(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = idx ^ 1;
            if sib < level.len() {
                path.push((level[sib], sib > idx));
            }
            idx /= 2;
        }
        Some(InclusionProof {
            index,
            leaf: self.levels[0][index],
            path,
            root: self.root(),
        })
    }
}

// ------------------------------------------------------------- append log

/// Append-only, hash-chained event log. Each entry embeds the hash of the one
/// before it, so altering entry N invalidates every entry after it. No
/// network, no consensus, no ledger — deployable inside an air gap.
#[derive(Debug, Default)]
pub struct AppendLog {
    pub entries: Vec<Json>,
    pub leaves: Vec<[u8; 32]>,
}

pub const GENESIS: [u8; 32] = [0u8; 32];

impl AppendLog {
    pub fn new() -> Self {
        AppendLog::default()
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(AppendLog::new());
        }
        let text = std::fs::read_to_string(path)?;
        let mut log = AppendLog::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let j = parse(line).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })?;
            log.leaves.push(leaf_hash(j.canonical().as_bytes()));
            log.entries.push(j);
        }
        Ok(log)
    }

    pub fn head(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| sha256(e.canonical().as_bytes()))
            .unwrap_or(GENESIS)
    }

    /// Append a record, chaining it to the current head.
    pub fn append(&mut self, mut record: Json) -> Json {
        record.set("seq", Json::Int(self.entries.len() as i64));
        record.set("prev_hash", Json::Str(hex(&self.head())));
        self.leaves.push(leaf_hash(record.canonical().as_bytes()));
        self.entries.push(record.clone());
        record
    }

    pub fn persist(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&e.canonical());
            out.push('\n');
        }
        std::fs::write(path, out)
    }

    pub fn merkle(&self) -> MerkleTree {
        MerkleTree::build(&self.leaves)
    }

    /// Walk the chain and confirm every link. Returns the index of the first
    /// broken entry, if any.
    pub fn audit(&self) -> Result<(), usize> {
        let mut prev = GENESIS;
        for (i, e) in self.entries.iter().enumerate() {
            let claimed = e.get("prev_hash").and_then(|j| j.as_str()).unwrap_or("");
            if claimed != hex(&prev) {
                return Err(i);
            }
            prev = sha256(e.canonical().as_bytes());
        }
        Ok(())
    }
}

// ------------------------------------------------------------ certificate

/// Build a certificate. The `payload` is everything that gets signed; the
/// signature and any human-facing annotations sit outside it so the signed
/// bytes are exactly reproducible by a verifier.
pub fn build_certificate(payload: Json, signer: &dyn Signer) -> Json {
    let canonical = payload.canonical();
    let sig = signer.sign(canonical.as_bytes());
    json! {
        "nishesh_certificate_version" => 1i64,
        "payload" => payload,
        "payload_sha256" => hex(&sha256(canonical.as_bytes())),
        "signature" => hex(&sig),
        "signature_scheme" => signer.scheme().label(),
        "signature_key_id" => signer.key_id(),
        "non_repudiation" => signer.scheme().provides_non_repudiation(),
    }
}

#[derive(Debug)]
pub struct CertCheck {
    pub payload_hash_ok: bool,
    pub signature_ok: bool,
    pub scheme: String,
    pub non_repudiation: bool,
}

impl CertCheck {
    pub fn ok(&self) -> bool {
        self.payload_hash_ok && self.signature_ok
    }
}

pub fn verify_certificate(cert: &Json, signer: &dyn Signer) -> Option<CertCheck> {
    let payload = cert.get("payload")?;
    let canonical = payload.canonical();
    let stated = cert.get("payload_sha256")?.as_str()?;
    let sig = crate::hash::unhex(cert.get("signature")?.as_str()?)?;
    Some(CertCheck {
        payload_hash_ok: stated == hex(&sha256(canonical.as_bytes())),
        signature_ok: signer.verify(canonical.as_bytes(), &sig),
        scheme: cert
            .get("signature_scheme")
            .and_then(|j| j.as_str())
            .unwrap_or("unknown")
            .to_string(),
        non_repudiation: matches!(cert.get("non_repudiation"), Some(Json::Bool(true))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verifies_for_every_leaf() {
        for n in [1usize, 2, 3, 7, 8, 100] {
            let leaves: Vec<[u8; 32]> =
                (0..n).map(|i| leaf_hash(&(i as u64).to_le_bytes())).collect();
            let t = MerkleTree::build(&leaves);
            for i in 0..n {
                let p = t.prove(i).expect("proof must exist");
                assert!(p.verify(), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn proof_length_is_logarithmic() {
        let leaves: Vec<[u8; 32]> =
            (0..1024u64).map(|i| leaf_hash(&i.to_le_bytes())).collect();
        let t = MerkleTree::build(&leaves);
        let p = t.prove(500).unwrap();
        assert_eq!(p.path.len(), 10, "1024 leaves must give a 10-hash proof");
    }

    #[test]
    fn a_forged_leaf_fails_its_proof() {
        let leaves: Vec<[u8; 32]> = (0..8u64).map(|i| leaf_hash(&i.to_le_bytes())).collect();
        let t = MerkleTree::build(&leaves);
        let mut p = t.prove(3).unwrap();
        p.leaf = leaf_hash(b"not the real entry");
        assert!(!p.verify());
    }

    #[test]
    fn tampering_with_an_entry_breaks_every_later_link() {
        let mut log = AppendLog::new();
        for i in 0..5 {
            log.append(json! { "event" => "sanitize", "device" => format!("dev{i}") });
        }
        assert!(log.audit().is_ok());
        // Rewrite entry 2 the way an operator hiding a failure would.
        log.entries[2].set("device", Json::Str("TAMPERED".into()));
        let broken = log.audit().unwrap_err();
        assert_eq!(broken, 3, "the break surfaces at the next link");
    }

    #[test]
    fn certificate_roundtrip_and_tamper_detection() {
        let s = DevSigner::from_passphrase("demo");
        let payload = json! {
            "device_serial" => "ABC123",
            "technique" => "ATA SANITIZE",
            "verified" => true,
        };
        let cert = build_certificate(payload, &s);
        let c = verify_certificate(&cert, &s).unwrap();
        assert!(c.ok());
        assert!(!c.non_repudiation, "a MAC must never claim non-repudiation");

        let mut bad = cert.clone();
        if let Some(Json::Obj(_)) = bad.get("payload") {
            let mut p = bad.get("payload").unwrap().clone();
            p.set("verified", Json::Bool(false));
            bad.set("payload", p);
        }
        let c2 = verify_certificate(&bad, &s).unwrap();
        assert!(!c2.ok(), "flipping the verdict must invalidate the certificate");
    }

    #[test]
    fn canonicalisation_makes_the_signature_order_independent() {
        let s = DevSigner::from_passphrase("demo");
        let a = parse(r#"{"b":2,"a":1}"#).unwrap();
        let b = parse(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(s.sign(a.canonical().as_bytes()), s.sign(b.canonical().as_bytes()));
    }
}
