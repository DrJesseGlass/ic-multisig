use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for everything this crate hashes or signs. Bump on any
/// change to the canonical encodings.
pub const DOMAIN: &[u8] = b"ic-multisig/v1";

/// What is being approved: a kind tag (`"commit"`, `"module"`, `"tally"`)
/// and a 32-byte hash. The tag keeps a commit approval from ever counting as
/// a module approval with the same bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Subject {
    pub kind: String,
    #[serde(with = "crate::hexbytes::arr32")]
    pub hash: [u8; 32],
}

impl Subject {
    pub fn new(kind: impl Into<String>, hash: [u8; 32]) -> Self {
        Subject {
            kind: kind.into(),
            hash,
        }
    }

    /// A subject whose hash is the sha256 of `bytes`.
    pub fn of_bytes(kind: impl Into<String>, bytes: &[u8]) -> Self {
        Subject::new(kind, Sha256::digest(bytes).into())
    }

    /// A subject for a hash that is shorter than 32 bytes (a git SHA-1
    /// commit, say): the hash is sha256(kind || raw), so distinct inputs of
    /// any length stay distinct.
    pub fn of_short_hash(kind: impl Into<String>, raw: &[u8]) -> Self {
        let kind = kind.into();
        let mut h = Sha256::new();
        h.update(kind.as_bytes());
        h.update([0]);
        h.update(raw);
        Subject::new(kind, h.finalize().into())
    }

    /// Canonical bytes: DOMAIN || 0 || kind || 0 || hash.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN.len() + self.kind.len() + 34);
        out.extend_from_slice(DOMAIN);
        out.push(0);
        out.extend_from_slice(self.kind.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.hash);
        out
    }

    /// A storage key: `<kind>:<hex hash>`.
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind, hex::encode(self.hash))
    }
}

impl core::fmt::Display for Subject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}
