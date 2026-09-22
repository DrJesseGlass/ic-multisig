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
    /// What the hash is of. Consumers agree on these out of band:
    /// `"commit"`, `"module"`, `"tally"`.
    pub kind: String,
    /// The 32 bytes being approved.
    #[serde(with = "crate::hexbytes::arr32")]
    pub hash: [u8; 32],
}

impl Subject {
    /// A subject over a hash that is already 32 bytes -- a sha256 digest, an
    /// IC module hash. Use [`Subject::of_bytes`] to hash content, or
    /// [`Subject::of_short_hash`] for a shorter identifier.
    ///
    /// ```
    /// use ic_multisig::Subject;
    ///
    /// let s = Subject::new("module", [0u8; 32]);
    /// assert_eq!(s.kind, "module");
    /// ```
    pub fn new(kind: impl Into<String>, hash: [u8; 32]) -> Self {
        Subject {
            kind: kind.into(),
            hash,
        }
    }

    /// A subject whose hash is the sha256 of `bytes`.
    ///
    /// ```
    /// use ic_multisig::Subject;
    ///
    /// let s = Subject::of_bytes("tally", b"results.json");
    /// assert_eq!(s.hash.len(), 32);
    /// ```
    pub fn of_bytes(kind: impl Into<String>, bytes: &[u8]) -> Self {
        Subject::new(kind, Sha256::digest(bytes).into())
    }

    /// A subject for a hash that is shorter than 32 bytes (a git SHA-1
    /// commit, say): the hash is sha256(kind || 0 || raw), so distinct
    /// inputs of any length stay distinct.
    ///
    /// The kind goes into the hash as well as beside it, so the same raw
    /// bytes under two kinds never collide even before the tag is compared.
    ///
    /// ```
    /// use ic_multisig::Subject;
    ///
    /// let sha1 = [0xabu8; 20];
    /// let commit = Subject::of_short_hash("commit", &sha1);
    /// let other = Subject::of_short_hash("module", &sha1);
    /// assert_ne!(commit.hash, other.hash);
    /// ```
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

    /// A storage key: `<kind>:<hex hash>`. Stable across releases, so a
    /// canister's stable map keyed by this survives an upgrade.
    ///
    /// ```
    /// use ic_multisig::Subject;
    ///
    /// let s = Subject::new("module", [0u8; 32]);
    /// assert_eq!(s.key(), format!("module:{}", "00".repeat(32)));
    /// ```
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind, hex::encode(self.hash))
    }
}

impl core::fmt::Display for Subject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}
