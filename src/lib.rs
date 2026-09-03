//! K-of-N approvals over a hashed subject.
//!
//! A **policy** names N approvers and a threshold K. A **subject** is a
//! 32-byte hash with a kind tag: a commit a repo wants to deploy, a module
//! hash a release wants attested, a tally an election wants published. Each
//! approver casts one **approval** (approve or reject) per subject, later
//! ballots replacing earlier ones. A **tally** counts the ballots that count
//! -- from approvers currently in the policy -- and says whether K is reached.
//!
//! Two flavors share the same records:
//!
//! - **Authenticated approvals.** Inside a canister the approver is the
//!   caller of an update call, authenticated by the IC, and the record needs
//!   no signature. The approver's identity is its principal bytes.
//! - **Signed approvals.** When an approval must be checkable outside the
//!   canister, or by another chain, it carries a signature over
//!   [`Approval::message`], and the approver's identity is its public key.
//!   Enable the `ed25519` feature to verify (and, for tests and clients, to
//!   produce) them.
//!
//! The crate has no dependency on `ic-cdk`: callers pass the approver in and
//! supply storage through [`Store`], so every rule here is testable on the
//! host. Under the `candid` feature the public types derive `CandidType` and
//! [`Approver`] converts from `candid::Principal`.
//!
//! Consumers: ic-git (voters gating the deploy queue), ic-vote (trustees
//! gating election lifecycle steps), and the attestation tooling both rely
//! on (K-of-N verifiers on a module hash).

mod approval;
mod policy;
mod store;
mod subject;
mod tally;

#[cfg(feature = "ed25519")]
pub mod ed25519;

pub use approval::{Approval, Approver, Decision};
pub use policy::Policy;
pub use store::{record, MemoryStore, Store};
pub use subject::Subject;
pub use tally::{cast, tally, Tally};

/// Why an approval was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The approver is not in the policy.
    NotAnApprover,
    /// The policy requires signed approvals and this one has none.
    MissingSignature,
    /// The signature does not verify against the approver key and message.
    InvalidSignature,
    /// The approval carries a signature but this build cannot verify it
    /// (enable the `ed25519` feature).
    SignaturesUnsupported,
    /// The policy is malformed (threshold above the approver count, ...).
    InvalidPolicy(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotAnApprover => write!(f, "not an approver under this policy"),
            Error::MissingSignature => write!(f, "this policy requires a signed approval"),
            Error::InvalidSignature => write!(f, "signature does not verify"),
            Error::SignaturesUnsupported => {
                write!(f, "signed approvals need the ed25519 feature")
            }
            Error::InvalidPolicy(why) => write!(f, "invalid policy: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Serde helpers: byte vectors as lowercase hex, so stored and logged
/// records read as text.
pub(crate) mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(b) => s.serialize_some(&hex::encode(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            let s: Option<String> = Option::deserialize(d)?;
            s.map(|s| hex::decode(s).map_err(serde::de::Error::custom)).transpose()
        }
    }

    pub mod arr32 {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&hex::encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let s = String::deserialize(d)?;
            let v = hex::decode(s).map_err(serde::de::Error::custom)?;
            v.try_into()
                .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        }
    }
}
