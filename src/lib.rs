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
    /// The approver already has a ballot on this subject with a later
    /// `at_ns`. Replaying an old signed ballot must not undo a newer one.
    Superseded,
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
            Error::Superseded => write!(f, "a later ballot by this approver is already recorded"),
        }
    }
}

impl std::error::Error for Error {}

/// Serde helpers for byte fields: lowercase hex in human-readable formats
/// (JSON), so stored and logged records read as text, and raw bytes
/// elsewhere. The raw path is what makes the `candid` feature work: the
/// `CandidType` derive advertises these fields as `vec nat8`, and Candid
/// decoding runs through serde, so the visitor here has to accept bytes.
pub(crate) mod hexbytes {
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]> + ?Sized>(
        bytes: &T,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(bytes))
        } else {
            s.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(BytesVisitor)
        } else {
            d.deserialize_byte_buf(BytesVisitor)
        }
    }

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            f.write_str("hex text or bytes")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            hex::decode(v).map_err(de::Error::custom)
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(b) = seq.next_element()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    /// The two functions above as a value type, so `Option` can lean on
    /// serde's own `Option` handling (Candid's decoder accepts no other).
    struct Bytes(Vec<u8>);

    impl Serialize for Bytes {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self::serialize(&self.0, s)
        }
    }

    impl<'de> Deserialize<'de> for Bytes {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            self::deserialize(d).map(Bytes)
        }
    }

    pub mod opt {
        use super::Bytes;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            // Borrow rather than clone: serialize through a shim that looks
            // like `Bytes` to the format but holds a reference.
            struct Ref<'a>(&'a [u8]);
            impl Serialize for Ref<'_> {
                fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    super::serialize(self.0, s)
                }
            }
            match v {
                Some(b) => s.serialize_some(&Ref(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            Option::<Bytes>::deserialize(d).map(|o| o.map(|b| b.0))
        }
    }

    pub mod arr32 {
        pub use super::serialize;
        use serde::Deserializer;

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            super::deserialize(d)?
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        }
    }
}
