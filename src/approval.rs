use crate::subject::Subject;
use serde::{Deserialize, Serialize};

/// Who approves. Bytes, compared bytewise: an IC principal for
/// authenticated approvals, a public key for signed ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Approver(#[serde(with = "crate::hexbytes")] pub Vec<u8>);

impl Approver {
    /// An approver from raw bytes: principal bytes for an authenticated
    /// approval, a 32-byte verifying key for a signed one. No validation --
    /// what makes an approver legitimate is being named by the
    /// [`Policy`](crate::Policy), not the shape of its bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Approver(bytes.into())
    }

    /// The identity bytes, as stored and as compared.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The approver as a principal, when it can be one. Any blob of at
    /// most 29 bytes is a principal by the IC's definition, so this is
    /// `Some` for short opaque ids too; a 32-byte signing key never is.
    #[cfg(feature = "candid")]
    pub fn principal(&self) -> Option<candid::Principal> {
        candid::Principal::try_from_slice(&self.0).ok()
    }
}

#[cfg(feature = "candid")]
impl From<candid::Principal> for Approver {
    fn from(p: candid::Principal) -> Self {
        Approver(p.as_slice().to_vec())
    }
}

impl core::fmt::Display for Approver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "candid")]
        if let Some(p) = self.principal() {
            return write!(f, "{p}");
        }
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Which way an approver voted.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub enum Decision {
    /// Counts toward the threshold.
    Approve,
    /// Does not. A rejection is recorded rather than dropped so a tally can
    /// tell "voted no" from "has not voted", and so that replacing it later
    /// with an approval needs a newer ballot.
    Reject,
}

/// One approver's ballot on one subject.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Approval {
    /// Who cast it. For a signed approval this is also the verifying key
    /// the signature is checked against.
    pub approver: Approver,
    /// Approve or reject.
    pub decision: Decision,
    /// When it was cast, nanoseconds since the epoch (the canister's clock,
    /// or the signer's claim for a signed approval).
    pub at_ns: u64,
    /// Present for signed approvals: a signature over [`Approval::message`].
    #[serde(default, with = "crate::hexbytes::opt", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl Approval {
    /// An unsigned ballot. Inside a canister this is the whole record: the
    /// IC authenticated the caller, so there is nothing left to prove. Use
    /// `ed25519::sign` when the approval has to be checkable off-chain.
    pub fn new(approver: Approver, decision: Decision, at_ns: u64) -> Self {
        Approval {
            approver,
            decision,
            at_ns,
            signature: None,
        }
    }

    /// Whether this ballot counts toward the threshold.
    pub fn approves(&self) -> bool {
        self.decision == Decision::Approve
    }

    /// The bytes a signed approval signs: the subject's canonical form, the
    /// decision, and the time, each domain-separated so a signature over one
    /// subject or decision can never be replayed as another.
    ///
    /// The time is part of the message, which is what makes the
    /// supersede rule in [`cast`](crate::cast) enforceable: an old signed
    /// ballot cannot be re-dated without invalidating its signature.
    pub fn message(&self, subject: &Subject) -> Vec<u8> {
        let mut m = subject.canonical();
        m.push(0);
        m.push(match self.decision {
            Decision::Approve => 1,
            Decision::Reject => 0,
        });
        m.push(0);
        m.extend_from_slice(&self.at_ns.to_le_bytes());
        m
    }
}
