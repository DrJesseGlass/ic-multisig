use crate::subject::Subject;
use serde::{Deserialize, Serialize};

/// Who approves. Bytes, compared bytewise: an IC principal for
/// authenticated approvals, a public key for signed ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Approver(#[serde(with = "crate::hexbytes")] pub Vec<u8>);

impl Approver {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Approver(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The approver as a principal, when it is one.
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub enum Decision {
    Approve,
    Reject,
}

/// One approver's ballot on one subject.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Approval {
    pub approver: Approver,
    pub decision: Decision,
    /// When it was cast, nanoseconds since the epoch (the canister's clock,
    /// or the signer's claim for a signed approval).
    pub at_ns: u64,
    /// Present for signed approvals: a signature over [`Approval::message`].
    #[serde(default, with = "crate::hexbytes::opt", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl Approval {
    pub fn new(approver: Approver, decision: Decision, at_ns: u64) -> Self {
        Approval {
            approver,
            decision,
            at_ns,
            signature: None,
        }
    }

    pub fn approves(&self) -> bool {
        self.decision == Decision::Approve
    }

    /// The bytes a signed approval signs: the subject's canonical form, the
    /// decision, and the time, each domain-separated so a signature over one
    /// subject or decision can never be replayed as another.
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
