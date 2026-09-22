use crate::approval::Approver;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// N approvers and a threshold K. `threshold == 0` means no approval is
/// needed and every subject is reached; that is the "deploy on push" default
/// a consumer starts from.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Policy {
    /// The N. Held as a set, so an approver listed twice still gets one
    /// vote and the count in [`Policy::validate`] is the real one.
    pub approvers: BTreeSet<Approver>,
    /// The K: how many approvals a subject needs before it is reached.
    pub threshold: u32,
    /// Refuse approvals that carry no signature. For policies whose
    /// approvers are public keys rather than principals.
    #[serde(default)]
    pub require_signature: bool,
}

impl Policy {
    /// A policy whose approvals need no signature: the approver is
    /// authenticated by the IC as the caller of an update call.
    ///
    /// ```
    /// use ic_multisig::{Approver, Policy};
    ///
    /// let p = Policy::new([Approver::from_bytes(b"alice"), Approver::from_bytes(b"bob")], 2);
    /// assert_eq!(p.threshold, 2);
    /// assert!(p.validate().is_ok());
    /// ```
    pub fn new(approvers: impl IntoIterator<Item = Approver>, threshold: u32) -> Self {
        Policy {
            approvers: approvers.into_iter().collect(),
            threshold,
            require_signature: false,
        }
    }

    /// The same, with `require_signature` set: every approval must carry a
    /// signature over [`Approval::message`](crate::Approval::message). The
    /// approvers are 32-byte verifying keys, not principals, and the result
    /// is checkable by anyone holding the policy -- a browser, another
    /// chain -- without asking the canister.
    pub fn signed(approvers: impl IntoIterator<Item = Approver>, threshold: u32) -> Self {
        Policy {
            require_signature: true,
            ..Policy::new(approvers, threshold)
        }
    }

    /// Whether `a` is named by this policy right now. Membership is checked
    /// at tally time, not at cast time, so removing an approver retires
    /// their ballot too.
    pub fn is_approver(&self, a: &Approver) -> bool {
        self.approvers.contains(a)
    }

    /// A threshold no set of approvers could ever reach is a configuration
    /// error, not a very strict policy. [`record`](crate::record) calls
    /// this before anything else, so a malformed policy is refused at the
    /// first ballot rather than silently never reaching its threshold.
    ///
    /// ```
    /// use ic_multisig::{Approver, Policy};
    ///
    /// let p = Policy::new([Approver::from_bytes(b"alice")], 2);
    /// assert!(p.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        if self.threshold as usize > self.approvers.len() {
            return Err(Error::InvalidPolicy(format!(
                "threshold {} exceeds {} approvers",
                self.threshold,
                self.approvers.len()
            )));
        }
        Ok(())
    }
}
