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
    pub approvers: BTreeSet<Approver>,
    pub threshold: u32,
    /// Refuse approvals that carry no signature. For policies whose
    /// approvers are public keys rather than principals.
    #[serde(default)]
    pub require_signature: bool,
}

impl Policy {
    pub fn new(approvers: impl IntoIterator<Item = Approver>, threshold: u32) -> Self {
        Policy {
            approvers: approvers.into_iter().collect(),
            threshold,
            require_signature: false,
        }
    }

    pub fn signed(approvers: impl IntoIterator<Item = Approver>, threshold: u32) -> Self {
        Policy {
            require_signature: true,
            ..Policy::new(approvers, threshold)
        }
    }

    pub fn is_approver(&self, a: &Approver) -> bool {
        self.approvers.contains(a)
    }

    /// A threshold no set of approvers could ever reach is a configuration
    /// error, not a very strict policy.
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
