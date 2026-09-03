use crate::approval::Approval;
use crate::policy::Policy;
use crate::subject::Subject;
use crate::tally::{cast, tally, Tally};
use crate::Error;
use std::collections::BTreeMap;

/// Where ballots live. A canister implements this over a stable map keyed
/// by [`Subject::key`]; tests use [`MemoryStore`].
pub trait Store {
    fn load(&self, subject: &Subject) -> Vec<Approval>;
    fn save(&mut self, subject: &Subject, ballots: &[Approval]);
}

#[derive(Default, Debug)]
pub struct MemoryStore(BTreeMap<String, Vec<Approval>>);

impl Store for MemoryStore {
    fn load(&self, subject: &Subject) -> Vec<Approval> {
        self.0.get(&subject.key()).cloned().unwrap_or_default()
    }

    fn save(&mut self, subject: &Subject, ballots: &[Approval]) {
        self.0.insert(subject.key(), ballots.to_vec());
    }
}

/// Validate an approval against the policy, persist it, and return the new
/// tally. This is the one entry point a canister endpoint should call: it
/// refuses outsiders, enforces the policy's signature rule, and verifies a
/// signature when one is present and the build can.
pub fn record(
    store: &mut impl Store,
    policy: &Policy,
    subject: &Subject,
    approval: Approval,
) -> Result<Tally, Error> {
    policy.validate()?;
    if !policy.is_approver(&approval.approver) {
        return Err(Error::NotAnApprover);
    }
    match &approval.signature {
        None if policy.require_signature => return Err(Error::MissingSignature),
        None => {}
        Some(_) => verify(subject, &approval)?,
    }
    let mut ballots = store.load(subject);
    cast(&mut ballots, approval);
    store.save(subject, &ballots);
    Ok(tally(policy, &ballots))
}

#[cfg(feature = "ed25519")]
fn verify(subject: &Subject, approval: &Approval) -> Result<(), Error> {
    crate::ed25519::verify(subject, approval)
}

#[cfg(not(feature = "ed25519"))]
fn verify(_subject: &Subject, _approval: &Approval) -> Result<(), Error> {
    Err(Error::SignaturesUnsupported)
}
