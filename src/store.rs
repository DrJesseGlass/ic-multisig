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
    fn save(&mut self, subject: &Subject, ballots: Vec<Approval>);
}

#[derive(Default, Debug)]
pub struct MemoryStore(BTreeMap<String, Vec<Approval>>);

impl Store for MemoryStore {
    fn load(&self, subject: &Subject) -> Vec<Approval> {
        self.0.get(&subject.key()).cloned().unwrap_or_default()
    }

    fn save(&mut self, subject: &Subject, ballots: Vec<Approval>) {
        self.0.insert(subject.key(), ballots);
    }
}

/// Validate an approval against the policy, persist it, and return the new
/// tally. This is the one entry point a canister endpoint should call: it
/// refuses outsiders, enforces the policy's signature rule, refuses a
/// ballot older than the approver's recorded one, and verifies any
/// signature present. A signature this build cannot verify (no `ed25519`
/// feature, or an approver that is not a 32-byte key) is refused rather
/// than stored unchecked, whatever the policy's signature rule says.
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
    if !cast(&mut ballots, approval) {
        return Err(Error::Superseded);
    }
    let t = tally(policy, &ballots);
    store.save(subject, ballots);
    Ok(t)
}

#[cfg(feature = "ed25519")]
use crate::ed25519::verify;

#[cfg(not(feature = "ed25519"))]
fn verify(_subject: &Subject, _approval: &Approval) -> Result<(), Error> {
    Err(Error::SignaturesUnsupported)
}
