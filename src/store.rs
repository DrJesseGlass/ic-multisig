use crate::approval::Approval;
use crate::ballots::{verify, Ballots};
use crate::policy::Policy;
use crate::subject::Subject;
use crate::tally::{cast, tally_checked, Tally};
use crate::Error;
use std::collections::BTreeMap;

/// Where ballots live. A canister implements this over a stable map keyed
/// by [`Subject::key`]; tests use [`MemoryStore`].
///
/// # Contract
///
/// A store holds only what [`record`] put there. `record` checks each
/// ballot on the way in and then counts what comes back out without
/// checking it again, so an implementation that admits records by any
/// other route -- a migration, a test fixture, a second writer -- is
/// handing the count things nothing verified. Where that is unavoidable,
/// count with [`Ballots::verified`](crate::Ballots::verified) instead of
/// relying on `record`'s return value.
pub trait Store {
    /// Every ballot recorded against `subject`, in any order. An unknown
    /// subject has none, which is an empty vector, not an error.
    fn load(&self, subject: &Subject) -> Vec<Approval>;
    /// Replace the ballots for `subject` with `ballots`. [`record`] reads,
    /// applies one ballot, and writes the whole list back, so an
    /// implementation needs no merge rule of its own.
    fn save(&mut self, subject: &Subject, ballots: Vec<Approval>);
}

/// A [`Store`] in a `BTreeMap`, for tests and for host-side verifiers that
/// tally a collected set of signed approvals without persisting anything.
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
///
/// ```
/// use ic_multisig::{record, Approval, Approver, Decision, MemoryStore, Policy, Subject};
///
/// let alice = Approver::from_bytes(b"alice");
/// let bob = Approver::from_bytes(b"bob");
/// let policy = Policy::new([alice.clone(), bob.clone()], 2);
/// let subject = Subject::of_short_hash("commit", &[0xabu8; 20]);
/// let mut store = MemoryStore::default();
///
/// let t = record(&mut store, &policy, &subject,
///     Approval::new(alice, Decision::Approve, 1_000))?;
/// assert!(!t.reached);
///
/// let t = record(&mut store, &policy, &subject,
///     Approval::new(bob, Decision::Approve, 2_000))?;
/// assert!(t.reached);
///
/// // An approver the policy does not name is refused, not counted.
/// let mallory = Approver::from_bytes(b"mallory");
/// assert!(record(&mut store, &policy, &subject,
///     Approval::new(mallory, Decision::Reject, 3_000)).is_err());
/// # Ok::<(), ic_multisig::Error>(())
/// ```
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
    // Each ballot was verified above before it was ever stored, so the
    // count does not verify them again: that would be a signature check
    // per stored ballot on every update call, for an answer already known.
    let ballots = Ballots::assume_checked(subject, ballots);
    let t = tally_checked(policy, subject, &ballots);
    store.save(subject, ballots.into_vec());
    Ok(t)
}
