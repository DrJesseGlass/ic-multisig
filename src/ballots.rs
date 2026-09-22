use crate::approval::Approval;
use crate::subject::Subject;

/// Ballots that may be counted, and the subject they are about.
///
/// An [`Approval`] is an inert record: `approver` is whatever bytes its
/// author put there. What makes one evidence is something that happened
/// outside the record -- the IC authenticated the caller who submitted it,
/// or its signature verified against the approver's key -- and neither
/// fact is visible in the record itself. So counting goes through this
/// type rather than a raw slice: to count ballots you must first say, by
/// choosing a constructor, which of the two you are relying on.
///
/// The subject is part of the value because a signature is only ever
/// evidence about one subject. Carrying a `Ballots` verified against one
/// module hash to the count of another would otherwise be a bookkeeping
/// slip that nothing catches; [`tally_checked`](crate::tally_checked)
/// catches it.
///
/// [`tally`](crate::tally) is the shorthand that verifies and counts in
/// one step, and [`record`](crate::record) builds one internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ballots {
    subject: Subject,
    kept: Vec<Approval>,
    rejected: Vec<Approval>,
}

impl Ballots {
    /// Keep the records that carry a signature valid for `subject`, and
    /// set every other record aside in [`Ballots::rejected`].
    ///
    /// This is the constructor for records that arrived over a path you do
    /// not control: a verifier collecting signed attestations on a module
    /// hash, a browser counting them against a keyset it trusts.
    ///
    /// A record with no signature is rejected too. It may be perfectly
    /// honest -- an approval the IC authenticated inside a canister needs
    /// no signature -- but nothing here can tell that from a record an
    /// attacker typed, and this constructor's whole job is to answer that
    /// question by checking. An unsigned record whose authenticity you
    /// know by other means belongs in [`Ballots::assume_checked`], where
    /// the knowing is explicit.
    ///
    /// Fail-closed in a build without the `ed25519` feature: no signature
    /// can be checked, so every record is rejected rather than taken on
    /// trust.
    pub fn verified(subject: &Subject, records: impl IntoIterator<Item = Approval>) -> Self {
        let mut b = Ballots::empty(subject);
        for r in records {
            match r.signature {
                Some(_) if verify(subject, &r).is_ok() => b.kept.push(r),
                _ => b.rejected.push(r),
            }
        }
        b
    }

    /// Take the records as they are, checking nothing.
    ///
    /// Two callers may. A canister whose approvers are the authenticated
    /// callers of its update calls: the IC established who they were and
    /// there is no signature to check. And anything reading back a store
    /// that [`record`](crate::record) wrote, where every record was
    /// checked on the way in.
    ///
    /// Anything else -- in particular records that crossed a network or
    /// were read from a file -- wants [`Ballots::verified`]. The name is
    /// the warning: this asserts a fact the type cannot check.
    pub fn assume_checked(subject: &Subject, records: impl IntoIterator<Item = Approval>) -> Self {
        Ballots {
            kept: records.into_iter().collect(),
            ..Ballots::empty(subject)
        }
    }

    fn empty(subject: &Subject) -> Self {
        Ballots {
            subject: subject.clone(),
            kept: Vec::new(),
            rejected: Vec::new(),
        }
    }

    /// What these ballots are about. Set by the constructor, and what
    /// [`tally_checked`](crate::tally_checked) checks its own argument
    /// against.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// The records that will be counted.
    pub fn as_slice(&self) -> &[Approval] {
        &self.kept
    }

    /// The records [`Ballots::verified`] threw out, in the order they came
    /// in. Kept rather than dropped so a verifier can log or show what it
    /// refused instead of silently reporting a lower count.
    pub fn rejected(&self) -> &[Approval] {
        &self.rejected
    }

    /// The records that will be counted, by value.
    pub fn into_vec(self) -> Vec<Approval> {
        self.kept
    }

    /// How many records will be counted. Not the number of approvers: an
    /// approver with two ballots here is one voter at the count.
    pub fn len(&self) -> usize {
        self.kept.len()
    }

    /// Whether there is nothing to count.
    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }
}

/// Signature verification as the rest of the crate sees it: the real
/// check when the feature is on, a refusal when it is off. Every path
/// that could take a signature on trust goes through here, so a build
/// without `ed25519` cannot silently become a build that accepts
/// anything.
#[cfg(feature = "ed25519")]
pub(crate) use crate::ed25519::verify;

#[cfg(not(feature = "ed25519"))]
pub(crate) fn verify(_subject: &Subject, _approval: &Approval) -> Result<(), crate::Error> {
    Err(crate::Error::SignaturesUnsupported)
}
