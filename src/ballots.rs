use crate::approval::Approval;
use crate::subject::Subject;

/// A ballot list that has already been accounted for, so that counting it
/// is not counting a forgery.
///
/// An [`Approval`] is an inert record: `approver` is whatever bytes its
/// author put there. What makes it evidence is one of two things having
/// happened -- the IC authenticated the caller who submitted it, or its
/// signature verified against the approver's key. Neither is visible in
/// the record itself, so [`tally_checked`](crate::tally_checked) asks for
/// this type instead of a raw slice: to count ballots you must first say,
/// by choosing a constructor, which of the two you are relying on.
///
/// [`tally`](crate::tally) is the shorthand that verifies and counts in
/// one step, and [`record`](crate::record) builds one internally.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ballots {
    kept: Vec<Approval>,
    rejected: Vec<Approval>,
}

impl Ballots {
    /// Check every signature against `subject`, keeping the records that
    /// pass and setting the failures aside in [`Ballots::rejected`].
    ///
    /// This is the constructor for records that arrived over an untrusted
    /// path: a verifier collecting signed attestations on a module hash, a
    /// browser counting them against a keyset it trusts.
    ///
    /// A record carrying *no* signature is kept, not rejected, because a
    /// missing signature is not a forged one -- whether an unsigned record
    /// may count is [`Policy::require_signature`](crate::Policy), and the
    /// counting step applies it. A verifier holding untrusted records
    /// therefore wants a [`Policy::signed`](crate::Policy::signed) policy:
    /// this constructor throws out invalid signatures, and that policy
    /// throws out absent ones.
    ///
    /// Fail-closed in a build without the `ed25519` feature: no signature
    /// can be checked, so every signed record is rejected rather than
    /// taken on trust.
    pub fn verified(subject: &Subject, records: impl IntoIterator<Item = Approval>) -> Self {
        let mut b = Ballots::default();
        for r in records {
            match r.signature {
                Some(_) if verify(subject, &r).is_err() => b.rejected.push(r),
                _ => b.kept.push(r),
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
    pub fn assume_checked(records: impl IntoIterator<Item = Approval>) -> Self {
        Ballots {
            kept: records.into_iter().collect(),
            rejected: Vec::new(),
        }
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
