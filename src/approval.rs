use crate::subject::Subject;
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The longest reason a ballot may carry, in bytes of UTF-8. Room for a
/// sentence or a link, which is what a reason is; the argument itself
/// belongs wherever the link points.
pub const MAX_REASON_BYTES: usize = 1024;

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
    /// Does not, and counts against nothing: "no", or an approval
    /// withdrawn. A rejection is recorded rather than dropped so a tally
    /// can tell "voted no" from "has not voted", and so that replacing it
    /// later with an approval needs a newer ballot.
    Reject,
    /// Counts against: a subject with an objection needs one more approval
    /// to be reached. It blocks nothing on its own -- there is no veto --
    /// and it must say why, in [`Approval::reason`].
    Object,
}

/// One approver's ballot on one subject.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Approval {
    /// Who cast it. For a signed approval this is also the verifying key
    /// the signature is checked against.
    pub approver: Approver,
    /// Approve, reject or object.
    pub decision: Decision,
    /// When it was cast, nanoseconds since the epoch (the canister's clock,
    /// or the signer's claim for a signed approval).
    pub at_ns: u64,
    /// Present for signed approvals: a signature over [`Approval::message`].
    #[serde(default, with = "crate::hexbytes::opt", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    /// Why: a short text or a link, at most [`MAX_REASON_BYTES`]. Required
    /// on an objection and allowed on any unsigned ballot. A signed ballot
    /// may carry one only when it is an objection, the one case where the
    /// signature covers it (see [`Approval::message`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
            reason: None,
        }
    }

    /// An unsigned objection, which is a ballot with a reason. Use
    /// `ed25519::sign_objection` for one that has to be checkable
    /// off-chain.
    ///
    /// ```
    /// use ic_multisig::{Approval, Approver, Decision};
    ///
    /// let a = Approval::objection(Approver::from_bytes(b"alice"), "skips the migration", 1_000);
    /// assert_eq!(a.decision, Decision::Object);
    /// assert!(a.validate().is_ok());
    /// ```
    pub fn objection(approver: Approver, reason: impl Into<String>, at_ns: u64) -> Self {
        Approval::new(approver, Decision::Object, at_ns).with_reason(reason)
    }

    /// The same ballot carrying `reason`. For saying why on an approval or
    /// a rejection; [`Approval::objection`] already takes one. Not for a
    /// ballot that is already signed: attached afterwards, the reason is
    /// either outside what was signed or changes it.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Whether this ballot counts toward the threshold.
    pub fn approves(&self) -> bool {
        self.decision == Decision::Approve
    }

    /// Whether this ballot counts against the threshold.
    pub fn objects(&self) -> bool {
        self.decision == Decision::Object
    }

    /// The rules a record must meet whatever the policy says: an objection
    /// carries a reason, and no reason is longer than
    /// [`MAX_REASON_BYTES`]. A reason that is empty or all whitespace is
    /// no reason.
    ///
    /// [`record`](crate::record) refuses a ballot that fails this, and both
    /// counts treat one as invalid, so an objection cannot cost the
    /// subject an approval without saying what is wrong with it.
    ///
    /// ```
    /// use ic_multisig::{Approval, Approver, Decision, Error};
    ///
    /// let alice = Approver::from_bytes(b"alice");
    /// let bare = Approval::new(alice.clone(), Decision::Object, 1_000);
    /// assert_eq!(bare.validate(), Err(Error::MissingReason));
    /// assert!(bare.with_reason("see issue 12").validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        match &self.reason {
            Some(r) if r.len() > MAX_REASON_BYTES => Err(Error::ReasonTooLong),
            Some(r) if !r.trim().is_empty() => Ok(()),
            _ if self.objects() => Err(Error::MissingReason),
            _ => Ok(()),
        }
    }

    /// The bytes a signed approval signs: the subject's canonical form, the
    /// decision, and the time, each domain-separated so a signature over one
    /// subject or decision can never be replayed as another.
    ///
    /// The time is part of the message, which is what makes the
    /// supersede rule in [`cast`](crate::cast) enforceable: an old signed
    /// ballot cannot be re-dated without invalidating its signature.
    ///
    /// # Layout
    ///
    /// For an approval or a rejection, exactly what 0.1 signed, so every
    /// signature made then still verifies:
    ///
    /// ```text
    /// canonical(subject) || 0 || decision || 0 || at_ns (8 bytes, LE)
    /// ```
    ///
    /// with `decision` 1 to approve and 0 to reject. The reason is not in
    /// it, which is why a signed approval or rejection may not carry one:
    /// `ed25519::verify` refuses a reason the signature says nothing
    /// about, rather than present a relayer's words as the signer's.
    ///
    /// An objection signs its reason too, as a sha256:
    ///
    /// ```text
    /// canonical(subject) || 0 || sha256(reason) || 0 || 2 || 0 || at_ns
    /// ```
    ///
    /// The hash goes in ahead of the decision rather than after the time
    /// so that every message, old or new, ends the same way: the decision
    /// is the tenth byte from the end, and reading from the end is how the
    /// encoding stays unambiguous whatever bytes a subject's kind holds.
    /// With the hash last, those ten bytes would be the signer's to choose
    /// by choosing a reason, and an objection could be shaped to read as
    /// an approval of some other subject.
    pub fn message(&self, subject: &Subject) -> Vec<u8> {
        let mut m = subject.canonical();
        m.push(0);
        if self.objects() {
            // An objection with no reason signs the hash of nothing. It
            // can be signed, and `validate` refuses it everywhere.
            let reason = self.reason.as_deref().unwrap_or_default();
            m.extend_from_slice(&Sha256::digest(reason.as_bytes()));
            m.push(0);
        }
        m.push(match self.decision {
            Decision::Reject => 0,
            Decision::Approve => 1,
            Decision::Object => 2,
        });
        m.push(0);
        m.extend_from_slice(&self.at_ns.to_le_bytes());
        m
    }
}
