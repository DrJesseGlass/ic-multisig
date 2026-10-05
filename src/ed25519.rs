//! Signed approvals with Ed25519. The approver identity is the 32-byte
//! verifying key; the signature covers [`Approval::message`]: the subject,
//! the decision and the time, and for an objection its reason.
//!
//! This is the flavor that leaves the canister. A signed approval is a
//! bearer record: whoever holds it can present it anywhere, and anyone
//! holding the [`Policy`](crate::Policy) can check it -- a browser counting
//! attestations on a module hash, a contract on another chain -- without
//! trusting the canister that stored it.
//!
//! ```
//! use ic_multisig::ed25519::{self, SigningKey};
//! use ic_multisig::{record, Approver, Decision, MemoryStore, Policy, Subject};
//!
//! let key = SigningKey::from_bytes(&[1u8; 32]);
//! let policy = Policy::signed([Approver::from_bytes(key.verifying_key().to_bytes())], 1);
//! let subject = Subject::of_bytes("module", b"wasm bytes");
//!
//! let approval = ed25519::sign(&subject, &key, Decision::Approve, 100);
//! assert!(ed25519::verify(&subject, &approval).is_ok());
//!
//! // The same record presented against another subject does not verify.
//! let other = Subject::of_bytes("module", b"other wasm");
//! assert!(ed25519::verify(&other, &approval).is_err());
//!
//! let t = record(&mut MemoryStore::default(), &policy, &subject, approval)?;
//! assert!(t.reached);
//! # Ok::<(), ic_multisig::Error>(())
//! ```

use crate::approval::{Approval, Approver, Decision};
use crate::subject::Subject;
use crate::Error;
use ed25519_dalek::Signer;

/// The `ed25519-dalek` types this module's signatures are written in.
///
/// They are re-exported because [`sign`] takes a `SigningKey` and there is
/// no way to build one without naming the type. A caller who adds
/// `ed25519-dalek` to their own manifest to get it can easily end up with
/// a different major version than this crate resolved, and then their
/// `SigningKey` is a different type from the one `sign` wants -- a
/// mismatch rustc reports as `expected SigningKey, found SigningKey`,
/// which is not the most helpful sentence it has ever produced. Take the
/// types from here and the question cannot come up.
///
/// This crate tracks `ed25519-dalek` 2. If you need version 3 in the same
/// binary, both can coexist; only the keys crossing this module's API have
/// to come from here.
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Produce a signed approval. For clients, tests, and off-chain attesters.
///
/// The approver is derived from `key`, so a signed approval always names
/// the key that signed it; `at_ns` is the signer's own claim about when,
/// which the supersede rule in [`cast`](crate::cast) reads.
///
/// For an approval or a rejection. An objection needs its reason inside
/// the signature and is made by [`sign_objection`]; `Decision::Object`
/// passed here signs an objection with no reason, which every count
/// refuses.
pub fn sign(subject: &Subject, key: &SigningKey, decision: Decision, at_ns: u64) -> Approval {
    seal(subject, key, Approval::new(approver(key), decision, at_ns))
}

/// Produce a signed objection. The signature covers the reason, so the
/// record cannot be relayed with a different one, or with the decision
/// changed.
///
/// ```
/// use ic_multisig::ed25519::{self, SigningKey};
/// use ic_multisig::Subject;
///
/// let key = SigningKey::from_bytes(&[1u8; 32]);
/// let subject = Subject::of_bytes("module", b"wasm bytes");
///
/// let mut objection = ed25519::sign_objection(&subject, &key, "not the audited build", 100);
/// assert!(ed25519::verify(&subject, &objection).is_ok());
///
/// objection.reason = Some("looks fine".into());
/// assert!(ed25519::verify(&subject, &objection).is_err());
/// ```
pub fn sign_objection(
    subject: &Subject,
    key: &SigningKey,
    reason: impl Into<String>,
    at_ns: u64,
) -> Approval {
    seal(subject, key, Approval::objection(approver(key), reason, at_ns))
}

fn approver(key: &SigningKey) -> Approver {
    Approver::from_bytes(key.verifying_key().to_bytes())
}

fn seal(subject: &Subject, key: &SigningKey, mut a: Approval) -> Approval {
    let sig: Signature = key.sign(&a.message(subject));
    a.signature = Some(sig.to_bytes().to_vec());
    a
}

/// Check an approval's signature against its approver key and the subject.
///
/// Strict verification: a small-order (weak) key or `R` is refused. Under
/// plain `verify`, a policy listing the identity point would accept one
/// fixed signature for every message, letting anyone vote as that approver.
///
/// A reason on anything but an objection is refused as
/// [`Error::UnsignedReason`]: the message an approval or a rejection signs
/// is the one 0.1 signed, which has no reason in it, so a reason on such a
/// record is text the signature says nothing about.
pub fn verify(subject: &Subject, approval: &Approval) -> Result<(), Error> {
    let sig = approval.signature.as_ref().ok_or(Error::MissingSignature)?;
    if approval.reason.is_some() && !approval.objects() {
        return Err(Error::UnsignedReason);
    }
    let key = VerifyingKey::try_from(approval.approver.as_bytes())
        .map_err(|_| Error::InvalidSignature)?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
    key.verify_strict(&approval.message(subject), &sig)
        .map_err(|_| Error::InvalidSignature)
}
