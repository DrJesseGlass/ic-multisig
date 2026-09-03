//! Signed approvals with Ed25519. The approver identity is the 32-byte
//! verifying key; the signature covers [`Approval::message`].

use crate::approval::{Approval, Approver, Decision};
use crate::subject::Subject;
use crate::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Produce a signed approval. For clients, tests, and off-chain attesters.
pub fn sign(subject: &Subject, key: &SigningKey, decision: Decision, at_ns: u64) -> Approval {
    let mut a = Approval::new(
        Approver::from_bytes(key.verifying_key().to_bytes()),
        decision,
        at_ns,
    );
    let sig: Signature = key.sign(&a.message(subject));
    a.signature = Some(sig.to_bytes().to_vec());
    a
}

/// Check an approval's signature against its approver key and the subject.
pub fn verify(subject: &Subject, approval: &Approval) -> Result<(), Error> {
    let sig_bytes = approval.signature.as_ref().ok_or(Error::MissingSignature)?;
    let key_bytes: [u8; 32] = approval
        .approver
        .as_bytes()
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::InvalidSignature)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify(&approval.message(subject), &sig)
        .map_err(|_| Error::InvalidSignature)
}
