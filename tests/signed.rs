#![cfg(feature = "ed25519")]
use ed25519_dalek::SigningKey;
use ic_multisig::{ed25519, record, Approver, Decision, Error, MemoryStore, Policy, Subject};

#[test]
fn signed_approvals_verify_and_tampering_fails() {
    let k1 = SigningKey::from_bytes(&[1u8; 32]);
    let k2 = SigningKey::from_bytes(&[2u8; 32]);
    let policy = Policy::signed(
        [
            Approver::from_bytes(k1.verifying_key().to_bytes()),
            Approver::from_bytes(k2.verifying_key().to_bytes()),
        ],
        2,
    );
    let subject = Subject::of_bytes("module", b"wasm bytes");
    let mut store = MemoryStore::default();

    let a1 = ed25519::sign(&subject, &k1, Decision::Approve, 100);
    let t = record(&mut store, &policy, &subject, a1.clone()).unwrap();
    assert_eq!((t.approvals, t.reached), (1, false));

    // Same signature presented for a different subject: refused.
    let other = Subject::of_bytes("module", b"other wasm");
    assert_eq!(
        record(&mut store, &policy, &other, a1.clone()).unwrap_err(),
        Error::InvalidSignature
    );
    // Flipping the decision under the old signature: refused.
    let mut flipped = a1.clone();
    flipped.decision = Decision::Reject;
    assert_eq!(
        record(&mut store, &policy, &subject, flipped).unwrap_err(),
        Error::InvalidSignature
    );
    // A key outside the policy, even with a valid signature: refused.
    let k9 = SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(
        record(&mut store, &policy, &subject, ed25519::sign(&subject, &k9, Decision::Approve, 1)).unwrap_err(),
        Error::NotAnApprover
    );
    let t = record(&mut store, &policy, &subject, ed25519::sign(&subject, &k2, Decision::Approve, 101)).unwrap();
    assert!(t.reached);
}

#[test]
fn weak_keys_are_refused() {
    // The identity point as an approver key, with R = identity and S = 0,
    // satisfies non-strict Ed25519 verification for every message: anyone
    // could vote as that approver on any subject. Strict verification
    // refuses it.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = vec![0u8; 64];
    sig[..32].copy_from_slice(&identity);
    let policy = Policy::signed([Approver::from_bytes(identity)], 1);
    let subject = Subject::of_bytes("module", b"wasm bytes");
    let mut forged = ic_multisig::Approval::new(Approver::from_bytes(identity), Decision::Approve, 1);
    forged.signature = Some(sig);
    assert_eq!(ed25519::verify(&subject, &forged).unwrap_err(), Error::InvalidSignature);
    assert_eq!(
        record(&mut MemoryStore::default(), &policy, &subject, forged).unwrap_err(),
        Error::InvalidSignature
    );
}
