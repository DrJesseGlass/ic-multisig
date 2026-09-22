// An Approval is an inert record: `approver` is whatever bytes its author
// typed. Everything here is about the gap that opens when something counts
// one without first establishing where it came from -- and about the order
// in which the count throws the bad ones out, which turns out to matter as
// much as throwing them out at all.

use ic_multisig::{tally, tally_checked, Approval, Approver, Ballots, Decision, Policy, Subject};

fn subject() -> Subject {
    Subject::of_bytes("module", b"wasm bytes")
}

#[test]
fn an_unsigned_record_naming_an_approver_is_not_counted() {
    // The plain forgery: no key, no signature, just an authorized approver's
    // public bytes copied into a record. Under a signed policy it is
    // invalid, and invalid is not a vote.
    let key = Approver::from_bytes([7u8; 32]);
    let policy = Policy::signed([key.clone()], 1);
    let forged = Approval::new(key, Decision::Approve, 1_000);

    let t = tally(&policy, &subject(), &[forged]);
    assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
}

#[test]
fn an_unsigned_record_cannot_suppress_a_real_one() {
    // The subtler attack, and the reason refused records are dropped before
    // the latest-ballot rule rather than after. An attacker who cannot forge
    // a vote can still write a record naming an honest approver, dated far
    // in the future. If that record were allowed to be a candidate, it would
    // supersede the approver's real ballot and the approval would vanish --
    // and suppressing an approval is as good as reversing it at K of N.
    let alice = Approver::from_bytes([1u8; 32]);
    let policy = Policy::signed([alice.clone()], 1);

    // Pretend alice's real ballot has already been checked, and hand the
    // count a forged reject dated at the end of time alongside it.
    let ballots = Ballots::assume_checked(
        &subject(),
        [
            signed_looking(alice.clone(), Decision::Approve, 1_000),
            Approval::new(alice, Decision::Reject, u64::MAX),
        ],
    );

    let t = tally_checked(&policy, &subject(), &ballots);
    assert_eq!((t.approvals, t.rejections, t.invalid), (1, 0, 1));
    assert!(t.reached, "the forged reject must not bury the real approval");
}

/// A record that carries signature bytes, so the signed policy's
/// "must have a signature" rule is satisfied and the test is about the
/// ordering rather than about that rule. Never verified here.
fn signed_looking(approver: Approver, decision: Decision, at_ns: u64) -> Approval {
    let mut a = Approval::new(approver, decision, at_ns);
    a.signature = Some(vec![0u8; 64]);
    a
}

#[test]
fn tally_counts_nothing_that_is_not_signed_whatever_the_policy_says() {
    // The policy's require_signature rule is not what protects `tally`.
    // Under Policy::new, an unsigned record breaks no policy rule -- and
    // it still cannot be counted here, because a record that reached this
    // function unsigned has nothing behind it but its author's say-so.
    // Otherwise the suppression attack would land under exactly the policy
    // shape that looks most innocent: the forged reject dated at the end
    // of time would become alice's latest ballot and bury her approval.
    let alice = Approver::from_bytes(b"alice");
    let policy = Policy::new([alice.clone()], 1);
    let ballots = vec![
        Approval::new(alice.clone(), Decision::Approve, 1_000),
        Approval::new(alice, Decision::Reject, u64::MAX),
    ];

    let t = tally(&policy, &subject(), &ballots);
    assert_eq!((t.approvals, t.rejections, t.invalid), (0, 0, 2));
    assert!(!t.reached);
}

#[test]
fn ballots_cannot_be_counted_against_another_subject() {
    // A signature is evidence about one subject. Carrying a checked list
    // to the count of a different one asks a question the evidence does
    // not answer, so it is refused rather than answered wrongly.
    let alice = Approver::from_bytes(b"alice");
    let policy = Policy::new([alice.clone()], 1);
    let here = subject();
    let elsewhere = Subject::of_bytes("module", b"a different wasm");

    let ballots = Ballots::assume_checked(&here, [Approval::new(alice, Decision::Approve, 1)]);
    assert!(tally_checked(&policy, &here, &ballots).reached);

    let t = tally_checked(&policy, &elsewhere, &ballots);
    assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
}

#[test]
fn assume_checked_keeps_what_it_is_given() {
    // The escape hatch does what it says: no verification, nothing rejected.
    // It is sound only where the caller's assertion is true, which is why it
    // is spelled the way it is.
    let alice = Approver::from_bytes(b"alice");
    let policy = Policy::new([alice.clone()], 1);
    let ballots = Ballots::assume_checked(&subject(), [Approval::new(alice, Decision::Approve, 1)]);
    assert_eq!(ballots.rejected().len(), 0);
    assert!(tally_checked(&policy, &subject(), &ballots).reached);
}

#[cfg(not(feature = "ed25519"))]
#[test]
fn without_the_feature_a_signed_record_is_refused_not_trusted() {
    // A build that cannot check a signature must not count one. The failure
    // mode to avoid is the quiet one, where dropping the feature turns the
    // verifier into something that believes every record it is shown.
    let alice = Approver::from_bytes([1u8; 32]);
    let policy = Policy::signed([alice.clone()], 1);
    let mut record = Approval::new(alice, Decision::Approve, 1_000);
    record.signature = Some(vec![0u8; 64]);

    let ballots = Ballots::verified(&subject(), [record]);
    assert_eq!(ballots.rejected().len(), 1);
    assert!(ballots.is_empty());
    assert!(!tally_checked(&policy, &subject(), &ballots).reached);
}

#[cfg(feature = "ed25519")]
mod signed {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ic_multisig::{ed25519, record, MemoryStore, Store};

    fn approver(k: &SigningKey) -> Approver {
        Approver::from_bytes(k.verifying_key().to_bytes())
    }

    #[test]
    fn a_bad_signature_is_refused_and_kept_for_the_audit() {
        let k = SigningKey::from_bytes(&[1u8; 32]);
        let policy = Policy::signed([approver(&k)], 1);
        let mut tampered = ed25519::sign(&subject(), &k, Decision::Approve, 1_000);
        tampered.signature.as_mut().unwrap()[0] ^= 1;

        let ballots = Ballots::verified(&subject(), [tampered.clone()]);
        assert!(ballots.is_empty());
        assert_eq!(ballots.rejected(), &[tampered]);

        let t = tally_checked(&policy, &subject(), &ballots);
        assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
    }

    #[test]
    fn a_signature_for_another_subject_does_not_transfer() {
        let k = SigningKey::from_bytes(&[1u8; 32]);
        let policy = Policy::signed([approver(&k)], 1);
        let elsewhere = ed25519::sign(&Subject::of_bytes("module", b"other"), &k, Decision::Approve, 1);

        let t = tally(&policy, &subject(), &[elsewhere]);
        assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
    }

    #[test]
    fn a_forged_record_cannot_bury_a_signed_approval() {
        // The suppression attack again, this time with the real signature
        // path: the forgery is thrown out by verification, before it can be
        // the approver's "latest" ballot.
        let k = SigningKey::from_bytes(&[1u8; 32]);
        let policy = Policy::signed([approver(&k)], 1);
        let real = ed25519::sign(&subject(), &k, Decision::Approve, 1_000);

        let mut forged = Approval::new(approver(&k), Decision::Reject, u64::MAX);
        forged.signature = Some(vec![0u8; 64]);

        let t = tally(&policy, &subject(), &[real, forged]);
        assert_eq!((t.approvals, t.rejections, t.invalid), (1, 0, 1));
        assert!(t.reached);
    }

    #[test]
    fn an_outside_verifier_and_the_canister_reach_the_same_answer() {
        // The whole point of the crate: a browser counting collected
        // records against a policy gets what the canister got, without
        // asking the canister.
        let k1 = SigningKey::from_bytes(&[1u8; 32]);
        let k2 = SigningKey::from_bytes(&[2u8; 32]);
        let policy = Policy::signed([approver(&k1), approver(&k2)], 2);
        let subject = subject();

        let mut store = MemoryStore::default();
        for k in [&k1, &k2] {
            record(&mut store, &policy, &subject, ed25519::sign(&subject, k, Decision::Approve, 10)).unwrap();
        }
        let canister =
            tally_checked(&policy, &subject, &Ballots::assume_checked(&subject, store.load(&subject)));

        // The verifier holds the same records plus a forgery it collected
        // from somewhere less careful.
        let mut collected = store.load(&subject);
        collected.push(Approval::new(approver(&k1), Decision::Reject, u64::MAX));
        let outside = tally(&policy, &subject, &collected);

        assert!(canister.reached && outside.reached);
        assert_eq!(
            (canister.approvals, canister.rejections),
            (outside.approvals, outside.rejections)
        );
        assert_eq!((canister.invalid, outside.invalid), (0, 1));
    }
}
