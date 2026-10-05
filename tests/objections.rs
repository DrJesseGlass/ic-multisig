// An objection is the one ballot that weighs against: approvals minus
// objections must reach K. Everything else about a ballot is unchanged by
// it -- latest per approver, removed approvers ignored, refused records
// dropped first -- and these tests are as much about that as about the
// arithmetic. The last section pins what 0.1 wrote: its records still
// load, and its signatures still verify.

use ic_multisig::{
    record, tally_checked, Approval, Approver, Ballots, Decision, Error, MemoryStore, Policy,
    Store, Subject, Tally, MAX_REASON_BYTES,
};

fn who(n: u8) -> Approver {
    Approver::from_bytes(vec![n; 8])
}

fn approve(n: u8, at: u64) -> Approval {
    Approval::new(who(n), Decision::Approve, at)
}

fn reject(n: u8, at: u64) -> Approval {
    Approval::new(who(n), Decision::Reject, at)
}

fn object(n: u8, at: u64) -> Approval {
    Approval::objection(who(n), "see issue 12", at)
}

fn subject() -> Subject {
    Subject::of_short_hash("commit", b"deadbeef")
}

/// `approvals` approvers approve, then the next `objections` object, then
/// the next `rejections` reject, each through `record`, under K of 8.
fn count(threshold: u32, approvals: u8, objections: u8, rejections: u8) -> Tally {
    let policy = Policy::new((0..8).map(who), threshold);
    let mut store = MemoryStore::default();
    let mut t = tally_checked(&policy, &subject(), &Ballots::assume_checked(&subject(), []));
    for n in 0..approvals + objections + rejections {
        let ballot = match n {
            n if n < approvals => approve(n, 10),
            n if n < approvals + objections => object(n, 10),
            n => reject(n, 10),
        };
        t = record(&mut store, &policy, &subject(), ballot).unwrap();
    }
    t
}

#[test]
fn approvals_minus_objections_must_reach_k() {
    // (K, approve, object, reject) -> reached. The first three rows are
    // the examples in ic-git's docs/GOVERNANCE.md, section 1.
    let table = [
        ((3, 3, 0, 0), true),
        ((3, 4, 1, 0), true),
        ((3, 3, 1, 0), false),
        // Each objection costs exactly one approval.
        ((3, 5, 2, 0), true),
        ((3, 4, 2, 0), false),
        // A rejection weighs nothing, beside an objection or without one.
        ((3, 3, 0, 5), true),
        ((3, 4, 1, 3), true),
        ((3, 2, 0, 1), false),
        // Objections alone decide nothing, and no count goes negative.
        ((3, 0, 4, 0), false),
        // K = 0 is reached with no ballots at all, until someone objects;
        // then it takes an approval to outweigh the objection.
        ((0, 0, 0, 0), true),
        ((0, 0, 1, 0), false),
        ((0, 1, 1, 0), true),
    ];
    for ((k, approvals, objections, rejections), reached) in table {
        let t = count(k, approvals, objections, rejections);
        assert_eq!(
            (t.approvals, t.objections, t.rejections, t.required),
            (approvals.into(), objections.into(), rejections.into(), k),
            "K={k}: {approvals} approve, {objections} object, {rejections} reject"
        );
        assert_eq!(
            t.reached, reached,
            "K={k}: {approvals} approve, {objections} object, {rejections} reject"
        );
    }
}

#[test]
fn an_objection_is_superseded_by_the_same_approvers_later_approval() {
    let policy = Policy::new([who(1), who(2)], 1);
    let mut store = MemoryStore::default();

    assert!(record(&mut store, &policy, &subject(), approve(1, 10)).unwrap().reached);
    let t = record(&mut store, &policy, &subject(), object(2, 20)).unwrap();
    assert_eq!((t.approvals, t.objections, t.reached), (1, 1, false));

    // Approver 2 comes round. The objection is replaced, not outvoted.
    let t = record(&mut store, &policy, &subject(), approve(2, 30)).unwrap();
    assert_eq!((t.approvals, t.objections, t.reached), (2, 0, true));
    assert_eq!(store.load(&subject()).len(), 2);

    // And the old objection cannot be replayed over the newer approval.
    assert_eq!(
        record(&mut store, &policy, &subject(), object(2, 20)).unwrap_err(),
        Error::Superseded
    );
}

#[test]
fn an_objection_is_withdrawn_by_a_rejection() {
    // Withdrawing is casting another ballot. A rejection takes the
    // objection's weight away without adding an approval.
    let policy = Policy::new([who(1), who(2)], 1);
    let mut store = MemoryStore::default();
    record(&mut store, &policy, &subject(), approve(1, 10)).unwrap();
    assert!(!record(&mut store, &policy, &subject(), object(2, 20)).unwrap().reached);
    let t = record(&mut store, &policy, &subject(), reject(2, 30)).unwrap();
    assert_eq!((t.approvals, t.objections, t.rejections, t.reached), (1, 0, 1, true));
}

#[test]
fn an_objection_from_a_removed_approver_is_ignored() {
    let policy = Policy::new([who(1), who(2)], 1);
    let mut store = MemoryStore::default();
    record(&mut store, &policy, &subject(), approve(1, 10)).unwrap();
    assert!(!record(&mut store, &policy, &subject(), object(2, 20)).unwrap().reached);

    // Membership is read at the count, so removing the objector retires
    // the objection with them, and it shows up as ignored.
    let narrower = Policy::new([who(1)], 1);
    let stored = Ballots::assume_checked(&subject(), store.load(&subject()));
    let t = tally_checked(&narrower, &subject(), &stored);
    assert_eq!((t.approvals, t.objections, t.ignored, t.reached), (1, 0, 1, true));

    // An outsider cannot object in the first place.
    assert_eq!(
        record(&mut store, &policy, &subject(), object(9, 30)).unwrap_err(),
        Error::NotAnApprover
    );
}

#[test]
fn a_missing_or_over_long_reason_is_refused() {
    let policy = Policy::new([who(1)], 1);
    let mut store = MemoryStore::default();
    let mut refused = |a: Approval| record(&mut store, &policy, &subject(), a).unwrap_err();

    // An objection has to say why, and an empty or blank reason does not.
    assert_eq!(refused(Approval::new(who(1), Decision::Object, 1)), Error::MissingReason);
    assert_eq!(refused(Approval::objection(who(1), "", 1)), Error::MissingReason);
    assert_eq!(refused(Approval::objection(who(1), " \t\n", 1)), Error::MissingReason);

    // The cap is on every decision, since any unsigned ballot may carry a
    // reason, and it is counted in bytes rather than characters.
    let long = "x".repeat(MAX_REASON_BYTES + 1);
    assert_eq!(refused(Approval::objection(who(1), long.clone(), 1)), Error::ReasonTooLong);
    assert_eq!(refused(approve(1, 1).with_reason(long.clone())), Error::ReasonTooLong);
    assert_eq!(refused(reject(1, 1).with_reason(long)), Error::ReasonTooLong);
    let wide = "\u{e9}".repeat(MAX_REASON_BYTES / 2 + 1);
    assert_eq!(refused(Approval::objection(who(1), wide, 1)), Error::ReasonTooLong);

    // Nothing refused was stored.
    assert!(store.load(&subject()).is_empty());

    // Exactly at the cap is fine, and so is a reason on an approval.
    let full = Approval::objection(who(1), "x".repeat(MAX_REASON_BYTES), 1);
    assert_eq!(record(&mut store, &policy, &subject(), full).unwrap().objections, 1);
    let t = record(&mut store, &policy, &subject(), approve(1, 2).with_reason("lgtm")).unwrap();
    assert!(t.reached);
    assert_eq!(store.load(&subject())[0].reason.as_deref(), Some("lgtm"));
}

#[test]
fn an_objection_without_a_reason_is_invalid_at_the_count_too() {
    // `record` is not the only way to a count. A list handed straight to
    // `tally_checked` meets the same rule, and meets it before the
    // latest-ballot rule: the bare objection is the later ballot here, and
    // it must not bury the approval it cannot outweigh.
    let policy = Policy::new([who(1)], 1);
    let ballots = Ballots::assume_checked(
        &subject(),
        [approve(1, 10), Approval::new(who(1), Decision::Object, 20)],
    );
    let t = tally_checked(&policy, &subject(), &ballots);
    assert_eq!((t.approvals, t.objections, t.invalid, t.reached), (1, 0, 1, true));
}

#[test]
fn the_decision_is_the_tenth_byte_from_the_end_of_every_message() {
    // What keeps the three messages apart whatever a subject's kind holds:
    // read from the end, each one is time, 0, decision, 0, and only then
    // the part whose length varies. An objection's reason hash sits ahead
    // of that tail, so no choice of reason can make it read as another
    // decision.
    let s = subject();
    let tail = |a: &Approval| {
        let m = a.message(&s);
        m[m.len() - 11..].to_vec()
    };
    let expect = |decision: u8, at: u64| [&[0, decision, 0][..], &at.to_le_bytes()[..]].concat();
    assert_eq!(tail(&reject(1, 7)), expect(0, 7));
    assert_eq!(tail(&approve(1, 7)), expect(1, 7));
    assert_eq!(tail(&object(1, 7)), expect(2, 7));

    // An objection's message is the approval's with 33 bytes let in ahead
    // of the tail -- the reason's sha256 and a separator -- and it moves
    // with the reason.
    let (a, o) = (approve(1, 7).message(&s), object(1, 7).message(&s));
    assert_eq!(o.len(), a.len() + 33);
    assert_eq!(o[..a.len() - 10], a[..a.len() - 10]);
    assert_eq!(
        hex::encode(&o[a.len() - 10..a.len() + 22]),
        // sha256("see issue 12")
        "4f2d695c9aef31fb290ce8b1cf14c951b7692de43e8be063845c2cc706b34205"
    );
    assert_ne!(o, Approval::objection(who(1), "see issue 13", 7).message(&s));
}

// What 0.1.1 wrote, byte for byte: taken from that release's own output,
// not regenerated by this one. `module:sha256("wasm bytes")`, signed by the
// key [1; 32].
const V01_APPROVE: &str = r#"{"approver":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","decision":"Approve","at_ns":100,"signature":"d5f4765d49a1cc7a2d9fce529591709555c726233b23cce90e244c11d846fe89e37977ea6ee372d0a55e0c2e1930f50240421f105cfec9428ae922e590038c0a"}"#;
const V01_REJECT: &str = r#"{"approver":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","decision":"Reject","at_ns":200,"signature":"a89b01e8bac1e81b5df867132593f3d4ddc143d91fefa453e1ad474f3c75490e0ac0d208a5f2bbb0610ef141e253155aee573a443a2e1de411d7039433309003"}"#;
const V01_UNSIGNED: &str = r#"{"approver":"0707070707070707","decision":"Reject","at_ns":42}"#;
const V01_APPROVE_MESSAGE: &str = "69632d6d756c74697369672f7631006d6f64756c6500a81d16f296ff2ebdb2dfe2ee0fbb532ba602da1ef9f797f8b1edb3e987fcf5db0001006400000000000000";
const V01_REJECT_MESSAGE: &str = "69632d6d756c74697369672f7631006d6f64756c6500a81d16f296ff2ebdb2dfe2ee0fbb532ba602da1ef9f797f8b1edb3e987fcf5db000000c800000000000000";

#[test]
fn v0_1_records_still_load_and_write_back_unchanged() {
    for json in [V01_APPROVE, V01_REJECT, V01_UNSIGNED] {
        let a: Approval = serde_json::from_str(json).unwrap();
        assert_eq!(a.reason, None);
        // No reason, no field: a 0.1 reader can still read what 0.2
        // writes for a ballot 0.1 could have cast.
        assert_eq!(serde_json::to_string(&a).unwrap(), json);
    }
    // A tally serialized before there were objections has none.
    let t: Tally = serde_json::from_str(
        r#"{"approvals":2,"rejections":1,"ignored":0,"invalid":0,"required":2,"reached":true}"#,
    )
    .unwrap();
    assert_eq!((t.approvals, t.objections, t.reached), (2, 0, true));
}

#[test]
fn v0_1_messages_are_byte_identical() {
    let module = Subject::of_bytes("module", b"wasm bytes");
    for (json, message) in [(V01_APPROVE, V01_APPROVE_MESSAGE), (V01_REJECT, V01_REJECT_MESSAGE)] {
        let a: Approval = serde_json::from_str(json).unwrap();
        assert_eq!(hex::encode(a.message(&module)), message);
    }
}

#[test]
fn a_reason_round_trips_as_json() {
    let o = object(7, 42);
    let j = serde_json::to_string(&o).unwrap();
    assert!(j.contains(r#""decision":"Object""#), "{j}");
    assert!(j.contains(r#""reason":"see issue 12""#), "{j}");
    assert_eq!(serde_json::from_str::<Approval>(&j).unwrap(), o);
}

#[cfg(feature = "ed25519")]
mod signed {
    use super::*;
    use ic_multisig::ed25519::{self, SigningKey};
    use ic_multisig::tally;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn approver(k: &SigningKey) -> Approver {
        Approver::from_bytes(k.verifying_key().to_bytes())
    }

    fn module() -> Subject {
        Subject::of_bytes("module", b"wasm bytes")
    }

    #[test]
    fn v0_1_signatures_still_verify() {
        let k = key(1);
        let policy = Policy::signed([approver(&k)], 1);
        let approve: Approval = serde_json::from_str(V01_APPROVE).unwrap();
        let reject: Approval = serde_json::from_str(V01_REJECT).unwrap();
        assert_eq!(ed25519::verify(&module(), &approve), Ok(()));
        assert_eq!(ed25519::verify(&module(), &reject), Ok(()));

        // And they count: the stored approval reaches K on its own, and
        // the later stored rejection supersedes it, as in 0.1.
        assert!(tally(&policy, &module(), std::slice::from_ref(&approve)).reached);
        let t = tally(&policy, &module(), &[approve.clone(), reject.clone()]);
        assert_eq!((t.approvals, t.rejections, t.invalid, t.reached), (0, 1, 0, false));

        // Signing is deterministic, so this release signs what that one did.
        assert_eq!(ed25519::sign(&module(), &k, Decision::Approve, 100), approve);
        assert_eq!(ed25519::sign(&module(), &k, Decision::Reject, 200), reject);
    }

    #[test]
    fn a_signed_objection_counts_against() {
        let (k1, k2, k3) = (key(1), key(2), key(3));
        let policy = Policy::signed([approver(&k1), approver(&k2), approver(&k3)], 1);
        let mut store = MemoryStore::default();

        let a1 = ed25519::sign(&module(), &k1, Decision::Approve, 10);
        assert!(record(&mut store, &policy, &module(), a1).unwrap().reached);
        let o2 = ed25519::sign_objection(&module(), &k2, "not the audited build", 20);
        let t = record(&mut store, &policy, &module(), o2).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (1, 1, false));
        let a3 = ed25519::sign(&module(), &k3, Decision::Approve, 30);
        assert!(record(&mut store, &policy, &module(), a3).unwrap().reached);

        // An outside verifier holding the same records agrees.
        let outside = tally(&policy, &module(), &store.load(&module()));
        assert_eq!(
            (outside.approvals, outside.objections, outside.invalid, outside.reached),
            (2, 1, 0, true)
        );
    }

    #[test]
    fn a_signed_objection_whose_reason_is_altered_is_invalid() {
        let k = key(1);
        let other = key(2);
        let policy = Policy::signed([approver(&k), approver(&other)], 1);
        let signed = ed25519::sign_objection(&module(), &k, "not the audited build", 100);
        assert_eq!(ed25519::verify(&module(), &signed), Ok(()));

        let mut altered = signed.clone();
        altered.reason = Some("not the audited build.".into());
        assert_eq!(ed25519::verify(&module(), &altered), Err(Error::InvalidSignature));
        assert_eq!(
            record(&mut MemoryStore::default(), &policy, &module(), altered.clone()).unwrap_err(),
            Error::InvalidSignature
        );

        // At the count it is invalid rather than an objection, so it does
        // not cost the other approver's approval anything.
        let approval = ed25519::sign(&module(), &other, Decision::Approve, 100);
        let t = tally(&policy, &module(), &[approval, altered]);
        assert_eq!((t.approvals, t.objections, t.invalid, t.reached), (1, 0, 1, true));

        // Nor does it transfer to another subject with the reason intact.
        let elsewhere = Subject::of_bytes("module", b"other wasm");
        assert_eq!(ed25519::verify(&elsewhere, &signed), Err(Error::InvalidSignature));
    }

    #[test]
    fn a_signed_objection_cannot_be_turned_into_another_decision() {
        let k = key(1);
        let signed = ed25519::sign_objection(&module(), &k, "not the audited build", 100);

        for decision in [Decision::Approve, Decision::Reject] {
            // Keeping the reason: refused for carrying one unsigned.
            let mut flipped = signed.clone();
            flipped.decision = decision;
            assert_eq!(ed25519::verify(&module(), &flipped), Err(Error::UnsignedReason));
            // Dropping it: the signature is over a different message.
            flipped.reason = None;
            assert_eq!(ed25519::verify(&module(), &flipped), Err(Error::InvalidSignature));
        }

        // And the other way: an approval's signature does not make an
        // objection, with whatever reason a relayer cares to supply.
        let mut promoted = ed25519::sign(&module(), &k, Decision::Approve, 100);
        promoted.decision = Decision::Object;
        promoted.reason = Some("changed my mind".into());
        assert_eq!(ed25519::verify(&module(), &promoted), Err(Error::InvalidSignature));
    }

    #[test]
    fn a_signed_approval_cannot_carry_a_reason() {
        // An approval signs what it signed in 0.1, which has no reason in
        // it. A reason on one is text anybody could have attached, so the
        // record is refused rather than shown as the signer's words.
        let k = key(1);
        let policy = Policy::signed([approver(&k)], 1);
        let dressed = ed25519::sign(&module(), &k, Decision::Approve, 100).with_reason("under duress");

        assert_eq!(ed25519::verify(&module(), &dressed), Err(Error::UnsignedReason));
        assert_eq!(
            record(&mut MemoryStore::default(), &policy, &module(), dressed.clone()).unwrap_err(),
            Error::UnsignedReason
        );
        let t = tally(&policy, &module(), &[dressed]);
        assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
    }

    #[test]
    fn a_signed_objection_without_a_reason_is_refused() {
        // `sign` will sign one, since a signature is only a signature. No
        // count takes it.
        let k = key(1);
        let policy = Policy::signed([approver(&k)], 1);
        let bare = ed25519::sign(&module(), &k, Decision::Object, 100);
        assert_eq!(
            record(&mut MemoryStore::default(), &policy, &module(), bare.clone()).unwrap_err(),
            Error::MissingReason
        );
        let t = tally(&policy, &module(), &[bare]);
        assert_eq!((t.objections, t.invalid), (0, 1));
    }
}
