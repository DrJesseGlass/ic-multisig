#![cfg(feature = "candid")]
// Candid encodes through `CandidType` (these byte fields are `vec nat8`)
// but decodes through serde, so the hex helpers must accept raw bytes in
// a non-human-readable format or no canister endpoint can take these types.
use ic_multisig::{Approval, Approver, Decision, Policy, Subject, Tally};

fn round_trip<T: candid::CandidType + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug>(v: &T) {
    let bytes = candid::encode_one(v).unwrap();
    assert_eq!(&candid::decode_one::<T>(&bytes).unwrap(), v);
}

#[test]
fn public_types_round_trip_through_candid() {
    let a = Approver::from_bytes(vec![7u8; 8]);
    round_trip(&a);
    round_trip(&Subject::of_bytes("module", b"x"));
    let mut ap = Approval::new(a.clone(), Decision::Approve, 1);
    round_trip(&ap);
    ap.signature = Some(vec![9u8; 64]);
    round_trip(&ap);
    // An objection, and a reason on each of the other two decisions.
    round_trip(&Approval::objection(a.clone(), "see issue 12", 2));
    round_trip(&Approval::new(a.clone(), Decision::Approve, 3).with_reason("lgtm"));
    round_trip(&Approval::new(a.clone(), Decision::Reject, 4).with_reason("withdrawn"));
    let mut signed = Approval::objection(a.clone(), "see issue 12", 5);
    signed.signature = Some(vec![9u8; 64]);
    round_trip(&signed);
    round_trip(&Policy::signed([a], 1));
    round_trip(&Tally {
        approvals: 1,
        rejections: 0,
        objections: 1,
        ignored: 0,
        invalid: 0,
        required: 1,
        reached: false,
    });
    // The principal conversion the docs promise.
    let p = candid::Principal::anonymous();
    assert_eq!(Approver::from(p).principal(), Some(p));
}

// The 0.1 wire types, as a client built against that release has them: no
// `reason` on the record, no `Object` in the variant.
#[derive(candid::CandidType, serde::Deserialize, PartialEq, Debug)]
enum DecisionV01 {
    Approve,
    Reject,
}

#[derive(candid::CandidType, serde::Deserialize, PartialEq, Debug)]
struct ApprovalV01 {
    approver: Approver,
    decision: DecisionV01,
    at_ns: u64,
    signature: Option<Vec<u8>>,
}

#[test]
fn the_wire_type_is_compatible_with_v0_1_both_ways() {
    let a = Approver::from_bytes(vec![7u8; 8]);
    let old = ApprovalV01 {
        approver: a.clone(),
        decision: DecisionV01::Reject,
        at_ns: 9,
        signature: Some(vec![9u8; 64]),
    };

    // 0.1 -> 0.2: `reason` is `opt text`, so a record without it decodes,
    // with none.
    let mut new = Approval::new(a.clone(), Decision::Reject, 9);
    new.signature = Some(vec![9u8; 64]);
    let bytes = candid::encode_one(&old).unwrap();
    assert_eq!(candid::decode_one::<Approval>(&bytes).unwrap(), new);

    // 0.2 -> 0.1: an old client reads any ballot it could have cast, and
    // skips a reason it has no field for.
    let bytes = candid::encode_one(&new).unwrap();
    assert_eq!(candid::decode_one::<ApprovalV01>(&bytes).unwrap(), old);
    let bytes = candid::encode_one(new.with_reason("withdrawn")).unwrap();
    assert_eq!(candid::decode_one::<ApprovalV01>(&bytes).unwrap(), old);

    // What it cannot read is the decision it has never heard of. That is
    // the breaking part of this release, and it fails loudly.
    let bytes = candid::encode_one(Approval::objection(a, "see issue 12", 9)).unwrap();
    assert!(candid::decode_one::<ApprovalV01>(&bytes).is_err());
}
