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
    round_trip(&Policy::signed([a], 1));
    round_trip(&Tally { approvals: 1, rejections: 0, ignored: 0, required: 1, reached: true });
    // The principal conversion the docs promise.
    let p = candid::Principal::anonymous();
    assert_eq!(Approver::from(p).principal(), Some(p));
}
