use ic_multisig::{cast, record, tally, Approval, Approver, Decision, Error, MemoryStore, Policy, Store, Subject};

fn who(n: u8) -> Approver {
    Approver::from_bytes(vec![n; 8])
}

fn approve(n: u8, at: u64) -> Approval {
    Approval::new(who(n), Decision::Approve, at)
}

fn reject(n: u8, at: u64) -> Approval {
    Approval::new(who(n), Decision::Reject, at)
}

#[test]
fn threshold_zero_is_always_reached() {
    let policy = Policy::new([], 0);
    let t = tally(&policy, &[]);
    assert!(t.reached);
    assert_eq!(t.required, 0);
}

#[test]
fn counts_only_current_approvers_once_each() {
    // Two voters plus an owner who also counts; threshold 2.
    let policy = Policy::new([who(1), who(2), who(3)], 2);
    let subject = Subject::of_short_hash("commit", b"deadbeef");
    let mut store = MemoryStore::default();

    let t = record(&mut store, &policy, &subject, approve(2, 10)).unwrap();
    assert_eq!((t.approvals, t.required, t.reached), (1, 2, false));
    let t = record(&mut store, &policy, &subject, approve(1, 11)).unwrap();
    assert_eq!((t.approvals, t.reached), (2, true));

    // Changing a ballot replaces it.
    let t = record(&mut store, &policy, &subject, reject(1, 12)).unwrap();
    assert_eq!((t.approvals, t.rejections, t.reached), (1, 1, false));
    let t = record(&mut store, &policy, &subject, approve(3, 13)).unwrap();
    assert!(t.reached);

    // A removed approver's ballot stops counting but is reported as ignored.
    let narrower = Policy::new([who(1), who(2)], 2);
    let t = tally(&narrower, &store.load(&subject));
    assert_eq!((t.approvals, t.ignored, t.reached), (1, 1, false));
}

#[test]
fn a_stale_ballot_cannot_undo_a_newer_one() {
    // A signed ballot is a bearer record: anyone who saw the approval at
    // t=100 could resubmit it after the reject at t=200. It must not count.
    let policy = Policy::new([who(1)], 1);
    let subject = Subject::of_bytes("module", b"wasm");
    let mut store = MemoryStore::default();
    assert!(record(&mut store, &policy, &subject, approve(1, 100)).unwrap().reached);
    assert!(!record(&mut store, &policy, &subject, reject(1, 200)).unwrap().reached);
    assert_eq!(
        record(&mut store, &policy, &subject, approve(1, 100)).unwrap_err(),
        Error::Superseded
    );
    assert_eq!(store.load(&subject), vec![reject(1, 200)]);
    // Same time: the resubmission replaces, so replaying a ballot is idempotent.
    assert!(record(&mut store, &policy, &subject, approve(1, 200)).unwrap().reached);
}

#[test]
fn cast_and_tally_agree_on_latest() {
    // Whatever order ballots arrive in, the list `cast` maintains and a
    // raw list handed to `tally` (an off-chain verifier's) pick the same
    // ballot: highest at_ns, ties to the later arrival.
    let policy = Policy::new([who(1)], 1);
    let raw = vec![approve(1, 5000), reject(1, 100), reject(1, 5000)];
    let mut list = vec![];
    for b in raw.iter().cloned() {
        cast(&mut list, b);
    }
    assert_eq!(list, vec![reject(1, 5000)]);
    assert_eq!(tally(&policy, &raw), tally(&policy, &list));
    assert!(!tally(&policy, &raw).reached);
}

#[test]
fn outsiders_and_bad_policies_are_refused() {
    let policy = Policy::new([who(1)], 1);
    let subject = Subject::of_bytes("module", b"wasm");
    let mut store = MemoryStore::default();
    assert_eq!(
        record(&mut store, &policy, &subject, approve(9, 1)).unwrap_err(),
        Error::NotAnApprover
    );
    let impossible = Policy::new([who(1)], 2);
    assert!(matches!(
        record(&mut store, &impossible, &subject, approve(1, 1)).unwrap_err(),
        Error::InvalidPolicy(_)
    ));
    let signed_only = Policy::signed([who(1)], 1);
    assert_eq!(
        record(&mut store, &signed_only, &subject, approve(1, 1)).unwrap_err(),
        Error::MissingSignature
    );
}

#[test]
fn subjects_are_domain_separated() {
    let a = Subject::of_short_hash("commit", b"x");
    let b = Subject::of_short_hash("module", b"x");
    assert_ne!(a.hash, b.hash);
    assert_ne!(a.canonical(), b.canonical());
    assert!(a.key().starts_with("commit:"));
    // The signed message binds subject, decision and time.
    let ap = approve(1, 5);
    assert_ne!(ap.message(&a), ap.message(&b));
    assert_ne!(ap.message(&a), reject(1, 5).message(&a));
    assert_ne!(ap.message(&a), approve(1, 6).message(&a));
}

#[test]
fn records_round_trip_as_readable_json() {
    let subject = Subject::of_bytes("tally", b"result");
    let ap = approve(7, 42);
    let j = serde_json::to_string(&ap).unwrap();
    assert!(j.contains("\"approver\":\"0707070707070707\""), "{j}");
    assert!(!j.contains("signature"), "absent signature is omitted: {j}");
    assert_eq!(serde_json::from_str::<Approval>(&j).unwrap(), ap);
    let sj = serde_json::to_string(&subject).unwrap();
    assert_eq!(serde_json::from_str::<Subject>(&sj).unwrap(), subject);
    let mut list = vec![];
    assert!(cast(&mut list, approve(1, 1)));
    assert!(cast(&mut list, approve(1, 2)));
    assert!(!cast(&mut list, approve(1, 1)));
    assert_eq!(list, vec![approve(1, 2)]);
}
