# ic-multisig

K-of-N approvals over a hashed subject, for Internet Computer canisters and
the clients that verify them.

A **policy** names N approvers and a threshold K. A **subject** is a 32-byte
hash with a kind tag: a commit a repo wants to deploy, a module hash a
release wants attested, a tally an election wants published. Each approver
casts one **approval** per subject -- approve, reject, or object with a
reason; a **tally** counts the ballots from approvers currently in the
policy and says whether K is reached: approvals, less objections.

Two flavors share one record type:

- **Authenticated approvals**: inside a canister, the approver is the caller
  of an update call. No signature; the identity is the principal's bytes.
- **Signed approvals**: when an approval must be checkable outside the
  canister, or on another chain, it carries an Ed25519 signature over the
  subject, the decision, and the time, and for an objection its reason
  (`ed25519` feature).

Which one a record relies on is not visible in the record, so counting
goes through `Ballots`, and its two constructors are the two claims a
caller can make. `Ballots::verified` keeps the records carrying a valid
signature for the subject and sets every other one aside;
`Ballots::assume_checked` takes them as they are, which is how a caller
states that the IC authenticated the approvers or that `record` already
checked what it stored.

So there are two ways to count, and which one you may use is decided by
where the records came from:

- `tally(policy, subject, records)` verifies first and counts only what
  verified. An unsigned record is refused here whatever the policy says,
  because a record that arrives unsigned has nothing behind it but its
  author's say-so. This is the call for anything collected from a network
  or a file.
- `tally_checked(policy, subject, ballots)` counts what the caller
  vouched for. Authenticated ballots can only be counted this way -- they
  carry no signature -- and `record` uses it so a canister does not
  re-verify its own store on every call.

A refused record is dropped before the latest-ballot rule, never after.
Otherwise a record naming an honest approver, dated far in the future,
would supersede their real ballot without having to be a valid vote at
all, and suppressing an approval is as good as reversing it at K of N.

A `Ballots` remembers the subject it was built against, and
`tally_checked` checks that against the subject it was asked about: a
signature is evidence about one subject, and a count that would answer a
different question refuses to answer at all.

No dependency on `ic-cdk`: callers pass the approver in and supply storage
through the `Store` trait, so every rule is testable on the host.

```rust
use ic_multisig::{record, Approval, Approver, Decision, MemoryStore, Policy, Subject};

fn main() -> Result<(), ic_multisig::Error> {
    let alice = Approver::from_bytes(b"alice");   // a canister: ic_cdk::caller()
    let bob = Approver::from_bytes(b"bob");
    let policy = Policy::new([alice.clone(), bob.clone()], 2);

    // A git commit is a 20-byte SHA-1, so it is widened rather than used raw.
    let subject = Subject::of_short_hash("commit", &[0xab; 20]);
    let mut store = MemoryStore::default();      // a canister: a Store over a stable map

    let tally = record(&mut store, &policy, &subject,
        Approval::new(alice, Decision::Approve, 1_000))?;
    assert!(!tally.reached);

    let tally = record(&mut store, &policy, &subject,
        Approval::new(bob, Decision::Approve, 2_000))?;
    if tally.reached { /* deploy */ }
    Ok(())
}
```

That block, and the one under Objections below, are the crate-root
doctests byte for byte: `tests/readme.rs` asserts the two files have not
drifted, and the doctest run is what compiles them. Paste either into a
`main.rs` and it builds as written.

## Objections

An approver who thinks a subject should not pass can **object**. An
objection must give a reason (a short text or a link, at most 1024 bytes)
and counts -1: the subject is reached when approvals minus objections
reach K. So an objection blocks nothing by itself. It costs one more
approval to overcome, and it puts a reason in front of the other
approvers. A rejection still weighs nothing: it says "no", or withdraws
an earlier approval, without raising the bar for anyone else.

```rust
use ic_multisig::{record, Approval, Approver, Decision, MemoryStore, Policy, Subject};

fn main() -> Result<(), ic_multisig::Error> {
    let alice = Approver::from_bytes(b"alice");
    let bob = Approver::from_bytes(b"bob");
    let carol = Approver::from_bytes(b"carol");
    let policy = Policy::new([alice.clone(), bob.clone(), carol.clone()], 1);
    let subject = Subject::of_short_hash("commit", &[0xab; 20]);
    let mut store = MemoryStore::default();

    let tally = record(&mut store, &policy, &subject,
        Approval::new(alice, Decision::Approve, 1_000))?;
    assert!(tally.reached);

    // An objection is a ballot with a reason, and takes one approval away.
    let tally = record(&mut store, &policy, &subject,
        Approval::objection(bob, "skips the schema migration", 2_000))?;
    assert_eq!((tally.approvals, tally.objections), (1, 1));
    assert!(!tally.reached);

    // It is not a veto: one more approval outweighs it.
    let tally = record(&mut store, &policy, &subject,
        Approval::new(carol, Decision::Approve, 3_000))?;
    assert!(tally.reached);
    Ok(())
}
```

Each approver's latest ballot is the one that counts, so an objection is
withdrawn by casting another ballot, and one from an approver since
removed from the policy is ignored like any other. `record` refuses an
objection with no reason, and both counts report one as invalid.

A signed objection signs the sha256 of its reason along with the subject,
the decision and the time (`ed25519::sign_objection`), so neither the
reason nor the decision can be changed under the signature. A signed
approval or rejection signs exactly what it did in 0.1, which has no
reason in it, so those two cannot carry one when signed: `verify` refuses
a reason the signature does not cover. Unsigned ballots, the kind a
canister records for an authenticated caller, may carry a reason on any
decision.

## Features

- `candid`: `CandidType` on the public types; `Approver: From<Principal>`.
- `ed25519`: verify signed approvals; `ed25519::sign` for clients and tests.

Take the key types from `ic_multisig::ed25519`, which re-exports
`SigningKey`, `VerifyingKey` and `Signature`, rather than adding
`ed25519-dalek` to your own manifest. This crate tracks `ed25519-dalek` 2;
`cargo add ed25519-dalek` now resolves 3, and two major versions in one
graph produce a `SigningKey` that `sign` will not accept.

## Consumers

- ic-git: voters named on a repo approve a commit before the deploy queue
  runs it (`kind = "commit"`).
- ic-vote: trustees approve election lifecycle steps (`kind = "tally"` and
  friends).
- The attestation tooling both rely on: K independent verifiers approve a
  module hash (`kind = "module"`), signed, so a browser extension can count
  them against a trusted keyset.

## Conventions

ASCII only, in code, comments, docs, and commit messages; the pre-commit
hook in `.githooks` enforces it (`git config core.hooksPath .githooks`).
The toolchain is pinned to match ic-git's reproducible build.

## Roadmap

- secp256k1 signed approvals, so EVM attesters can sign with the key they
  already have.
- A client-side verifier (JavaScript) that counts signed approvals against
  a policy, for countersign and the ic-vote ballot client.
- Expiry and revocation of approvals.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
crate by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
