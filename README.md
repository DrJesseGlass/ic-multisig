# ic-multisig

K-of-N approvals over a hashed subject, for Internet Computer canisters and
the clients that verify them.

A **policy** names N approvers and a threshold K. A **subject** is a 32-byte
hash with a kind tag: a commit a repo wants to deploy, a module hash a
release wants attested, a tally an election wants published. Each approver
casts one **approval** per subject; a **tally** counts the ballots from
approvers currently in the policy and says whether K is reached.

Two flavors share one record type:

- **Authenticated approvals**: inside a canister, the approver is the caller
  of an update call. No signature; the identity is the principal's bytes.
- **Signed approvals**: when an approval must be checkable outside the
  canister, or on another chain, it carries an Ed25519 signature over the
  subject, the decision, and the time (`ed25519` feature).

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

That block is the crate-root doctest byte for byte: `tests/readme.rs`
asserts the two have not drifted, and the doctest run is what compiles
them. Paste it into a `main.rs` and it builds as written.

## Features

- `candid`: `CandidType` on the public types; `Approver: From<Principal>`.
- `ed25519`: verify signed approvals; `ed25519::sign` for clients and tests.

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
