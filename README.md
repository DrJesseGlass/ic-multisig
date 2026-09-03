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

No dependency on `ic-cdk`: callers pass the approver in and supply storage
through the `Store` trait, so every rule is testable on the host.

```rust
use ic_multisig::{record, Approval, Approver, Decision, MemoryStore, Policy, Subject};

let policy = Policy::new([Approver::from_bytes(b"alice"), Approver::from_bytes(b"bob")], 2);
let subject = Subject::of_short_hash("commit", &commit_sha1_bytes);
let mut store = MemoryStore::default();   // a canister: a Store over a stable map
let tally = record(&mut store, &policy, &subject,
    Approval::new(Approver::from_bytes(b"alice"), Decision::Approve, now_ns))?;
if tally.reached { /* deploy */ }
```

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
