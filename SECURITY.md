# Security

## Reporting a vulnerability

Report it privately, not in a public issue or pull request:

    https://github.com/DrJesseGlass/ic-multisig/security/advisories/new

That form opens a draft advisory only the maintainer and you can see. Say
what you found, how to reproduce it (a failing test is the best form), and
which version and features it needs. Expect an acknowledgement within a
week.

A bug that is not a security problem is an ordinary issue:
https://github.com/DrJesseGlass/ic-multisig/issues/new/choose

## What counts

ic-multisig's promise is that a tally says `reached` only when approvals
of that subject from approvers currently in the policy, less their
objections, reach K, and that a signed approval proves its approver made
exactly that decision about exactly that subject. Anything that breaks
that promise is in scope, in particular:

- signatures (`ed25519` feature): a record `ed25519::verify` accepts that
  the approver's key did not sign, a signature accepted for a different
  subject, decision, time or objection reason than the one signed, or two
  different records that sign the same bytes (`Approval::message`,
  `Subject::canonical`);
- counting: a `tally` that counts an unsigned or invalid record, an
  approver counted twice, an approver outside the policy counted at all,
  or `reached` reported below the threshold;
- suppression: a record that `record`, `tally` or `tally_checked` refuses
  and that still supersedes or removes an honest approver's ballot;
- `Ballots`: a way to have `tally_checked` count ballots against a subject
  other than the one they were checked for;
- decoding: a serde or candid encoding that decodes to a different record
  than was encoded, or a panic on untrusted input in any of the above.

## What does not

- `Ballots::assume_checked` and `tally_checked` count what the caller
  vouched for. Passing them records nobody authenticated is the caller's
  bug, and the documented meaning of the name.
- `cast` is list maintenance: it applies the latest-ballot rule and checks
  nothing else, as its documentation says. A forged record displacing a
  real one in a list built with `cast` alone is not a report; one that
  survives into a count by `tally`, or into a store through `record`, is.
- A tally is a count of what it was shown. Signatures prove the records
  present are real, not that the list is complete, so a subject reached
  because whoever assembled the list left an objection out is the
  documented limit of counting someone else's list (`tally`).
- The `at_ns` on a signed approval is the signer's own claim. An approver
  who dates their own ballot to win the latest-ballot rule is using their
  own vote.
- At K = N - 1 or K = N a single objection holds a subject. That is
  arithmetic the README states (Objections), not a veto bypass.
- A signed approval is a bearer record with no expiry or revocation
  (README, Roadmap). Replaying a valid one for the same subject is its
  intended use.
- A dependency advisory with no reachable path in this code. Dependabot
  files those (`.github/dependabot.yml`); if you believe a path exists,
  that is a report.
- A vulnerability in a canister that uses this crate, unless the crate is
  the cause. ic-git has its own policy:
  https://github.com/DrJesseGlass/ic-git/blob/main/SECURITY.md

## Supported versions

Only the latest release on crates.io. A fix is a new version; older ones
are not patched.

## How a fix ships

A fix is a release to crates.io, with the affected versions yanked where
the flaw warrants it. The canisters that consume the crate take it by a
version bump, which changes their module hashes, so each ships it by its
own release path; for ic-git that is a reproducible build and a governor
vote, which takes days, not hours. The advisory is published, with credit
to the reporter if wanted, once the fixed version is on crates.io and the
known consumers have had the chance to take it.
