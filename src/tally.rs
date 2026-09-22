use crate::approval::Approval;
use crate::ballots::Ballots;
use crate::policy::Policy;
use crate::subject::Subject;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The count for one subject under one policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "candid", derive(candid::CandidType))]
pub struct Tally {
    /// Approvals from approvers currently in the policy.
    pub approvals: u32,
    /// Rejections from approvers currently in the policy.
    pub rejections: u32,
    /// Ballots that no longer count: their approver left the policy.
    pub ignored: u32,
    /// Records thrown out before counting: a signature that did not
    /// verify, or none at all under a policy that requires one. Counted
    /// per record rather than per approver, since a record refused this
    /// way has not established whose it is.
    pub invalid: u32,
    /// The policy's threshold at the time of the count.
    pub required: u32,
    /// `approvals >= required`. Rejections do not block: a subject is
    /// reached the moment K approvers say yes, whatever the rest said.
    pub reached: bool,
}

/// Count `ballots` under `policy`, verifying them against `subject` first.
///
/// This is the whole job in one call, and the one to reach for when the
/// records came from somewhere you do not control. It applies exactly the
/// rules [`record`](crate::record) applies to a single ballot: a signature
/// that does not verify is refused, a missing signature is refused when
/// the policy requires one, and an approver the policy does not name is
/// ignored.
///
/// Each remaining approver counts once, by their latest ballot (highest
/// `at_ns`; on a tie, the later one in the list) -- the rule [`cast`]
/// enforces when it writes, so a list assembled elsewhere tallies the way
/// the canister does. Ballots from outside the policy are reported as
/// ignored rather than dropped silently, so an audit can see a removed
/// approver's history.
///
/// Verification happens before the latest-ballot rule, not after, and that
/// order is load-bearing: see [`tally_checked`].
///
/// ```
/// use ic_multisig::{tally, Approval, Approver, Decision, Policy, Subject};
///
/// let alice = Approver::from_bytes(b"alice");
/// let policy = Policy::new([alice.clone()], 1);
/// let subject = Subject::of_bytes("commit", b"x");
///
/// // The later ballot by an approver is the one that counts.
/// let ballots = vec![
///     Approval::new(alice.clone(), Decision::Approve, 1_000),
///     Approval::new(alice, Decision::Reject, 2_000),
/// ];
/// let t = tally(&policy, &subject, &ballots);
/// assert_eq!((t.approvals, t.rejections, t.reached), (0, 1, false));
/// ```
pub fn tally(policy: &Policy, subject: &Subject, ballots: &[Approval]) -> Tally {
    tally_checked(policy, &Ballots::verified(subject, ballots.iter().cloned()))
}

/// Count ballots that have already been through the check, without
/// repeating it.
///
/// [`Ballots`] is where the claim lives: either its records were verified,
/// or the caller asserted the IC authenticated them. This is the path a
/// canister wants -- [`record`](crate::record) verifies each ballot on the
/// way in, so re-verifying the whole stored list on every count would buy
/// nothing and cost a signature check per ballot per call.
///
/// The policy's own rules still apply here, because they are about the
/// policy rather than about the record: an approver the policy does not
/// name is ignored, and under
/// [`require_signature`](crate::Policy::require_signature) a record with
/// no signature is invalid however it got here.
///
/// # Why the order matters
///
/// Refused records are dropped before the latest-ballot rule runs, never
/// after. An attacker who could get a refused record as far as the
/// latest-ballot rule would not need to forge a vote to do damage: a
/// record naming an honest approver with `at_ns` far in the future would
/// supersede that approver's real ballot, and suppressing an approval is
/// as good as reversing it when the threshold is tight. So a refused
/// record is never a candidate for anything.
///
/// ```
/// use ic_multisig::{tally_checked, Approval, Approver, Ballots, Decision, Policy};
///
/// let alice = Approver::from_bytes(b"alice");
/// let policy = Policy::signed([alice.clone()], 1);
///
/// // Alice signed nothing here, so under a signed policy neither ballot
/// // counts -- including the one dated far in the future.
/// let ballots = Ballots::assume_checked([
///     Approval::new(alice.clone(), Decision::Approve, 1_000),
///     Approval::new(alice, Decision::Reject, u64::MAX),
/// ]);
/// let t = tally_checked(&policy, &ballots);
/// assert_eq!((t.approvals, t.invalid, t.reached), (0, 2, false));
/// ```
pub fn tally_checked(policy: &Policy, ballots: &Ballots) -> Tally {
    let mut t = Tally {
        approvals: 0,
        rejections: 0,
        ignored: 0,
        invalid: ballots.rejected().len() as u32,
        required: policy.threshold,
        reached: false,
    };

    // Refused first, latest-ballot second. A record that cannot count must
    // not be able to supersede one that can.
    let mut latest: BTreeMap<&[u8], &Approval> = BTreeMap::new();
    for b in ballots.as_slice() {
        if policy.require_signature && b.signature.is_none() {
            t.invalid += 1;
            continue;
        }
        let e = latest.entry(b.approver.as_bytes()).or_insert(b);
        if b.at_ns >= e.at_ns {
            *e = b;
        }
    }

    for b in latest.values() {
        if !policy.is_approver(&b.approver) {
            t.ignored += 1;
        } else if b.approves() {
            t.approvals += 1;
        } else {
            t.rejections += 1;
        }
    }
    t.reached = t.approvals >= policy.threshold;
    t
}

/// Add a ballot to a list, replacing any earlier ballot by the same
/// approver. Returns `false` and leaves the list untouched when the
/// approver's existing ballot has a later `at_ns`: a signed ballot is a
/// bearer record anyone can resubmit, and an old one must not undo the
/// signer's newer decision. Equal `at_ns` replaces, so resubmitting the
/// same ballot is idempotent.
///
/// [`record`](crate::record) calls this, and is what anything holding a
/// [`Store`](crate::Store) should call. Reach for `cast` directly only
/// when assembling a ballot list outside a `Store` -- an off-chain
/// verifier collecting signed approvals.
///
/// # This is list maintenance, not admission
///
/// `cast` applies the supersede rule and nothing else: it does not know
/// the policy and does not look at a signature, so a list it built is a
/// pile of claims, not a set of votes. Whether a record may count is
/// settled where the policy is known -- by [`tally`], or by
/// [`Ballots::verified`](crate::Ballots::verified) followed by
/// [`tally_checked`]. Counting a `cast` list any other way is counting
/// whatever an attacker put in it.
///
/// ```
/// use ic_multisig::{cast, Approval, Approver, Decision};
///
/// let alice = Approver::from_bytes(b"alice");
/// let mut ballots = vec![Approval::new(alice.clone(), Decision::Approve, 2_000)];
///
/// // A replayed older ballot is refused; the newer decision stands.
/// assert!(!cast(&mut ballots, Approval::new(alice.clone(), Decision::Reject, 1_000)));
/// assert_eq!(ballots.len(), 1);
/// assert!(ballots[0].approves());
///
/// // A newer one replaces it.
/// assert!(cast(&mut ballots, Approval::new(alice, Decision::Reject, 3_000)));
/// assert_eq!(ballots.len(), 1);
/// ```
pub fn cast(ballots: &mut Vec<Approval>, approval: Approval) -> bool {
    let newer_exists = ballots
        .iter()
        .any(|b| b.approver == approval.approver && b.at_ns > approval.at_ns);
    if newer_exists {
        return false;
    }
    ballots.retain(|b| b.approver != approval.approver);
    ballots.push(approval);
    true
}
