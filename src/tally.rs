use crate::approval::Approval;
use crate::policy::Policy;
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
    /// The policy's threshold at the time of the count.
    pub required: u32,
    /// `approvals >= required`. Rejections do not block: a subject is
    /// reached the moment K approvers say yes, whatever the rest said.
    pub reached: bool,
}

/// Count `ballots` under `policy`. Each approver counts once, by their
/// latest ballot (highest `at_ns`; on a tie, the later one in the list),
/// the same rule [`cast`] enforces when it writes, so a list assembled
/// elsewhere (an off-chain verifier collecting signed records) tallies the
/// way the canister does. Ballots from outside the policy are reported as
/// ignored rather than dropped silently, so an audit can see a removed
/// approver's history.
///
/// This counts what it is handed. Signatures are not verified here; see
/// [`cast`] for what that means for a verifier holding untrusted records.
///
/// ```
/// use ic_multisig::{tally, Approval, Approver, Decision, Policy};
///
/// let alice = Approver::from_bytes(b"alice");
/// let policy = Policy::new([alice.clone()], 1);
///
/// // The later ballot by an approver is the one that counts.
/// let ballots = vec![
///     Approval::new(alice.clone(), Decision::Approve, 1_000),
///     Approval::new(alice, Decision::Reject, 2_000),
/// ];
/// let t = tally(&policy, &ballots);
/// assert_eq!((t.approvals, t.rejections, t.reached), (0, 1, false));
/// ```
pub fn tally(policy: &Policy, ballots: &[Approval]) -> Tally {
    let mut latest: BTreeMap<&[u8], &Approval> = BTreeMap::new();
    for b in ballots {
        let e = latest.entry(b.approver.as_bytes()).or_insert(b);
        if b.at_ns >= e.at_ns {
            *e = b;
        }
    }
    let mut t = Tally {
        approvals: 0,
        rejections: 0,
        ignored: 0,
        required: policy.threshold,
        reached: false,
    };
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
/// [`Store`](crate::Store) should call: it checks policy membership, the
/// policy's signature rule, and the signature itself first. Reach for
/// `cast` directly only when assembling a ballot list outside a `Store` --
/// an off-chain verifier collecting signed approvals -- and read the next
/// paragraph before you do.
///
/// # Signatures are not checked here
///
/// `cast` applies only the supersede rule, and [`tally`] only asks whether
/// a ballot's approver is named by the policy. Neither looks at a
/// signature. Given untrusted records, a verifier that calls these two
/// directly counts a forgery: anyone can build an `Approval` naming an
/// authorized public key, leave `signature` empty or fill it with
/// nonsense, and be counted. Call `ed25519::verify` on every record first
/// and drop the ones that fail, or route them through `record` against a
/// [`Policy::signed`](crate::Policy::signed) policy, which does it for you.
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
