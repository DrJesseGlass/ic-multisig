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
    /// verify, none at all where one was needed, or a whole list built
    /// against a different subject. Counted per record rather than per
    /// approver, since a record refused this way has not established
    /// whose it is.
    pub invalid: u32,
    /// The policy's threshold at the time of the count.
    pub required: u32,
    /// `approvals >= required`. Rejections do not block: a subject is
    /// reached the moment K approvers say yes, whatever the rest said.
    pub reached: bool,
}

/// Verify `ballots` against `subject` and count what survives.
///
/// This is the call for records that came from somewhere you do not
/// control: a verifier collecting signed attestations, a browser counting
/// them against a keyset it trusts. Only a record carrying a signature
/// valid for `subject` is counted. Everything else -- a bad signature, no
/// signature at all -- is invalid, whatever the policy says, because an
/// unsigned record reaching this function has nothing behind it but its
/// author's say-so.
///
/// That makes this the wrong call for ballots whose approvers the IC
/// authenticated, since those carry no signature and would all be
/// refused. Those are counted by [`tally_checked`], which is where the
/// caller says so out loud.
///
/// Each surviving approver counts once, by their latest ballot (highest
/// `at_ns`; on a tie, the later one in the list) -- the rule [`cast`]
/// enforces when it writes, so a list assembled elsewhere tallies the way
/// the canister does. Ballots from approvers the policy no longer names
/// are reported as ignored rather than dropped silently, so an audit can
/// see a removed approver's history.
///
/// # Not quite the rules `record` applies
///
/// Close, but two differences a caller should not be surprised by.
/// [`record`](crate::record) returns `Err(NotAnApprover)` where this
/// reports `ignored`, because refusing one submission and counting a
/// collected set are different jobs. And `record` calls
/// [`Policy::validate`](crate::Policy::validate) first, while this does
/// not: a policy whose threshold exceeds its approver count tallies here
/// as an honest `reached == false`, where the canister would have refused
/// the first ballot outright. Validate the policy yourself if you did not
/// author it.
///
/// ```
/// use ic_multisig::{tally, Approval, Approver, Decision, Policy, Subject};
///
/// let alice = Approver::from_bytes([1u8; 32]);
/// let policy = Policy::signed([alice.clone()], 1);
/// let subject = Subject::of_bytes("module", b"wasm bytes");
///
/// // Anyone can write this record, and nothing in it says alice did.
/// let forged = Approval::new(alice, Decision::Approve, 1_000);
///
/// let t = tally(&policy, &subject, &[forged]);
/// assert_eq!((t.approvals, t.invalid, t.reached), (0, 1, false));
/// ```
pub fn tally(policy: &Policy, subject: &Subject, ballots: &[Approval]) -> Tally {
    tally_checked(
        policy,
        subject,
        &Ballots::verified(subject, ballots.iter().cloned()),
    )
}

/// Count ballots that have already been accounted for, without repeating
/// the check.
///
/// [`Ballots`] is where the claim lives: either its records were verified,
/// or the caller asserted the IC authenticated them. This is the path a
/// canister wants -- [`record`](crate::record) verifies each ballot on the
/// way in, so re-verifying the whole stored list on every count would buy
/// nothing and cost a signature check per ballot per call -- and the only
/// path that can count the unsigned ballots an authenticated caller casts.
///
/// The policy's own rules still apply, because they are about the policy
/// rather than about the record: an approver the policy does not name is
/// ignored, and under
/// [`require_signature`](crate::Policy::require_signature) a record with
/// no signature is invalid however it got here.
///
/// `subject` is redundant with [`Ballots::subject`] and that is the point:
/// it is the caller's statement of what this count is about, checked
/// against what the ballots were actually built from. They disagree only
/// when a `Ballots` has been carried from one subject to another, and a
/// count that would answer the wrong question refuses to answer at all --
/// every record invalid, nothing reached.
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
/// use ic_multisig::{tally_checked, Approval, Approver, Ballots, Decision, Policy, Subject};
///
/// let alice = Approver::from_bytes(b"alice");   // a principal, not a key
/// let policy = Policy::new([alice.clone()], 1);
/// let subject = Subject::of_short_hash("commit", &[0xab; 20]);
///
/// // The IC authenticated alice as the caller, so there is no signature
/// // to check and the caller says as much.
/// let ballots = Ballots::assume_checked(
///     &subject,
///     [Approval::new(alice, Decision::Approve, 1_000)],
/// );
/// assert!(tally_checked(&policy, &subject, &ballots).reached);
/// ```
pub fn tally_checked(policy: &Policy, subject: &Subject, ballots: &Ballots) -> Tally {
    let mut t = Tally {
        approvals: 0,
        rejections: 0,
        ignored: 0,
        invalid: ballots.rejected().len() as u32,
        required: policy.threshold,
        reached: false,
    };

    // A count about the wrong subject is worse than no count: it would
    // answer a question nobody asked, in the shape of an answer to the one
    // they did. Refuse the lot.
    if ballots.subject() != subject {
        t.invalid += ballots.len() as u32;
        return t;
    }

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
