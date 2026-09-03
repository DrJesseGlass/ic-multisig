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
    pub required: u32,
    pub reached: bool,
}

/// Count `ballots` under `policy`. Each approver counts once, by their
/// latest ballot; ballots from outside the policy are reported as ignored
/// rather than dropped silently, so an audit can see a removed approver's
/// history.
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

/// Add a ballot to a list, replacing any earlier ballot by the same approver.
pub fn cast(ballots: &mut Vec<Approval>, approval: Approval) {
    ballots.retain(|b| b.approver != approval.approver);
    ballots.push(approval);
}
