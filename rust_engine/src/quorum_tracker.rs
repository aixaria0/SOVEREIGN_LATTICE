use std::collections::{HashMap, HashSet};
use super::pbft_state::{NodeId, View, Digest};

/// Manages the collection of votes to reach the Byzantine quorum (2f + 1).
/// This directly maps to the `IsQuorum` and `Prepared`/`Committed` properties in Lean 4.
#[derive(Debug, Default)]
pub struct QuorumTracker {
    // Maps (View, Sequence, Digest) to a set of unique node IDs that sent a PREPARE message
    pub prepare_votes: HashMap<(View, u64, Digest), HashSet<NodeId>>,
    
    // Maps (View, Sequence, Digest) to a set of unique node IDs that sent a COMMIT message
    pub commit_votes: HashMap<(View, u64, Digest), HashSet<NodeId>>,
}

impl QuorumTracker {
    pub fn new() -> Self {
        Self {
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
        }
    }

    /// Registers a PREPARE vote. 
    /// Returns true ONLY if this exact vote crossed the (2f + 1) threshold.
    pub fn add_prepare(&mut self, view: View, seq: u64, digest: Digest, sender: NodeId, f: usize) -> bool {
        let voters = self.prepare_votes
            .entry((view, seq, digest))
            .or_insert_with(HashSet::new);
        
        let already_had_quorum = Self::has_quorum(voters.len(), f);
        voters.insert(sender);
        let now_has_quorum = Self::has_quorum(voters.len(), f);

        // We only trigger the state machine transition exactly when the threshold is crossed
        !already_had_quorum && now_has_quorum
    }

    /// Registers a COMMIT vote. 
    /// Returns true ONLY if this exact vote crossed the (2f + 1) threshold.
    pub fn add_commit(&mut self, view: View, seq: u64, digest: Digest, sender: NodeId, f: usize) -> bool {
        let voters = self.commit_votes
            .entry((view, seq, digest))
            .or_insert_with(HashSet::new);
        
        let already_had_quorum = Self::has_quorum(voters.len(), f);
        voters.insert(sender);
        let now_has_quorum = Self::has_quorum(voters.len(), f);

        !already_had_quorum && now_has_quorum
    }

    /// Helper to enforce the fundamental `IsQuorum` condition verified in Lean 4: Q.card ≥ 2 * f + 1
    #[inline]
    pub fn has_quorum(voters_count: usize, f: usize) -> bool {
        voters_count >= (2 * f + 1)
    }
}

