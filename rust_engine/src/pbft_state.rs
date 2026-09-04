use std::collections::{HashMap, HashSet};

/// Represents the current view number of the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct View(pub u64);

pub type NodeId = u64;
pub type Digest = [u8; 32]; // Hash of the data or block

/// Structure representing the state of an honest node (maps to HonestState in Lean)
#[derive(Debug, Default, Clone)]
pub struct NodeState {
    // Maps (View, Sequence) to Digest for the Prepare phase
    pub prepared: HashMap<(View, u64), Digest>,
    
    // Maps (View, Sequence) to Digest for the Commit phase
    pub committed: HashMap<(View, u64), Digest>,
}

impl NodeState {
    pub fn new() -> Self {
        Self {
            prepared: HashMap::new(),
            committed: HashMap::new(),
        }
    }

    /// Records the prepared data
    pub fn mark_prepared(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        // Signature verification logic can be added here later
        self.prepared.insert((view, seq), digest);
        Ok(())
    }

    /// Records the committed data
    /// This function strictly enforces the `rule_commit_implies_prepare` invariant from Lean!
    pub fn mark_committed(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        // 🛡️ Critical safety check: No node is allowed to commit a digest unless it has explicitly prepared it first
        match self.prepared.get(&(view, seq)) {
            Some(prep_dig) if prep_dig == &digest => {
                self.committed.insert((view, seq), digest);
                Ok(())
            }
            Some(_) => Err("Safety Violation: Prepared digest does not match commit digest!"),
            None => Err("Safety Violation: Cannot commit without a prior prepare state!"),
        }
    }

    /// Checks if a specific (View, Seq) has been committed
    pub fn is_committed(&self, view: View, seq: u64, digest: &Digest) -> bool {
        self.committed.get(&(view, seq)) == Some(digest)
    }
}

/// A node's vote for a view change (maps to ViewChangeVote in Lean)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewChangeVote {
    pub sender: NodeId,
    pub view: View,
    pub max_seq: u64,
    pub best_digest: Digest,
}

/// Certificate initiating a new view (maps to NewViewCertificate in Lean)
#[derive(Debug, Clone)]
pub struct NewViewCertificate {
    pub target_view: View,
    pub votes: Vec<ViewChangeVote>, 
    // Prepare proof certificate can be passed here later
}

impl NewViewCertificate {
    /// Calculates the highest sequence based on votes (maps to maxQuorumSeq in Lean)
    pub fn max_quorum_seq(&self) -> u64 {
        self.votes.iter().map(|v| v.max_seq).max().unwrap_or(0)
    }

    /// Validates the NewView votes against the fault tolerance parameter 'f'
    pub fn is_valid(&self, f: usize) -> bool {
        // Collect unique senders to check the quorum size
        let unique_senders: HashSet<NodeId> = self.votes.iter().map(|v| v.sender).collect();
        
        // Check the IsQuorum condition (must be at least 2f + 1)
        unique_senders.len() >= (2 * f + 1)
    }
}
