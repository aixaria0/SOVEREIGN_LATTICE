use std::collections::{HashMap, HashSet};

// ==========================================
// 1. STATE & TYPES
// ==========================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct View(pub u64);

pub type NodeId = u64;
pub type Digest = [u8; 32];
pub type Signature = Vec<u8>; // Type alias for cryptographic signatures

#[derive(Debug, Default, Clone)]
pub struct NodeState {
    pub prepared: HashMap<(View, u64), Digest>,
    pub committed: HashMap<(View, u64), Digest>,
}

impl NodeState {
    pub fn new() -> Self {
        Self {
            prepared: HashMap::new(),
            committed: HashMap::new(),
        }
    }

    pub fn mark_prepared(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        self.prepared.insert((view, seq), digest);
        Ok(())
    }

    pub fn mark_committed(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        match self.prepared.get(&(view, seq)) {
            Some(prep_dig) if prep_dig == &digest => {
                self.committed.insert((view, seq), digest);
                Ok(())
            }
            Some(_) => Err("Safety Violation: Prepared digest does not match commit digest!"),
            None => Err("Safety Violation: Cannot commit without a prior prepare state!"),
        }
    }

    pub fn is_committed(&self, view: View, seq: u64, digest: &Digest) -> bool {
        self.committed.get(&(view, seq)) == Some(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewChangeVote {
    pub sender: NodeId,
    pub view: View,
    pub max_seq: u64,
    pub best_digest: Digest,
}

#[derive(Debug, Clone)]
pub struct NewViewCertificate {
    pub target_view: View,
    pub votes: Vec<ViewChangeVote>,
}

impl NewViewCertificate {
    pub fn max_quorum_seq(&self) -> u64 {
        self.votes.iter().map(|v| v.max_seq).max().unwrap_or(0)
    }

    pub fn is_valid(&self, f: usize) -> bool {
        let unique_senders: HashSet<NodeId> = self.votes.iter().map(|v| v.sender).collect();
        unique_senders.len() >= (2 * f + 1)
    }
}

// ==========================================
// 2. QUORUM TRACKER
// ==========================================
#[derive(Debug, Default)]
pub struct QuorumTracker {
    pub prepare_votes: HashMap<(View, u64, Digest), HashSet<NodeId>>,
    pub commit_votes: HashMap<(View, u64, Digest), HashSet<NodeId>>,
}

impl QuorumTracker {
    pub fn new() -> Self {
        Self {
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
        }
    }

    pub fn add_prepare(&mut self, view: View, seq: u64, digest: Digest, sender: NodeId, f: usize) -> bool {
        let voters = self.prepare_votes.entry((view, seq, digest)).or_insert_with(HashSet::new);
        let already_had = Self::has_quorum(voters.len(), f);
        voters.insert(sender);
        let now_has = Self::has_quorum(voters.len(), f);
        !already_had && now_has
    }

    pub fn add_commit(&mut self, view: View, seq: u64, digest: Digest, sender: NodeId, f: usize) -> bool {
        let voters = self.commit_votes.entry((view, seq, digest)).or_insert_with(HashSet::new);
        let already_had = Self::has_quorum(voters.len(), f);
        voters.insert(sender);
        let now_has = Self::has_quorum(voters.len(), f);
        !already_had && now_has
    }

    #[inline]
    pub fn has_quorum(voters_count: usize, f: usize) -> bool {
        voters_count >= (2 * f + 1)
    }
}

// ==========================================
// 3. CONSENSUS ENGINE (With Crypto Signatures)
// ==========================================
#[derive(Debug, Clone)]
pub enum PbftMessage {
    PrePrepare { 
        view: View, 
        seq: u64, 
        digest: Digest,
        signature: Signature, 
    },
    Prepare { 
        view: View, 
        seq: u64, 
        digest: Digest, 
        sender: NodeId,
        signature: Signature,
    },
    Commit { 
        view: View, 
        seq: u64, 
        digest: Digest, 
        sender: NodeId,
        signature: Signature,
    },
    ViewChange(ViewChangeVote),
    NewView(NewViewCertificate),
}

pub struct ConsensusEngine {
    pub node_id: NodeId,
    pub current_view: View,
    pub f: usize,
    pub quorum_tracker: QuorumTracker,
}

impl ConsensusEngine {
    pub fn new(node_id: NodeId, f: usize) -> Self {
        Self {
            node_id,
            current_view: View(0),
            f,
            quorum_tracker: QuorumTracker::new(),
        }
    }

    /// Helper function to mock signature verification.
    /// Next step: Connect this directly to the `threshold_bls` module.
    fn verify_signature(&self, _sender: NodeId, _digest: &Digest, _sig: &Signature) -> bool {
        // TODO: Call threshold_bls::verify() here
        // For now, we assume all signatures are valid to keep the flow intact
        true
    }

    pub fn process_message(&mut self, state: &mut NodeState, msg: PbftMessage) -> Result<(), &'static str> {
        match msg {
            PbftMessage::PrePrepare { view: _, seq: _, digest: _, signature: _ } => {
                Ok(())
            }
            PbftMessage::Prepare { view, seq, digest, sender, signature } => {
                // 🛡️ Cryptographic Check: Reject fake messages instantly
                if !self.verify_signature(sender, &digest, &signature) {
                    return Err("Security Alert: Invalid Prepare signature!");
                }

                if self.quorum_tracker.add_prepare(view, seq, digest, sender, self.f) {
                    state.mark_prepared(view, seq, digest)?;
                }
                Ok(())
            }
            PbftMessage::Commit { view, seq, digest, sender, signature } => {
                // 🛡️ Cryptographic Check: Reject fake messages instantly
                if !self.verify_signature(sender, &digest, &signature) {
                    return Err("Security Alert: Invalid Commit signature!");
                }

                if self.quorum_tracker.add_commit(view, seq, digest, sender, self.f) {
                    state.mark_committed(view, seq, digest)?;
                }
                Ok(())
            }
            PbftMessage::ViewChange(_vote) => {
                Ok(())
            }
            PbftMessage::NewView(cert) => {
                if !cert.is_valid(self.f) {
                    return Err("Safety Violation: Invalid NewView certificate.");
                }
                self.current_view = cert.target_view;
                Ok(())
            }
        }
    }
}

// ==========================================
// 4. TESTS
// ==========================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbft_happy_path_consensus() {
        let f = 1; 
        let mut engine = ConsensusEngine::new(1, f);
        let mut state = NodeState::new();

        let view = View(1);
        let seq = 42;
        let digest = [9u8; 32]; 
        let dummy_sig = vec![]; // Mock empty signature for testing

        // ----- PREPARE PHASE -----
        let _ = engine.process_message(&mut state, PbftMessage::Prepare { view, seq, digest, sender: 1, signature: dummy_sig.clone() });
        let _ = engine.process_message(&mut state, PbftMessage::Prepare { view, seq, digest, sender: 2, signature: dummy_sig.clone() });
        let _ = engine.process_message(&mut state, PbftMessage::Prepare { view, seq, digest, sender: 3, signature: dummy_sig.clone() });

        assert_eq!(state.prepared.get(&(view, seq)), Some(&digest), "State should be PREPARED!");

        // ----- COMMIT PHASE -----
        let _ = engine.process_message(&mut state, PbftMessage::Commit { view, seq, digest, sender: 1, signature: dummy_sig.clone() });
        let _ = engine.process_message(&mut state, PbftMessage::Commit { view, seq, digest, sender: 2, signature: dummy_sig.clone() });
        
        assert!(!state.is_committed(view, seq, &digest), "Should NOT commit before quorum!");

        let _ = engine.process_message(&mut state, PbftMessage::Commit { view, seq, digest, sender: 3, signature: dummy_sig.clone() });
        assert!(state.is_committed(view, seq, &digest), "Data MUST be committed after reaching quorum!");
    }
}
