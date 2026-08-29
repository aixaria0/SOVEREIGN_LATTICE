use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    PrePrepare,
    Prepare,
    Commit,
}

pub struct PbftState {
    // Maps Sequence -> Digest -> Set of Sender IDs
    prepares: HashMap<u64, HashMap<[u8; 32], HashSet<u32>>>,
    commits: HashMap<u64, HashMap<[u8; 32], HashSet<u32>>>,
    quorum_size: usize,
}

impl PbftState {
    pub fn new(total_nodes: usize) -> Self {
        // f = (N - 1) / 3 | Quorum = 2f + 1
        let f = (total_nodes - 1) / 3;
        Self {
            prepares: HashMap::new(),
            commits: HashMap::new(),
            quorum_size: 2 * f + 1,
        }
    }

    pub fn process_message(&mut self, phase: Phase, seq: u64, digest: [u8; 32], sender_id: u32) -> String {
        match phase {
            Phase::PrePrepare => {
                format!("📥 [PBFT STATE]: Received PRE-PREPARE for Seq {}. Transitioning to PREPARE phase.", seq)
            }
            Phase::Prepare => {
                let seq_map = self.prepares.entry(seq).or_insert_with(HashMap::new);
                let signers = seq_map.entry(digest).or_insert_with(HashSet::new);
                signers.insert(sender_id);
                
                if signers.len() == self.quorum_size {
                    format!("✅ [PBFT STATE]: PREPARE Quorum reached ({} votes) for Seq {}. Broadcasting COMMIT.", self.quorum_size, seq)
                } else {
                    format!("⏳ [PBFT STATE]: Logged PREPARE from Node {} for Seq {}. Total: {}/{}", sender_id, seq, signers.len(), self.quorum_size)
                }
            }
            Phase::Commit => {
                let seq_map = self.commits.entry(seq).or_insert_with(HashMap::new);
                let signers = seq_map.entry(digest).or_insert_with(HashSet::new);
                signers.insert(sender_id);
                
                if signers.len() == self.quorum_size {
                    format!("🏆 [PBFT STATE]: COMMIT Quorum reached ({} votes) for Seq {}. Block is now DEFINITIVELY COMMITTED.", self.quorum_size, seq)
                } else {
                    format!("⏳ [PBFT STATE]: Logged COMMIT from Node {} for Seq {}. Total: {}/{}", sender_id, seq, signers.len(), self.quorum_size)
                }
            }
        }
    }
}
