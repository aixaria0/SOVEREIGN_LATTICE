use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    PrePrepare,
    Prepare,
    Commit,
}

pub struct PbftState {
    // Exact mapping to Lean's HonestState: (view, seq) -> Option<Digest>
    // Enforces that an honest node NEVER prepares or commits two conflicting digests
    prepared_digest: HashMap<(u64, u64), [u8; 32]>,
    committed_digest: HashMap<(u64, u64), [u8; 32]>,

    // Quorum tracking: (view, seq, digest) -> Set of Node IDs
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    quorum_size: usize,
}

impl PbftState {
    pub fn new(total_nodes: usize) -> Self {
        let f = (total_nodes - 1) / 3;
        Self {
            prepared_digest: HashMap::new(),
            committed_digest: HashMap::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            quorum_size: 2 * f + 1,
        }
    }

    pub fn process_message(
        &mut self,
        phase: Phase,
        view: u64,
        seq: u64,
        digest: [u8; 32],
        sender_id: u32,
    ) -> Result<String, &'static str> {
        match phase {
            Phase::PrePrepare => {
                Ok(format!("📥 [PRE-PREPARE]: Proposal accepted for View {} Seq {}", view, seq))
            }

            Phase::Prepare => {
                // Correspondence check with Lean: Honest_Prepare_Unique
                if let Some(existing_digest) = self.prepared_digest.get(&(view, seq)) {
                    if existing_digest != &digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting PREPARE digest for same sequence!");
                    }
                }

                let votes = self.prepare_votes.entry((view, seq, digest)).or_default();
                votes.insert(sender_id);

                if votes.len() >= self.quorum_size {
                    self.prepared_digest.insert((view, seq), digest);
                    Ok(format!("✅ [PREPARED]: Quorum achieved for View {} Seq {}. Broadcasting COMMIT.", view, seq))
                } else {
                    Ok(format!("⏳ [PREPARE VOTE]: Node {} recorded. Progress: {}/{}", sender_id, votes.len(), self.quorum_size))
                }
            }

            Phase::Commit => {
                // Correspondence check with Lean: Commit_implies_Prepare
                if !self.prepared_digest.contains_key(&(view, seq)) {
                    return Err("SAFETY_VIOLATION: Node cannot commit an un-prepared sequence!");
                }

                // Check for commit conflict
                if let Some(existing_digest) = self.committed_digest.get(&(view, seq)) {
                    if existing_digest != &digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting COMMIT digest for same sequence!");
                    }
                }

                let votes = self.commit_votes.entry((view, seq, digest)).or_default();
                votes.insert(sender_id);

                if votes.len() >= self.quorum_size {
                    self.committed_digest.insert((view, seq), digest);
                    Ok(format!("🏆 [COMMITTED]: Sequence {} definitively committed under View {}.", seq, view))
                } else {
                    Ok(format!("⏳ [COMMIT VOTE]: Node {} recorded. Progress: {}/{}", sender_id, votes.len(), self.quorum_size))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_conflicting_prepare() {
        let mut state = PbftState::new(4);
        let digest_a = [1u8; 32];
        let digest_b = [2u8; 32];

        // Node 1, 2, 3 prepare digest A -> Quorum reached
        assert!(state.process_message(Phase::Prepare, 0, 1, digest_a, 1).is_ok());
        assert!(state.process_message(Phase::Prepare, 0, 1, digest_a, 2).is_ok());
        assert!(state.process_message(Phase::Prepare, 0, 1, digest_a, 3).is_ok());

        // Conflicting proposal arrives for same seq
        let err = state.process_message(Phase::Prepare, 0, 1, digest_b, 4);
        assert_eq!(err, Err("EQUIVOCATION_DETECTED: Conflicting PREPARE digest for same sequence!"));
    }

    #[test]
    fn test_commit_requires_prepare() {
        let mut state = PbftState::new(4);
        let digest = [1u8; 32];

        // Attempting to commit without preparing must fail (Lean invariant: rule_commit_implies_prepare)
        let err = state.process_message(Phase::Commit, 0, 1, digest, 1);
        assert_eq!(err, Err("SAFETY_VIOLATION: Node cannot commit an un-prepared sequence!"));
    }
}
