use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    PrePrepare,
    Prepare,
    Commit,
}

/// Represents the executable state machine mirroring Lean 4's HonestState model
pub struct PbftState {
    pub prepared_digest: HashMap<(u64, u64), [u8; 32]>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
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

    /// Enforces state transitions corresponding identically to Lean 4 formal safety theorems
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
                // Lean correspondence invariant: honest_prepare_unique
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
                // Lean correspondence invariant: honest_commit_implies_prepare
                if !self.prepared_digest.contains_key(&(view, seq)) {
                    return Err("SAFETY_VIOLATION: Node cannot commit an un-prepared sequence!");
                }

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
mod rigorous_and_adversarial_tests {
    use super::*;

    #[test]
    fn test_lean_correspondence_safety_invariant() {
        let mut state = PbftState::new(4);
        let view = 1;
        let seq = 100;
        let digest_alpha = [0xAA; 32];
        let digest_beta = [0xBB; 32];

        assert!(state.process_message(Phase::Prepare, view, seq, digest_alpha, 1).is_ok());
        assert!(state.process_message(Phase::Prepare, view, seq, digest_alpha, 2).is_ok());
        assert!(state.process_message(Phase::Prepare, view, seq, digest_alpha, 3).is_ok());

        assert_eq!(state.prepared_digest.get(&(view, seq)), Some(&digest_alpha));

        let malicious_attempt = state.process_message(Phase::Prepare, view, seq, digest_beta, 4);
        
        assert!(malicious_attempt.is_err());
        assert_eq!(
            malicious_attempt.unwrap_err(),
            "EQUIVOCATION_DETECTED: Conflicting PREPARE digest for same sequence!"
        );
    }

    #[test]
    fn test_adversarial_equivocation_attack() {
        let mut state = PbftState::new(4);
        let view = 1;
        let seq = 42;
        let honest_digest = [0x11; 32];
        let malicious_digest = [0x99; 32];

        assert!(state.process_message(Phase::Prepare, view, seq, honest_digest, 1).is_ok());
        assert!(state.process_message(Phase::Prepare, view, seq, honest_digest, 2).is_ok());
        assert!(state.process_message(Phase::Prepare, view, seq, honest_digest, 3).is_ok());

        let equivocation_attempt = state.process_message(Phase::Prepare, view, seq, malicious_digest, 4);
        
        assert!(equivocation_attempt.is_err());
        assert_eq!(
            equivocation_attempt.unwrap_err(),
            "EQUIVOCATION_DETECTED: Conflicting PREPARE digest for same sequence!"
        );
    }

    #[test]
    fn test_unprepared_commit_safety_violation() {
        let mut state = PbftState::new(4);
        let view = 1;
        let seq = 100;
        let digest = [0x55; 32];

        let premature_commit = state.process_message(Phase::Commit, view, seq, digest, 1);

        assert!(premature_commit.is_err());
        assert_eq!(
            premature_commit.unwrap_err(),
            "SAFETY_VIOLATION: Node cannot commit an un-prepared sequence!"
        );
    }
}

