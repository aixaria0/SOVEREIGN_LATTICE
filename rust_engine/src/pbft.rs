use std::collections::{HashMap, HashSet};
use bls12_381::{G1Projective, G2Projective};
use crate::threshold_bls::verify_bls_signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    PrePrepare,
    Prepare,
    Commit,
}

pub struct PbftState {
    pub total_nodes: usize,
    pub f: usize,
    pub prepared_digest: HashMap<(u64, u64), [u8; 32]>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    quorum_size: usize,
    registered_nodes: HashSet<u32>,
    public_keys: HashMap<u32, G2Projective>,
}

impl PbftState {
    pub fn new(total_nodes: usize, initial_public_keys: HashMap<u32, G2Projective>) -> Result<Self, &'static str> {
        let f = (total_nodes - 1) / 3;
        if total_nodes != 3 * f + 1 {
            return Err("TOPOLOGY_VIOLATION: Network size N must strictly satisfy N = 3f + 1!");
        }

        let mut registered_nodes = HashSet::new();
        for id in 0..total_nodes as u32 {
            registered_nodes.insert(id);
            if !initial_public_keys.contains_key(&id) {
                return Err("REGISTRY_VIOLATION: Missing cryptographic public key for a registered node ID!");
            }
        }

        Ok(Self {
            total_nodes,
            f,
            prepared_digest: HashMap::new(),
            committed_digest: HashMap::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            quorum_size: 2 * f + 1,
            registered_nodes,
            public_keys: initial_public_keys,
        })
    }

    pub fn process_signed_message(
        &mut self,
        phase: Phase,
        view: u64,
        seq: u64,
        digest: [u8; 32],
        sender_id: u32,
        signature: &G1Projective,
    ) -> Result<String, &'static str> {
        if !self.registered_nodes.contains(&sender_id) {
            return Err("AUTH_FAILED: Sender ID is not part of the active node registry!");
        }

        let pk = self.public_keys.get(&sender_id)
            .ok_or("CRYPTO_AUTH_FAILED: Public key not found for sender!")?;

        let mut canonical_msg = Vec::new();
        canonical_msg.push(match phase {
            Phase::PrePrepare => 0,
            Phase::Prepare => 1,
            Phase::Commit => 2,
        });
        canonical_msg.extend_from_slice(&(view as u64).to_be_bytes());
        canonical_msg.extend_from_slice(&(seq as u64).to_be_bytes());
        canonical_msg.extend_from_slice(&digest);

        if !verify_bls_signature(&canonical_msg, signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Cryptographic BLS signature verification failed!");
        }

        self.transition_state(phase, view, seq, digest, sender_id)
    }

    fn transition_state(
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
