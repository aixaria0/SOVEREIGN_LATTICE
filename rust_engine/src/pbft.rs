use std::collections::{HashMap, HashSet};
use bls12_381::{G1Projective, G2Projective};
use crate::threshold_bls::verify_bls_signature;
use crate::wal::WriteAheadLog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    PrePrepare = 0,
    Prepare = 1,
    Commit = 2,
    ViewChange = 3,
}

#[derive(Clone)]
pub struct PbftMessage {
    pub phase: Phase,
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub sender_id: u32,
    pub signature: G1Projective,
}

pub struct PbftState {
    pub total_nodes: usize,
    pub f: usize,
    pub current_view: u64,
    pub highest_seq: u64,
    pub prepared_digest: HashMap<(u64, u64), [u8; 32]>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
    pre_prepared_proposals: HashSet<(u64, u64, [u8; 32])>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    view_change_votes: HashMap<(u64, u32), HashSet<u32>>,
    quorum_size: usize,
    registered_nodes: HashSet<u32>,
    public_keys: HashMap<u32, G2Projective>,
    wal: WriteAheadLog,
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

        let wal = WriteAheadLog::open("consensus_wal.log")
            .map_err(|_| "WAL_ERROR: Failed to initialize Write-Ahead Log storage file!")?;

        Ok(Self {
            total_nodes,
            f,
            current_view: 0,
            highest_seq: 0,
            prepared_digest: HashMap::new(),
            committed_digest: HashMap::new(),
            pre_prepared_proposals: HashSet::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            view_change_votes: HashMap::new(),
            quorum_size: 2 * f + 1,
            registered_nodes,
            public_keys: initial_public_keys,
            wal,
        })
    }

    pub fn get_expected_leader(&self, view: u64) -> u32 {
        (view % self.total_nodes as u64) as u32
    }

    pub fn handle_message(&mut self, msg: &PbftMessage) -> Result<String, &'static str> {
        if !self.registered_nodes.contains(&msg.sender_id) {
            return Err("AUTH_FAILED: Sender ID is not part of the active node registry!");
        }

        let pk = self.public_keys.get(&msg.sender_id)
            .ok_or("CRYPTO_AUTH_FAILED: Public key not found for sender!")?;

        let mut canonical_msg = Vec::new();
        canonical_msg.push(msg.phase as u8);
        canonical_msg.extend_from_slice(&msg.view.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.digest);

        if !verify_bls_signature(&canonical_msg, &msg.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Cryptographic BLS signature verification failed!");
        }

        self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, &msg.digest)
            .map_err(|_| "WAL_ERROR: Failed to write consensus event to disk log!")?;

        match msg.phase {
            Phase::PrePrepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: PrePrepare view does not match current consensus view!");
                }

                let expected_leader = self.get_expected_leader(msg.view);
                if msg.sender_id != expected_leader {
                    return Err("LEADER_VIOLATION: PrePrepare message sent by a non-leader node!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("DUPLICATE_PROPOSAL: PrePrepare for this sequence and digest already processed!");
                }

                self.pre_prepared_proposals.insert(proposal_key);
                self.highest_seq = self.highest_seq.max(msg.seq);
                Ok(format!("📥 [PRE-PREPARE]: Validated leader {} proposal for View {} Seq {}", msg.sender_id, msg.view, msg.seq))
            }

            Phase::Prepare => {
                if let Some(existing_digest) = self.prepared_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting PREPARE digest for same sequence!");
                    }
                }

                let votes = self.prepare_votes.entry((msg.view, msg.seq, msg.digest)).or_default();
                votes.insert(msg.sender_id);

                if votes.len() >= self.quorum_size {
                    self.prepared_digest.insert((msg.view, msg.seq), msg.digest);
                    Ok(format!("✅ [PREPARED]: Quorum achieved for View {} Seq {}.", msg.view, msg.seq))
                } else {
                    Ok(format!("⏳ [PREPARE VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, votes.len(), self.quorum_size))
                }
            }

            Phase::Commit => {
                if !self.prepared_digest.contains_key(&(msg.view, msg.seq)) {
                    return Err("SAFETY_VIOLATION: Node cannot commit an un-prepared sequence!");
                }

                if let Some(existing_digest) = self.committed_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting COMMIT digest for same sequence!");
                    }
                }

                let votes = self.commit_votes.entry((msg.view, msg.seq, msg.digest)).or_default();
                votes.insert(msg.sender_id);

                if votes.len() >= self.quorum_size {
                    self.committed_digest.insert((msg.view, msg.seq), msg.digest);
                    Ok(format!("🏆 [COMMITTED]: Sequence {} definitively committed under View {}.", msg.seq, msg.view))
                } else {
                    Ok(format!("⏳ [COMMIT VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, votes.len(), self.quorum_size))
                }
            }

            Phase::ViewChange => {
                if msg.view <= self.current_view {
                    return Err("VIEW_CHANGE_INVALID: Target view must be greater than current view!");
                }

                let votes = self.view_change_votes.entry((msg.view, msg.sender_id)).or_default();
                votes.insert(msg.sender_id);

                Ok(format!("🔄 [VIEW CHANGE]: Vote recorded for transitioning to View {}.", msg.view))
            }
        }
    }
}
