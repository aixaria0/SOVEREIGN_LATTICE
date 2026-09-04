use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use bls12_381::{G1Projective, G2Projective};
use crate::wal::WriteAheadLog;
use crate::threshold_bls::verify_bound_threshold_signature;

pub static TEST_WAL_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    PrePrepare = 0,
    Prepare = 1,
    Commit = 2,
}

#[derive(Clone, Debug)]
pub struct PbftMessage {
    pub phase: Phase,
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub sender_id: u32,
    pub signature: G1Projective,
}

#[derive(Clone, Debug)]
pub struct PreparedCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl PreparedCertificate {
    pub fn verify(
        &self, 
        quorum_size: usize, 
        master_public_key: &G2Projective,
        registered_nodes: &HashSet<u32>
    ) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        // Strict validator-set membership enforcement
        for &signer_id in self.signatures.keys() {
            if !registered_nodes.contains(&signer_id) {
                return false;
            }
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        verify_bound_threshold_signature(
            &canonical_msg,
            &self.signatures,
            master_public_key,
            quorum_size,
        )
    }
}

#[derive(Clone, Debug)]
pub struct CommitCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl CommitCertificate {
    pub fn verify(
        &self, 
        quorum_size: usize, 
        master_public_key: &G2Projective,
        registered_nodes: &HashSet<u32>
    ) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        for &signer_id in self.signatures.keys() {
            if !registered_nodes.contains(&signer_id) {
                return false;
            }
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Commit as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        verify_bound_threshold_signature(
            &canonical_msg,
            &self.signatures,
            master_public_key,
            quorum_size,
        )
    }
}

pub struct PbftState {
    pub total_nodes: usize,
    pub quorum_size: usize,
    pub registered_nodes: HashSet<u32>,
    pub public_keys: HashMap<u32, G2Projective>,
    pub master_public_key: G2Projective,
    pub current_view: u64,
    pub sequence_number: u64,
    pub wal: WriteAheadLog,
    pub leader_proposals: HashMap<(u64, u64), [u8; 32]>,
}

impl PbftState {
    pub fn new(
        total_nodes: usize,
        initial_public_keys: HashMap<u32, G2Projective>,
        master_public_key: G2Projective,
    ) -> Result<Self, &'static str> {
        let f = (total_nodes - 1) / 3;
        let quorum_size = 2 * f + 1;

        let registered_nodes: HashSet<u32> = initial_public_keys.keys().copied().collect();

        // Namespaced WAL path to prevent parallel test collisions
        let wal_path = if cfg!(test) {
            let count = TEST_WAL_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("consensus_wal_test_{}_{:?}.log", count, std::thread::current().id())
        } else {
            format!("consensus_wal_node.log")
        };

        let wal = WriteAheadLog::open(&wal_path)
            .map_err(|_| "WAL_ERROR: Failed to initialize Write-Ahead Log storage file!")?;

        Ok(Self {
            total_nodes,
            quorum_size,
            registered_nodes,
            public_keys: initial_public_keys,
            master_public_key,
            current_view: 0,
            sequence_number: 0,
            wal,
            leader_proposals: HashMap::new(),
        })
    }

    pub fn handle_message(&mut self, msg: &PbftMessage) -> Result<(), &'static str> {
        if !self.registered_nodes.contains(&msg.sender_id) {
            return Err("UNAUTHORIZED_SENDER: Sender ID is not part of the active validator set.");
        }

        match msg.phase {
            Phase::PrePrepare => {
                let key = (msg.view, msg.seq);
                if let Some(existing_digest) = self.leader_proposals.get(&key) {
                    if *existing_digest != msg.digest {
                        return Err("SAFETY_VIOLATION: Leader equivocation detected! Conflicting proposal for same view and sequence.");
                    }
                }
                self.leader_proposals.insert(key, msg.digest);
                Ok(())
            }
            Phase::Prepare | Phase::Commit => {
                Ok(())
            }
        }
    }
}
