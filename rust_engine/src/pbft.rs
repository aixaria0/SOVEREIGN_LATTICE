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

#[derive(Clone)]
pub struct PreparedCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl PreparedCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        let mut valid_count = 0;
        for (&node_id, sig) in &self.signatures {
            if let Some(pk) = public_keys.get(&node_id) {
                if verify_bls_signature(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }
        valid_count >= quorum_size
    }
}

#[derive(Clone)]
pub struct CommitCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl CommitCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Commit as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        let mut valid_count = 0;
        for (&node_id, sig) in &self.signatures {
            if let Some(pk) = public_keys.get(&node_id) {
                if verify_bls_signature(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }
        valid_count >= quorum_size
    }
}

pub struct ViewChangePayload {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
}

impl ViewChangePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }
}

#[derive(Clone)]
pub struct NewViewCertificate {
    pub target_view: u64,
    pub view_change_votes: HashMap<u32, (u64, [u8; 32], G1Projective)>,
    pub selected_prepared_certificate: Option<PreparedCertificate>,
}

impl NewViewCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.view_change_votes.len() < quorum_size {
            return false;
        }

        let max_quorum_seq = self.view_change_votes.values().map(|&(s, _, _)| s).max().unwrap_or(0);
        let best_digest = self.view_change_votes.values()
            .find(|&&(s, _, _)| s == max_quorum_seq)
            .map(|&(_, d, _)| d)
            .unwrap_or([0u8; 32]);

        if let Some(ref cert) = self.selected_prepared_certificate {
            if !cert.verify(quorum_size, public_keys) {
                return false;
            }
            if cert.seq != max_quorum_seq || cert.digest != best_digest {
                return false;
            }
        } else {
            if max_quorum_seq > 0 {
                return false;
            }
        }

        let mut valid_count = 0;
        for (&node_id, &(seq, digest, ref sig)) in &self.view_change_votes {
            if let Some(pk) = public_keys.get(&node_id) {
                let mut canonical_msg = Vec::new();
                canonical_msg.push(Phase::ViewChange as u8);
                canonical_msg.extend_from_slice(&self.target_view.to_be_bytes());
                canonical_msg.extend_from_slice(&seq.to_be_bytes());
                canonical_msg.extend_from_slice(&digest);

                if verify_bls_signature(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }
        valid_count >= quorum_size
    }
}

pub struct PbftState {
    pub total_nodes: usize,
    pub f: usize,
    pub current_view: u64,
    pub highest_seq: u64,
    pub prepared_certificates: HashMap<(u64, u64), PreparedCertificate>,
    pub commit_certificates: HashMap<(u64, u64), CommitCertificate>,
    pub new_view_certificates: HashMap<u64, NewViewCertificate>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
    pre_prepared_proposals: HashSet<(u64, u64, [u8; 32])>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    pub view_change_votes: HashMap<u64, HashMap<u32, (u64, [u8; 32], G1Projective)>>, 
    pub quorum_size: usize,
    registered_nodes: HashSet<u32>,
    pub public_keys: HashMap<u32, G2Projective>,
    wal: WriteAheadLog,
}

impl PbftState {
    pub fn new(total_nodes: usize, initial_public_keys: HashMap<u32, G2Projective>) -> Result<Self, &'static str> {
        let f = (total_nodes - 1) / 3;
        if total_nodes != 3 * f + 1 {
            return Err("TOPOLOGY_VIOLATION: Network size N must strictly satisfy N = 3f + 1!");
        }

        let mut registered_nodes = HashSet::new();
        let quorum_size = 2 * f + 1;
        for id in 0..total_nodes as u32 {
            registered_nodes.insert(id);
        }

        let wal_path = if cfg!(test) {
            format!("consensus_wal_{:?}.log", std::thread::current().id())
        } else {
            "consensus_wal.log".to_string()
        };

        let wal = WriteAheadLog::open(&wal_path).unwrap();

        Ok(Self {
            total_nodes,
            f,
            current_view: 0,
            highest_seq: 0,
            prepared_certificates: HashMap::new(),
            commit_certificates: HashMap::new(),
            new_view_certificates: HashMap::new(),
            committed_digest: HashMap::new(),
            pre_prepared_proposals: HashSet::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            view_change_votes: HashMap::new(),
            quorum_size,
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

        match msg.phase {
            Phase::PrePrepare => {
                if msg.view < self.current_view {
                    return Err("VIEW_MISMATCH: PrePrepare view is older than current consensus view!");
                }

                let expected_leader = self.get_expected_leader(msg.view);
                if msg.sender_id != expected_leader {
                    return Err("LEADER_VIOLATION: PrePrepare message sent by a non-leader node!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("DUPLICATE_PROPOSAL: PrePrepare already processed!");
                }

                self.pre_prepared_proposals.insert(proposal_key);
                self.highest_seq = self.highest_seq.max(msg.seq);
                
                if msg.view > self.current_view {
                    self.current_view = msg.view;
                }

                Ok(format!("📥 [PRE-PREPARE]: Validated leader {} proposal", msg.sender_id))
            }
            Phase::Prepare => Ok("Prepare Phase".to_string()),
            Phase::Commit => Ok("Commit Phase".to_string()),
            Phase::ViewChange => Ok("ViewChange Phase".to_string()),
        }
    }
}
