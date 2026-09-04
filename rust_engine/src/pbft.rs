use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use bls12_381::{G1Affine, G1Projective, G2Projective};
use group::Curve;
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

impl PbftMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 + 8 + 8 + 32 + 4 + 48 {
            return Err("INVALID_MESSAGE_LENGTH");
        }
        let phase_val = bytes[0];
        let phase = match phase_val {
            0 => Phase::PrePrepare,
            1 => Phase::Prepare,
            2 => Phase::Commit,
            _ => return Err("INVALID_PHASE"),
        };
        let mut view_bytes = [0u8; 8];
        view_bytes.copy_from_slice(&bytes[1..9]);
        let view = u64::from_be_bytes(view_bytes);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&bytes[9..17]);
        let seq = u64::from_be_bytes(seq_bytes);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[17..49]);

        let mut sender_bytes = [0u8; 4];
        sender_bytes.copy_from_slice(&bytes[49..53]);
        let sender_id = u32::from_be_bytes(sender_bytes);

        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&bytes[53..101]);

        let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
        let signature = match affine_opt {
            Some(aff) => G1Projective::from(aff),
            None => return Err("INVALID_SIGNATURE_BYTES"),
        };

        Ok(Self {
            phase,
            view,
            seq,
            digest,
            sender_id,
            signature,
        })
    }
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

#[derive(Clone, Debug)]
pub struct ViewChangePayload {
    pub view: u64,
    pub last_seq: u64,
    pub prepared_certificates: Vec<PreparedCertificate>,
    pub sender_id: u32,
    pub signature: G1Projective,
}

pub struct PbftState {
    pub total_nodes: usize,
    pub f: usize,
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
            f,
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
                        return Err("SAFETY_VIOLATION: Leader equivocation detected!");
                    }
                }
                self.leader_proposals.insert(key, msg.digest);
                Ok(())
            }
            Phase::Prepare | Phase::Commit => Ok(),
        }
    }

    pub fn handle_view_change_payload(&mut self, payload: &ViewChangePayload) -> Result<(), &'static str> {
        if !self.registered_nodes.contains(&payload.sender_id) {
            return Err("UNAUTHORIZED_SENDER: View change sender not registered.");
        }
        Ok(())
    }
}

