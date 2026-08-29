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

/// Fully Cryptographically Portable Quorum Certificate with real signatures
#[derive(Clone)]
pub struct PreparedCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl PreparedCertificate {
    /// Cryptographically verifies that the certificate contains at least `quorum_size` 
    /// valid distinct signatures from the node registry.
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

pub struct PbftState {
    pub total_nodes: usize,
    pub f: usize,
    pub current_view: u64,
    pub highest_seq: u64,
    pub prepared_certificates: HashMap<(u64, u64), PreparedCertificate>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
    pre_prepared_proposals: HashSet<(u64, u64, [u8; 32])>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>>,
    view_change_votes: HashMap<u64, HashMap<u32, (u64, [u8; 32])>>, 
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

        let mut wal = WriteAheadLog::open("consensus_wal.log")
            .map_err(|_| "WAL_ERROR: Failed to initialize Write-Ahead Log storage file!")?;

        let mut recovered_view = 0;
        let mut recovered_seq = 0;
        let mut recovered_proposals = HashSet::new();
        let mut recovered_prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> = HashMap::new();
        let mut recovered_commit_votes: HashMap<(u64, u64, [u8; 32]), HashSet<u32>> = HashMap::new();
        let mut recovered_certificates = HashMap::new();
        let mut recovered_committed = HashMap::new();
        let quorum_size = 2 * f + 1;

        let _ = wal.replay_log(|view, seq, phase_u8, sender_id, digest, signature| {
            if view > recovered_view { recovered_view = view; }
            if seq > recovered_seq { recovered_seq = seq; }
            
            match phase_u8 {
                0 => { 
                    recovered_proposals.insert((view, seq, digest)); 
                }
                1 => {
                    let sigs = recovered_prepare_votes.entry((view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let cert = PreparedCertificate {
                            view,
                            seq,
                            digest,
                            signatures: sigs.clone(),
                        };
                        if cert.verify(quorum_size, &initial_public_keys) {
                            recovered_certificates.insert((view, seq), cert);
                        }
                    }
                }
                2 => { 
                    recovered_committed.insert((view, seq), digest); 
                    let commit_v: &mut HashSet<u32> = recovered_commit_votes.entry((view, seq, digest)).or_default();
                    commit_v.insert(sender_id);
                }
                _ => {}
            }
        });

        Ok(Self {
            total_nodes,
            f,
            current_view: recovered_view,
            highest_seq: recovered_seq,
            prepared_certificates: recovered_certificates,
            committed_digest: recovered_committed,
            pre_prepared_proposals: recovered_proposals,
            prepare_votes: recovered_prepare_votes,
            commit_votes: recovered_commit_votes,
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

        let response = match msg.phase {
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
                format!("📥 [PRE-PREPARE]: Validated leader {} proposal for View {} Seq {}", msg.sender_id, msg.view, msg.seq)
            }

            Phase::Prepare => {
                let proposal_key = (msg.view, msg.seq, msg.digest);
                let sigs = self.prepare_votes.entry(proposal_key).or_default();
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let cert = PreparedCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };
                    
                    if !cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated QC failed cryptographic signature verification!");
                    }

                    self.prepared_certificates.insert((msg.view, msg.seq), cert);
                    format!("✅ [VERIFIED PORTABLE CERTIFICATE CREATED]: Quorum achieved for View {} Seq {}.", msg.view, msg.seq)
                } else {
                    format!("⏳ [PREPARE VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
                }
            }

            Phase::Commit => {
                let has_valid_certificate = self.prepared_certificates.values()
                    .any(|cert| cert.seq == msg.seq && cert.digest == msg.digest && cert.verify(self.quorum_size, &self.public_keys));

                if !has_valid_certificate {
                    return Err("SAFETY_VIOLATION: Node cannot commit without a cryptographically verified Quorum Certificate!");
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
                    format!("🏆 [COMMITTED]: Sequence {} definitively committed under View {}.", msg.seq, msg.view)
                } else {
                    format!("⏳ [COMMIT VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, votes.len(), self.quorum_size)
                }
            }

            Phase::ViewChange => {
                if msg.view <= self.current_view {
                    return Err("VIEW_CHANGE_INVALID: Target view must be greater than current view!");
                }

                if msg.seq > 0 {
                    let has_valid_qc = self.prepared_certificates.values()
                        .any(|cert| cert.seq == msg.seq && cert.digest == msg.digest && cert.verify(self.quorum_size, &self.public_keys));

                    if !has_valid_qc {
                        return Err("CERTIFICATE_INVALID: ViewChange rejected; missing cryptographically verified Quorum Certificate!");
                    }
                }

                let supporters = self.view_change_votes.entry(msg.view).or_default();
                supporters.insert(msg.sender_id, (msg.seq, msg.digest));

                if supporters.len() >= self.quorum_size {
                    self.current_view = msg.view;
                    
                    let mut max_seq = 0;
                    let mut best_digest = [0u8; 32];
                    
                    for &(seq, digest) in supporters.values() {
                        if seq > max_seq {
                            max_seq = seq;
                            best_digest = digest;
                        }
                    }
                    
                    if max_seq > 0 {
                        self.highest_seq = self.highest_seq.max(max_seq);
                        
                        let mut inherited_sigs = HashMap::new();
                        if let Some(existing_cert) = self.prepared_certificates.values().find(|c| c.seq == max_seq && c.digest == best_digest) {
                            inherited_sigs = existing_cert.signatures.clone();
                        }

                        let verified_cert = PreparedCertificate {
                            view: msg.view,
                            seq: max_seq,
                            digest: best_digest,
                            signatures: inherited_sigs,
                        };

                        if verified_cert.verify(self.quorum_size, &self.public_keys) {
                            self.prepared_certificates.insert((msg.view, max_seq), verified_cert);
                        }
                    }

                    format!("🔄 [VIEW CHANGE COMMITTED]: Quorum reached with Cryptographically Verified Certificates. Advanced to View {}.", msg.view)
                } else {
                    format!("🔄 [VIEW CHANGE VOTE]: Recorded for View {}. Progress: {}/{}", msg.view, supporters.len(), self.quorum_size)
                }
            }
        };

        self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
            .map_err(|_| "WAL_ERROR: Failed to write valid consensus event to disk log!")?;

        Ok(response)
    }
}
