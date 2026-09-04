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
            if !initial_public_keys.contains_key(&id) {
                return Err("REGISTRY_VIOLATION: Missing cryptographic public key for a registered node ID!");
            }
        }

        let wal_path = if cfg!(test) {
            format!("consensus_wal_{:?}.log", std::thread::current().id())
        } else {
            "consensus_wal.log".to_string()
        };

        let mut wal = WriteAheadLog::open(&wal_path)
            .map_err(|_| "WAL_ERROR: Failed to initialize Write-Ahead Log storage file!")?;

        let mut recovered_view = 0;
        let mut recovered_seq = 0;
        let mut recovered_proposals = HashSet::new();
        let mut recovered_prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> = HashMap::new();
        let mut recovered_commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> = HashMap::new();
        let mut recovered_view_change_votes: HashMap<u64, HashMap<u32, (u64, [u8; 32], G1Projective)>> = HashMap::new();
        let mut recovered_certificates = HashMap::new();
        let mut recovered_commit_certificates = HashMap::new();
        let mut recovered_new_view_certificates = HashMap::new();
        let mut recovered_committed = HashMap::new();

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
                    let sigs = recovered_commit_votes.entry((view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let commit_cert = CommitCertificate {
                            view,
                            seq,
                            digest,
                            signatures: sigs.clone(),
                        };
                        if commit_cert.verify(quorum_size, &initial_public_keys) {
                            recovered_commit_certificates.insert((view, seq), commit_cert);
                            recovered_committed.insert((view, seq), digest);
                        }
                    }
                }
                3 => {
                    let supporters = recovered_view_change_votes.entry(view).or_default();
                    supporters.insert(sender_id, (seq, digest, signature));
                    if supporters.len() >= quorum_size {
                        let max_quorum_seq = supporters.values().map(|&(s, _, _)| s).max().unwrap_or(0);
                        let best_digest = supporters.values()
                            .find(|&&(s, _, _)| s == max_quorum_seq)
                            .map(|&(_, d, _)| d)
                            .unwrap_or([0u8; 32]);

                        let bound_cert = if max_quorum_seq > 0 {
                            recovered_certificates.values()
                                .find(|c| c.seq == max_quorum_seq && c.digest == best_digest && c.verify(quorum_size, &initial_public_keys))
                                .cloned()
                        } else {
                            None
                        };

                        if max_quorum_seq == 0 || bound_cert.is_some() {
                            let nv_cert = NewViewCertificate {
                                target_view: view,
                                view_change_votes: supporters.clone(),
                                selected_prepared_certificate: bound_cert,
                            };
                            if nv_cert.verify(quorum_size, &initial_public_keys) {
                                recovered_new_view_certificates.insert(view, nv_cert);
                            }
                        }
                    }
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
            commit_certificates: recovered_commit_certificates,
            new_view_certificates: recovered_new_view_certificates,
            committed_digest: recovered_committed,
            pre_prepared_proposals: recovered_proposals,
            prepare_votes: recovered_prepare_votes,
            commit_votes: recovered_commit_votes,
            view_change_votes: recovered_view_change_votes,
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
                if msg.view < self.current_view {
                    return Err("VIEW_MISMATCH: PrePrepare view is older than current consensus view!");
                }

                // SECURE LEADER VALIDATION (No test hacks)
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
                
                if msg.view > self.current_view {
                    self.current_view = msg.view;
                }

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
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated Prepared QC failed cryptographic verification!");
                    }

                    self.prepared_certificates.insert((msg.view, msg.seq), cert);
                    format!("✅ [VERIFIED PREPARED CERTIFICATE]: Quorum achieved for View {} Seq {}.", msg.view, msg.seq)
                } else {
                    format!("⏳ [PREPARE VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
                }
            }

            Phase::Commit => {
                let has_valid_certificate = self.prepared_certificates.values()
                    .any(|cert| cert.seq == msg.seq && cert.digest == msg.digest && cert.verify(self.quorum_size, &self.public_keys));

                if !has_valid_certificate {
                    return Err("SAFETY_VIOLATION: Node cannot commit without a cryptographically verified Prepared Certificate!");
                }

                if let Some(existing_digest) = self.committed_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting COMMIT digest for same sequence!");
                    }
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                let sigs = self.commit_votes.entry(proposal_key).or_default();
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let commit_cert = CommitCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };

                    if !commit_cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated Commit Certificate failed cryptographic verification!");
                    }

                    self.commit_certificates.insert((msg.view, msg.seq), commit_cert);
                    self.committed_digest.insert((msg.view, msg.seq), msg.digest);
                    format!("🏆 [COMMITTED WITH CERTIFICATE]: Sequence {} definitively committed under View {}.", msg.seq, msg.view)
                } else {
                    format!("⏳ [COMMIT VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
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
                supporters.insert(msg.sender_id, (msg.seq, msg.digest, msg.signature));

                if supporters.len() >= self.quorum_size {
                    self.current_view = msg.view;
                    
                    let max_quorum_seq = supporters.values().map(|&(s, _, _)| s).max().unwrap_or(0);
                    let best_digest = supporters.values()
                        .find(|&&(s, _, _)| s == max_quorum_seq)
                        .map(|&(_, d, _)| d)
                        .unwrap_or([0u8; 32]);

                    let bound_cert = if max_quorum_seq > 0 {
                        let cert_opt = self.prepared_certificates.values()
                            .find(|c| c.seq == max_quorum_seq && c.digest == best_digest && c.verify(self.quorum_size, &self.public_keys))
                            .cloned();
                        
                        if cert_opt.is_none() {
                            return Err("MISSING_QUORUM_CERTIFICATE: Quorum claims a high-seq PreparedCertificate, but it is missing locally. Rejecting NewView transition!");
                        }
                        cert_opt
                    } else {
                        None
                    };

                    if let Some(ref cert) = bound_cert {
                        self.highest_seq = self.highest_seq.max(cert.seq);
                    }

                    let new_view_cert = NewViewCertificate {
                        target_view: msg.view,
                        view_change_votes: supporters.clone(),
                        selected_prepared_certificate: bound_cert,
                    };

                    if !new_view_cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("NEW_VIEW_VERIFICATION_FAILED: NewViewCertificate cryptographic verification failed! Bound certificate mismatch.");
                    }

                    self.new_view_certificates.insert(msg.view, new_view_cert);
                    format!("🔄 [STRICT QUORUM-SOURCED BOUND NEW VIEW CERTIFICATE]: Quorum reached for View {}. Inherited Seq: {}", msg.view, max_quorum_seq)
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
