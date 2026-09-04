use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use bls12_381::{G1Projective, G2Projective, G1Affine};
use group::Curve;
use crate::threshold_bls::{verify_bls_signature, verify_bound_threshold_signature};
use crate::wal::WriteAheadLog;

static TEST_WAL_COUNTER: AtomicUsize = AtomicUsize::new(0);

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

impl PbftMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(101);
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 101 {
            return Err("INVALID_PAYLOAD_SIZE: Expected exactly 101 bytes for PBFT Message.");
        }
        
        let phase = match bytes[0] {
            0 => Phase::PrePrepare,
            1 => Phase::Prepare,
            2 => Phase::Commit,
            3 => Phase::ViewChange,
            _ => return Err("INVALID_PHASE: Byte does not match any known consensus phase."),
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
        let signature = affine_opt.map(G1Projective::from).ok_or("INVALID_SIGNATURE_BYTES: Failed to decompress BLS signature.")?;

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

#[derive(Clone)]
pub struct ViewChangePayload {
    pub target_view: u64,
    pub prepared_view: u64,
    pub prepared_seq: u64,
    pub digest: [u8; 32],
    pub sender_id: u32,
    pub signature: G1Projective,
}

impl ViewChangePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(109);
        bytes.push(Phase::ViewChange as u8);
        bytes.extend_from_slice(&self.target_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 109 {
            return Err("INVALID_PAYLOAD_SIZE: Expected exactly 109 bytes for ViewChange Message.");
        }
        if bytes[0] != Phase::ViewChange as u8 {
            return Err("INVALID_PHASE: Byte does not match ViewChange phase.");
        }

        let mut target_bytes = [0u8; 8];
        target_bytes.copy_from_slice(&bytes[1..9]);
        let target_view = u64::from_be_bytes(target_bytes);

        let mut prep_view_bytes = [0u8; 8];
        prep_view_bytes.copy_from_slice(&bytes[9..17]);
        let prepared_view = u64::from_be_bytes(prep_view_bytes);

        let mut prep_seq_bytes = [0u8; 8];
        prep_seq_bytes.copy_from_slice(&bytes[17..25]);
        let prepared_seq = u64::from_be_bytes(prep_seq_bytes);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[25..57]);

        let mut sender_bytes = [0u8; 4];
        sender_bytes.copy_from_slice(&bytes[57..61]);
        let sender_id = u32::from_be_bytes(sender_bytes);

        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&bytes[61..109]);

        let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
        let signature = affine_opt.map(G1Projective::from).ok_or("INVALID_SIGNATURE_BYTES: Failed to decompress BLS signature.")?;

        Ok(Self {
            target_view,
            prepared_view,
            prepared_seq,
            digest,
            sender_id,
            signature,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(Phase::ViewChange as u8);
        msg.extend_from_slice(&self.target_view.to_be_bytes());
        msg.extend_from_slice(&self.prepared_view.to_be_bytes());
        msg.extend_from_slice(&self.prepared_seq.to_be_bytes());
        msg.extend_from_slice(&self.digest);
        msg
    }
}

#[derive(Clone)]
pub struct PreparedCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl PreparedCertificate {
    pub fn verify(&self, quorum_size: usize, master_public_key: &G2Projective) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
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

#[derive(Clone)]
pub struct CommitCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl CommitCertificate {
    pub fn verify(&self, quorum_size: usize, master_public_key: &G2Projective) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
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

#[derive(Clone)]
pub struct NewViewCertificate {
    pub target_view: u64,
    pub view_change_votes: HashMap<u32, (u64, u64, [u8; 32], G1Projective)>,
    pub selected_prepared_certificate: Option<PreparedCertificate>,
}

impl NewViewCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>, master_public_key: &G2Projective) -> bool {
        if self.view_change_votes.len() < quorum_size {
            return false;
        }

        let mut highest_valid_claim: Option<(u64, u64, [u8; 32])> = None;

        for v in self.view_change_votes.values() {
            let (p_view, p_seq, p_digest) = (v.0, v.1, v.2);
            let is_valid_claim = (p_view == 0 && p_seq == 0) || self.selected_prepared_certificate.as_ref()
                .map_or(false, |cert| cert.view == p_view && cert.seq == p_seq && cert.digest == p_digest);

            if is_valid_claim {
                if let Some(current) = highest_valid_claim {
                    if p_view > current.0 || (p_view == current.0 && p_seq > current.1) {
                        highest_valid_claim = Some((p_view, p_seq, p_digest));
                    }
                } else {
                    highest_valid_claim = Some((p_view, p_seq, p_digest));
                }
            }
        }

        let (max_prep_view, max_seq_at_max_view, best_digest) = highest_valid_claim.unwrap_or((0, 0, [0u8; 32]));

        if let Some(ref cert) = self.selected_prepared_certificate {
            if !cert.verify(quorum_size, master_public_key) {
                return false;
            }
            if cert.view != max_prep_view || cert.seq != max_seq_at_max_view || cert.digest != best_digest {
                return false;
            }
        } else if max_prep_view > 0 || max_seq_at_max_view > 0 {
            return false;
        }

        let mut valid_count = 0;
        for (&node_id, vote_data) in &self.view_change_votes {
            if let Some(pk) = public_keys.get(&node_id) {
                let vc_payload = ViewChangePayload {
                    target_view: self.target_view,
                    prepared_view: vote_data.0,
                    prepared_seq: vote_data.1,
                    digest: vote_data.2,
                    sender_id: node_id,
                    signature: vote_data.3.clone(),
                };
                let canonical_msg = vc_payload.canonical_bytes();

                if verify_bls_signature(&canonical_msg, &vote_data.3, pk) {
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
    pub locked_digest: HashMap<u64, [u8; 32]>,
    pre_prepared_proposals: HashSet<(u64, u64, [u8; 32])>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    pub view_change_votes: HashMap<u64, HashMap<u32, (u64, u64, [u8; 32], G1Projective)>>, 
    pub quorum_size: usize,
    registered_nodes: HashSet<u32>,
    pub public_keys: HashMap<u32, G2Projective>,
    pub master_public_key: G2Projective,
    wal: WriteAheadLog,
}

impl PbftState {
    pub fn new(total_nodes: usize, initial_public_keys: HashMap<u32, G2Projective>, master_public_key: G2Projective) -> Result<Self, &'static str> {
        if total_nodes < 4 {
            return Err("TOPOLOGY_VIOLATION: Network size N must be at least 4 for PBFT (f >= 1).");
        }
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
            let count = TEST_WAL_COUNTER.fetch_add(1, Ordering::SeqCst);
            format!("consensus_wal_test_{}_{:?}.log", count, std::thread::current().id())
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
        let mut recovered_view_change_votes: HashMap<u64, HashMap<u32, (u64, u64, [u8; 32], G1Projective)>> = HashMap::new();
        let mut recovered_certificates = HashMap::new();
        let mut recovered_commit_certificates = HashMap::new();
        let mut recovered_new_view_certificates = HashMap::new();
        let mut recovered_committed = HashMap::new();
        let mut recovered_locked = HashMap::new();

        wal.replay_log(|view, seq_or_packed, phase_u8, sender_id, digest, signature| {
            if view > recovered_view { recovered_view = view; }
            
            let (prep_view, seq) = if phase_u8 == Phase::ViewChange as u8 {
                (seq_or_packed >> 32, seq_or_packed & 0xFFFFFFFF)
            } else {
                (view, seq_or_packed)
            };

            if seq > recovered_seq { recovered_seq = seq; }
            
            match phase_u8 {
                0 => { 
                    recovered_proposals.insert((prep_view, seq, digest)); 
                }
                1 => {
                    let sigs = recovered_prepare_votes.entry((prep_view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let cert = PreparedCertificate { view: prep_view, seq, digest, signatures: sigs.clone() };
                        if cert.verify(quorum_size, &master_public_key) {
                            recovered_certificates.insert((prep_view, seq), cert);
                        }
                    }
                }
                2 => {
                    let sigs = recovered_commit_votes.entry((prep_view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let commit_cert = CommitCertificate { view: prep_view, seq, digest, signatures: sigs.clone() };
                        if commit_cert.verify(quorum_size, &master_public_key) {
                            recovered_commit_certificates.insert((prep_view, seq), commit_cert);
                            recovered_committed.insert((prep_view, seq), digest);
                        }
                    }
                }
                3 => {
                    let supporters = recovered_view_change_votes.entry(view).or_default();
                    supporters.insert(sender_id, (prep_view, seq, digest, signature));
                    if supporters.len() >= quorum_size {
                        let mut highest_valid_claim: Option<(u64, u64, [u8; 32])> = None;

                        for v in supporters.values() {
                            let (p_view, p_seq, p_digest) = (v.0, v.1, v.2);
                            let is_valid_claim = if p_view > 0 || p_seq > 0 {
                                recovered_certificates.get(&(p_view, p_seq))
                                    .map(|cert| cert.digest == p_digest && cert.verify(quorum_size, &master_public_key))
                                    .unwrap_or(false)
                            } else {
                                true
                            };

                            if is_valid_claim {
                                if let Some(current) = highest_valid_claim {
                                    if p_view > current.0 || (p_view == current.0 && p_seq > current.1) {
                                        highest_valid_claim = Some((p_view, p_seq, p_digest));
                                    }
                                } else {
                                    highest_valid_claim = Some((p_view, p_seq, p_digest));
                                }
                            }
                        }

                        let (max_prep_view, max_seq_at_max_view, best_digest) = highest_valid_claim.unwrap_or((0, 0, [0u8; 32]));

                        let bound_cert = if max_prep_view > 0 || max_seq_at_max_view > 0 {
                            recovered_certificates.get(&(max_prep_view, max_seq_at_max_view))
                                .filter(|c| c.digest == best_digest && c.verify(quorum_size, &master_public_key))
                                .cloned()
                        } else {
                            None
                        };

                        if (max_prep_view == 0 && max_seq_at_max_view == 0) || bound_cert.is_some() {
                            if let Some(ref cert) = bound_cert {
                                recovered_locked.insert(cert.seq, cert.digest);
                            }
                            let nv_cert = NewViewCertificate {
                                target_view: view,
                                view_change_votes: supporters.clone(),
                                selected_prepared_certificate: bound_cert,
                            };
                            if nv_cert.verify(quorum_size, &initial_public_keys, &master_public_key) {
                                recovered_new_view_certificates.insert(view, nv_cert);
                            }
                        }
                    }
                }
                _ => {}
            }
        }).map_err(|_| "WAL_CORRUPTION_FATAL: Log integrity compromised during replay.")?;

        Ok(Self {
            total_nodes,
            f,
            current_view: recovered_view,
            highest_seq: recovered_seq,
            prepared_certificates: recovered_certificates,
            commit_certificates: recovered_commit_certificates,
            new_view_certificates: recovered_new_view_certificates,
            committed_digest: recovered_committed,
            locked_digest: recovered_locked,
            pre_prepared_proposals: recovered_proposals,
            prepare_votes: recovered_prepare_votes,
            commit_votes: recovered_commit_votes,
            view_change_votes: recovered_view_change_votes,
            quorum_size,
            registered_nodes,
            public_keys: initial_public_keys,
            master_public_key,
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

                let last_globally_committed_seq = self.commit_certificates.keys()
                    .map(|&(_, s)| s)
                    .max()
                    .unwrap_or(0);
                    
                if msg.seq > 0 && msg.seq <= last_globally_committed_seq {
                    return Err("SEQUENCE_VIOLATION: Proposed sequence is older than or equal to a GLOBALLY committed block!");
                }

                if let Some(locked) = self.locked_digest.get(&msg.seq) {
                    if locked != &msg.digest {
                        return Err("CROSS_VIEW_LOCK_VIOLATION: Proposal conflicts with locked inherited digest!");
                    }
                }

                let has_equivocated = self.pre_prepared_proposals.iter()
                    .any(|&(v, s, d)| v == msg.view && s == msg.seq && d != msg.digest);
                if has_equivocated {
                    return Err("EQUIVOCATION_DETECTED: Malicious leader proposed conflicting digests for the same sequence!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("DUPLICATE_PROPOSAL: PrePrepare for this sequence and digest already processed!");
                }

                self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
                    .map_err(|_| "WAL_ERROR: Failed to write valid PrePrepare to durable log!")?;

                self.pre_prepared_proposals.insert(proposal_key);
                self.highest_seq = self.highest_seq.max(msg.seq);
                
                format!("📥 [PRE-PREPARE]: Validated leader {} proposal for View {} Seq {}.", msg.sender_id, msg.view, msg.seq)
            }

            Phase::Prepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: Prepare view does not match current consensus view!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if !self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("PREPARE_WITHOUT_PREPREPARE: Prepare rejected; no valid PrePrepare exists for this digest.");
                }

                let sigs = self.prepare_votes.entry(proposal_key).or_default();
                if sigs.contains_key(&msg.sender_id) {
                    return Err("DUPLICATE_VOTE_DETECTED: Node attempted to vote twice for the same sequence!");
                }

                self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
                    .map_err(|_| "WAL_ERROR: Failed to write valid Prepare to durable log!")?;
                
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let cert = PreparedCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };
                    
                    if !cert.verify(self.quorum_size, &self.master_public_key) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated Prepared QC failed cryptographic verification!");
                    }

                    self.prepared_certificates.insert((msg.view, msg.seq), cert);
                    format!("✅ [VERIFIED PREPARED CERTIFICATE]: Quorum achieved for View {} Seq {}.", msg.view, msg.seq)
                } else {
                    format!("⏳ [PREPARE VOTE]: Recorded from Node {}. Progress: {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
                }
            }

            Phase::Commit => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: Commit view does not match current consensus view!");
                }

                let has_valid_certificate = self.prepared_certificates
                    .get(&(msg.view, msg.seq))
                    .map(|cert| cert.digest == msg.digest && cert.verify(self.quorum_size, &self.master_public_key))
                    .unwrap_or(false);

                if !has_valid_certificate {
                    return Err("SAFETY_VIOLATION: Node cannot commit without a cryptographically verified Prepared Certificate for THIS view!");
                }

                if let Some(existing_digest) = self.committed_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting COMMIT digest for same sequence!");
                    }
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                let sigs = self.commit_votes.entry(proposal_key).or_default();
                
                if sigs.contains_key(&msg.sender_id) {
                    return Err("DUPLICATE_VOTE_DETECTED: Node attempted to commit twice for the same sequence!");
                }

                self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
                    .map_err(|_| "WAL_ERROR: Failed to write valid Commit to durable log!")?;
                
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let commit_cert = CommitCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };

                    if !commit_cert.verify(self.quorum_size, &self.master_public_key) {
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
                return Err("VIEW_CHANGE_USE_PAYLOAD: ViewChange messages must be processed via handle_view_change_payload using the explicit 109-byte format.");
            }
        };

        Ok(response)
    }

    pub fn handle_view_change_payload(&mut self, vc: &ViewChangePayload) -> Result<String, &'static str> {
        if !self.registered_nodes.contains(&vc.sender_id) {
            return Err("AUTH_FAILED: Sender ID is not part of the active node registry!");
        }

        let pk = self.public_keys.get(&vc.sender_id)
            .ok_or("CRYPTO_AUTH_FAILED: Public key not found for sender!")?;

        let canonical_msg = vc.canonical_bytes();
        if !verify_bls_signature(&canonical_msg, &vc.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Cryptographic BLS signature verification failed for ViewChange!");
        }

        if vc.target_view <= self.current_view {
            return Err("VIEW_CHANGE_INVALID: Target view must be greater than current view!");
        }

        if vc.prepared_seq > 0 {
            let has_valid_qc = self.prepared_certificates
                .get(&(vc.prepared_view, vc.prepared_seq))
                .map(|cert| cert.digest == vc.digest && cert.verify(self.quorum_size, &self.master_public_key))
                .unwrap_or(false);

            if !has_valid_qc {
                return Err("CERTIFICATE_INVALID: ViewChange rejected; missing cryptographically verified Quorum Certificate matching prepared_view and seq!");
            }
        }

        let packed_seq = (vc.prepared_view << 32) | (vc.prepared_seq & 0xFFFFFFFF);
        self.wal.append_entry(vc.target_view, packed_seq, Phase::ViewChange as u8, vc.sender_id, &vc.digest, &vc.signature)
            .map_err(|_| "WAL_ERROR: Failed to write valid ViewChange to durable log!")?;

        let supporters = self.view_change_votes.entry(vc.target_view).or_default();
        if supporters.contains_key(&vc.sender_id) {
            return Err("DUPLICATE_VOTE_DETECTED: Node attempted to broadcast ViewChange twice for the same target view!");
        }

        supporters.insert(vc.sender_id, (vc.prepared_view, vc.prepared_seq, vc.digest, vc.signature));

        if supporters.len() >= self.quorum_size {
            let mut highest_valid_claim: Option<(u64, u64, [u8; 32])> = None;

            for v in supporters.values() {
                let (p_view, p_seq, p_digest) = (v.0, v.1, v.2);
                
                let is_valid_claim = if p_view > 0 || p_seq > 0 {
                    self.prepared_certificates.get(&(p_view, p_seq))
                        .map(|cert| cert.digest == p_digest && cert.verify(self.quorum_size, &self.master_public_key))
                        .unwrap_or(false)
                } else {
                    true
                };

                if is_valid_claim {
                    if let Some(current) = highest_valid_claim {
                        if p_view > current.0 || (p_view == current.0 && p_seq > current.1) {
                            highest_valid_claim = Some((p_view, p_seq, p_digest));
                        }
                    } else {
                        highest_valid_claim = Some((p_view, p_seq, p_digest));
                    }
                }
            }

            let (max_prep_view, max_seq_at_max_view, best_digest) = highest_valid_claim.unwrap_or((0, 0, [0u8; 32]));

            let bound_cert = if max_prep_view > 0 || max_seq_at_max_view > 0 {
                let cert_opt = self.prepared_certificates
                    .get(&(max_prep_view, max_seq_at_max_view))
                    .filter(|c| c.digest == best_digest && c.verify(self.quorum_size, &self.master_public_key))
                    .cloned();
                
                if cert_opt.is_none() {
                    return Err("MISSING_QUORUM_CERTIFICATE: Quorum claims a high-view PreparedCertificate, but it is missing locally. Rejecting NewView transition!");
                }
                cert_opt
            } else {
                None
            };

            let new_view_cert = NewViewCertificate {
                target_view: vc.target_view,
                view_change_votes: supporters.clone(),
                selected_prepared_certificate: bound_cert.clone(),
            };

            if !new_view_cert.verify(self.quorum_size, &self.public_keys, &self.master_public_key) {
                return Err("NEW_VIEW_VERIFICATION_FAILED: NewViewCertificate cryptographic verification failed! Bound certificate mismatch.");
            }

            self.current_view = vc.target_view;
            if let Some(ref cert) = bound_cert {
                self.highest_seq = self.highest_seq.max(cert.seq);
                self.locked_digest.insert(cert.seq, cert.digest);
            }
            self.new_view_certificates.insert(vc.target_view, new_view_cert);

            Ok(format!("🔄 [STRICT QUORUM-SOURCED BOUND NEW VIEW CERTIFICATE]: Quorum reached for View {}. Inherited PrepView: {}, Seq: {}", vc.target_view, max_prep_view, max_seq_at_max_view))
        } else {
            Ok(format!("🔄 [VIEW CHANGE VOTE]: Recorded for View {}. Progress: {}/{}", vc.target_view, supporters.len(), self.quorum_size))
        }
    }

    pub fn process_network_message(&mut self, payload: &[u8]) {
        println!("🧩 [NETWORK->PBFT]: Received {} bytes. Starting safe deserialization...", payload.len());
        
        if payload.len() == 109 && payload[0] == Phase::ViewChange as u8 {
            match ViewChangePayload::from_bytes(payload) {
                Ok(vc) => {
                    match self.handle_view_change_payload(&vc) {
                        Ok(log) => println!("{}", log),
                        Err(e) => eprintln!("⚠️ [CONSENSUS REJECTED]: {}", e),
                    }
                },
                Err(e) => eprintln!("❌ [NETWORK PARSE ERROR (ViewChange)]: {}", e),
            }
        } else {
            match PbftMessage::from_bytes(payload) {
                Ok(msg) => {
                    match self.handle_message(&msg) {
                        Ok(log) => println!("{}", log),
                        Err(e) => eprintln!("⚠️ [CONSENSUS REJECTED]: {}", e),
                    }
                },
                Err(e) => eprintln!("❌ [NETWORK PARSE ERROR]: {}", e),
            }
        }
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use bls12_381::{G1Projective, G2Projective, Scalar};
    use rand::rngs::OsRng;
    use ff::Field;
    use sha2::{Sha256, Digest};

    fn generate_test_keys(n: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>) {
        let mut secret_keys = HashMap::new();
        let mut public_keys = HashMap::new();
        for i in 0..n as u32 {
            let sk = Scalar::random(&mut OsRng);
            let pk = G2Projective::generator() * sk;
            secret_keys.insert(i, sk);
            public_keys.insert(i, pk);
        }
        (secret_keys, public_keys)
    }

    fn hash_to_curve(msg: &[u8]) -> G1Projective {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        let scalar_hash = Scalar::from_bytes(&bytes).unwrap_or(Scalar::one());
        G1Projective::generator() * scalar_hash
    }

    fn sign_message(msg: &[u8], sk: &Scalar) -> G1Projective {
        hash_to_curve(msg) * sk
    }

    #[test]
    fn test_ghost_certificate_attack_rejected() {
        let n = 4;
        let (secret_keys, public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator() * Scalar::random(&mut OsRng);
        
        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed to init state");
        
        let target_view: u64 = 1;
        let malicious_prep_view: u64 = 0;
        let malicious_seq: u64 = 999; 
        let malicious_digest = [0xbb; 32];

        let create_view_change = |sender_id: u32, sk: &Scalar| {
            let vc = ViewChangePayload {
                target_view,
                prepared_view: malicious_prep_view,
                prepared_seq: malicious_seq,
                digest: malicious_digest,
                sender_id,
                signature: G1Projective::identity(),
            };
            let canonical_msg = vc.canonical_bytes();
            let sig = sign_message(&canonical_msg, sk);
            ViewChangePayload {
                signature: sig,
                ..vc
            }
        };

        let vc1 = create_view_change(1, &secret_keys[&1]);
        let vc2 = create_view_change(2, &secret_keys[&2]);
        let vc3 = create_view_change(3, &secret_keys[&3]);

        let _ = state.handle_view_change_payload(&vc1);
        let _ = state.handle_view_change_payload(&vc2);
        let _ = state.handle_view_change_payload(&vc3);

        assert_eq!(state.highest_seq, 0, "SAFETY VIOLATION: Engine accepted unbacked phantom sequence!");
        assert_eq!(state.current_view, 0, "Engine should remain in view 0 because all ViewChange claims were maliciously forged!");
    }

    #[test]
    fn test_cross_view_equivocation_locked() {
        let n = 4;
        let (secret_keys, public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator() * Scalar::random(&mut OsRng);

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed to init state");

        let locked_seq = 10u64;
        let locked_digest = [0xaa; 32];
        let conflicting_digest = [0xbb; 32];

        state.current_view = 1;
        state.locked_digest.insert(locked_seq, locked_digest);

        let leader_id = state.get_expected_leader(1);
        let sk = &secret_keys[&leader_id];

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::PrePrepare as u8);
        canonical_msg.extend_from_slice(&1u64.to_be_bytes());
        canonical_msg.extend_from_slice(&locked_seq.to_be_bytes());
        canonical_msg.extend_from_slice(&conflicting_digest);

        let sig = sign_message(&canonical_msg, sk);

        let malicious_proposal = PbftMessage {
            phase: Phase::PrePrepare,
            view: 1,
            seq: locked_seq,
            digest: conflicting_digest,
            sender_id: leader_id,
            signature: sig,
        };

        let result = state.handle_message(&malicious_proposal);
        assert!(result.is_err(), "Leader proposal must be rejected due to cross-view lock violation");
        assert_eq!(result.unwrap_err(), "CROSS_VIEW_LOCK_VIOLATION: Proposal conflicts with locked inherited digest!");
    }

    #[test]
    fn test_sub_threshold_certificate_rejected() {
        let n = 4;
        let (secret_keys, _public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator() * Scalar::random(&mut OsRng);

        let view = 0u64;
        let seq = 1u64;
        let digest = [0x11; 32];

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&view.to_be_bytes());
        canonical_msg.extend_from_slice(&seq.to_be_bytes());
        canonical_msg.extend_from_slice(&digest);

        // Quorum for N=4 is 3. Provide only 2 signatures.
        let mut sub_threshold_sigs = HashMap::new();
        for id in 0..2u32 {
            let sig = sign_message(&canonical_msg, &secret_keys[&id]);
            sub_threshold_sigs.insert(id, sig);
        }

        let cert = PreparedCertificate {
            view,
            seq,
            digest,
            signatures: sub_threshold_sigs,
        };

        assert!(!cert.verify(3, &master_pk), "Sub-threshold certificate must fail verification against master PK");
    }
}
