// src/main.rs

pub mod schnorr_proof;
pub mod feldman_dkg;
pub mod frost_sim;
pub mod threshold_bls;

use std::time::{Duration, Instant};

// ---------------------------------------------------------
// Importing Cryptographic Primitives from our internal modules
// ---------------------------------------------------------
use threshold_bls::{PublicKey, AggregateSignature, verify};
use bls12_381::{G1Projective, G2Projective};
use group::Group;

// ==========================================
// 🛡️ SOVEREIGN LATTICE - PBFT ENGINE 
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub number: u64,
    pub leader: u64,
}

#[derive(Debug, Clone)]
pub enum MonitorEvent {
    // Events now require a mathematically valid cryptographic signature
    Commit { seq: u64, digest: u64, sig: AggregateSignature },
    Checkpoint { seq: u64, sig: AggregateSignature },
    Timeout,
    NewView { view: View, sig: AggregateSignature },
}

#[derive(Debug, Clone)]
pub struct PBFTMonitorState {
    pub current_view: View,
    pub last_seq: u64,
    pub locked_digest: Option<u64>,
    pub checkpoint: u64,
    pub decided: Vec<(u64, u64)>, 
    pub view_change_votes: u32,
    
    // The Group Public Key generated during the DKG phase
    pub group_public_key: PublicKey,
    
    pub last_progress: Instant,
    pub timeout: Duration,
}

impl PBFTMonitorState {
    /// Initializes the PBFT monitor engine with the established group public key
    pub fn new(initial_leader: u64, timeout_secs: u64, pk: PublicKey) -> Self {
        Self {
            current_view: View { number: 0, leader: initial_leader },
            last_seq: 0,
            locked_digest: None,
            checkpoint: 0,
            decided: Vec::new(),
            view_change_votes: 0,
            group_public_key: pk,
            last_progress: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Core dispatcher handling all network events with strict crypto verification
    pub fn dispatch(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::Commit { seq, digest, sig } => {
                let msg = format!("COMMIT_{}_{}", seq, digest);
                
                // 1. Verify the threshold signature
                let is_valid = verify(&self.group_public_key, msg.as_bytes(), &sig);

                // 2. Apply state transition if logically and cryptographically valid
                if is_valid && seq == self.last_seq + 1 {
                    self.last_seq = seq;
                    self.locked_digest = Some(digest);
                    self.decided.push((seq, digest));
                    self.reset_timer();
                    println!("✅ [COMMIT] Seq: {}, Digest: {} (Signature VERIFIED)", seq, digest);
                } else {
                    println!("❌ [COMMIT REJECTED] Seq: {} (Invalid Signature or Sequence)", seq);
                }
            }
            MonitorEvent::Checkpoint { seq, sig } => {
                let msg = format!("CHECKPOINT_{}", seq);
                let is_valid = verify(&self.group_public_key, msg.as_bytes(), &sig);

                if is_valid && seq > self.checkpoint {
                    self.checkpoint = seq;
                    self.reset_timer();
                    println!("🔒 [CHECKPOINT] Stable at Seq: {} (Signature VERIFIED)", seq);
                } else {
                    println!("❌ [CHECKPOINT REJECTED] Invalid Signature for Seq: {}", seq);
                }
            }
            MonitorEvent::Timeout => {
                self.view_change_votes += 1;
                println!("⚠️ [TIMEOUT] Leader unresponsive. Votes: {}", self.view_change_votes);
            }
            MonitorEvent::NewView { view, sig } => {
                let msg = format!("NEWVIEW_{}_{}", view.number, view.leader);
                let is_valid = verify(&self.group_public_key, msg.as_bytes(), &sig);

                if is_valid && view.number > self.current_view.number {
                    self.current_view = view;
                    self.reset_timer();
                    println!("🔄 [NEW VIEW] Shifted to View {} (Leader: {})", 
                             self.current_view.number, self.current_view.leader);
                } else {
                    println!("❌ [NEW VIEW REJECTED] Invalid Signature");
                }
            }
        }
    }

    pub fn check_timeout(&mut self) {
        if self.last_progress.elapsed() >= self.timeout {
            self.dispatch(MonitorEvent::Timeout);
        }
    }

    pub fn can_gc(&self, seq: u64) -> bool {
        seq <= self.checkpoint
    }

    fn reset_timer(&mut self) {
        self.last_progress = Instant::now();
        self.view_change_votes = 0;
    }
}

// ==========================================
// 🚀 MAIN ENTRY POINT
// ==========================================

fn main() {
    println!("========================================");
    println!(" 🏛️  SOVEREIGN LATTICE ENGINE BOOTING  ");
    println!("========================================\n");
    
    // In a live system, this key is generated dynamically via Feldman DKG.
    // We mock the public key structure here for architectural integrity.
    let genesis_pk = PublicKey(G2Projective::generator());
    
    // Initialize monitor
    let mut engine = PBFTMonitorState::new(1, 5, genesis_pk);
    println!("[*] Engine initialized -> Leader: {}, Timeout: {}s\n", 
             engine.current_view.leader, engine.timeout.as_secs());
             
    println!("[*] Sending test events with DUMMY signatures to trigger validation logic...\n");

    // Creating a dummy signature (This will logically fail the cryptographic check!)
    let dummy_sig = AggregateSignature(G1Projective::generator());

    // Dispatching events: We EXPECT these to fail because the math is now real!
    engine.dispatch(MonitorEvent::Commit { seq: 1, digest: 1042, sig: dummy_sig.clone() });
    engine.dispatch(MonitorEvent::Commit { seq: 2, digest: 2042, sig: dummy_sig.clone() });
    
    println!("\n[*] Final Engine State:");
    println!("{:#?}", engine);
}
