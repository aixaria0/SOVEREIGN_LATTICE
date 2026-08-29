// src/main.rs

// Uncomment these lines once the respective files are fully debugged 
// to make their modules available across the project:
// mod schnorr_proof;
// mod feldman_dkg;
// mod frost_sim;

use std::time::{Duration, Instant};

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
    Commit { seq: u64, digest: u64, cert_ok: bool },
    Checkpoint { seq: u64, cert_ok: bool },
    Timeout,
    NewView { view: View, cert_ok: bool },
}

#[derive(Debug, Clone)]
pub struct PBFTMonitorState {
    pub current_view: View,
    pub last_seq: u64,
    pub locked_digest: Option<u64>,
    pub checkpoint: u64,
    pub decided: Vec<(u64, u64)>, // (seq, digest)
    pub view_change_votes: u32,
    
    // Timeout management
    pub last_progress: Instant,
    pub timeout: Duration,
}

impl PBFTMonitorState {
    /// Initializes the PBFT monitor engine
    pub fn new(initial_leader: u64, timeout_secs: u64) -> Self {
        Self {
            current_view: View { number: 0, leader: initial_leader },
            last_seq: 0,
            locked_digest: None,
            checkpoint: 0,
            decided: Vec::new(),
            view_change_votes: 0,
            last_progress: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Core dispatcher handling all network events
    pub fn dispatch(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::Commit { seq, digest, cert_ok } => {
                if cert_ok && seq == self.last_seq + 1 {
                    self.last_seq = seq;
                    self.locked_digest = Some(digest);
                    self.decided.push((seq, digest));
                    self.reset_timer();
                    println!("✅ [COMMIT] Sequence: {}, Digest: {}", seq, digest);
                } else {
                    println!("❌ [COMMIT REJECTED] Sequence: {} (Invalid Cert or Seq)", seq);
                }
            }
            MonitorEvent::Checkpoint { seq, cert_ok } => {
                if cert_ok && seq > self.checkpoint {
                    self.checkpoint = seq;
                    self.reset_timer();
                    println!("🔒 [CHECKPOINT] System stable at Sequence: {}", seq);
                }
            }
            MonitorEvent::Timeout => {
                self.view_change_votes += 1;
                println!("⚠️ [TIMEOUT] Leader unresponsive. View-change votes: {}", self.view_change_votes);
            }
            MonitorEvent::NewView { view, cert_ok } => {
                if cert_ok && view.number > self.current_view.number {
                    self.current_view = view;
                    self.reset_timer();
                    println!("🔄 [NEW VIEW] Shifted to View {} (Leader: Node {})", 
                             self.current_view.number, self.current_view.leader);
                }
            }
        }
    }

    /// Manually checks for timeouts
    pub fn check_timeout(&mut self) {
        if self.last_progress.elapsed() >= self.timeout {
            self.dispatch(MonitorEvent::Timeout);
        }
    }

    /// Determines if old logs can be garbage collected
    pub fn can_gc(&self, seq: u64) -> bool {
        seq <= self.checkpoint
    }

    /// Resets the internal timer after a successful progression
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
    
    // Initialize monitor with Leader Node 1 and a 5-second timeout
    let mut engine = PBFTMonitorState::new(1, 5);
    println!("[*] Engine initialized -> Leader: {}, Timeout: {}s\n", 
             engine.current_view.leader, engine.timeout.as_secs());
    
    // Simulate a successful network scenario
    engine.dispatch(MonitorEvent::Commit { seq: 1, digest: 1042, cert_ok: true });
    engine.dispatch(MonitorEvent::Commit { seq: 2, digest: 2042, cert_ok: true });
    engine.dispatch(MonitorEvent::Checkpoint { seq: 2, cert_ok: true });
    
    // Simulate an error (e.g., node with invalid certificate)
    engine.dispatch(MonitorEvent::Commit { seq: 3, digest: 3042, cert_ok: false });

    println!("\n[*] Checking Garbage Collection Status...");
    println!(" -> Can GC seq 1? {}", engine.can_gc(1));
    println!(" -> Can GC seq 3? {}", engine.can_gc(3));

    println!("\n[*] Final Engine State:");
    println!("{:#?}", engine);
}
