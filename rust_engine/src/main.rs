use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;

// ==========================================
// 🔒 MOCK CRYPTO MODULE
// ==========================================
#[derive(Debug, Clone)]
pub struct AggregateSignature {
    pub is_valid: bool,
}

pub fn verify_mock(sig: &AggregateSignature) -> bool {
    sig.is_valid
}

// ==========================================
// 🛡️ SOVEREIGN LATTICE - ASYNC PBFT ENGINE 
// ==========================================
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub number: u64,
    pub leader: u64,
}

#[derive(Debug, Clone)]
pub enum MonitorEvent {
    Commit { seq: u64, digest: u64, sig: AggregateSignature },
    Timeout,
    NewView { view: View, sig: AggregateSignature },
}

#[derive(Debug, Clone)]
pub struct PBFTMonitorState {
    pub current_view: View,
    pub last_seq: u64,
    pub locked_digest: Option<u64>,
    pub view_change_votes: u32,
    pub last_progress: Instant,
    pub timeout: Duration,
}

impl PBFTMonitorState {
    pub fn new(initial_leader: u64, timeout_secs: u64) -> Self {
        Self {
            current_view: View { number: 0, leader: initial_leader },
            last_seq: 0,
            locked_digest: None,
            view_change_votes: 0,
            last_progress: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn dispatch(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::Commit { seq, digest, sig } => {
                if verify_mock(&sig) && seq == self.last_seq + 1 {
                    self.last_seq = seq;
                    self.locked_digest = Some(digest);
                    self.reset_timer();
                    println!("✅ [COMMIT] Seq: {}, Digest: {} (VERIFIED)", seq, digest);
                } else {
                    println!("❌ [COMMIT REJECTED] Seq: {}", seq);
                }
            }
            MonitorEvent::Timeout => {
                self.view_change_votes += 1;
                println!("⚠️ [TIMEOUT] Votes: {}", self.view_change_votes);
            }
            MonitorEvent::NewView { view, sig } => {
                if verify_mock(&sig) && view.number > self.current_view.number {
                    self.current_view = view;
                    self.reset_timer();
                    println!("🔄 [NEW VIEW] Shifted to View {} (Leader: {})", 
                             self.current_view.number, self.current_view.leader);
                } else {
                    println!("❌ [NEW VIEW REJECTED]");
                }
            }
        }
    }

    fn reset_timer(&mut self) {
        self.last_progress = Instant::now();
        self.view_change_votes = 0;
    }

    pub fn check_timeout(&mut self) {
        if self.last_progress.elapsed() >= self.timeout {
            self.dispatch(MonitorEvent::Timeout);
            self.last_progress = Instant::now() - (self.timeout / 2);
        }
    }

    /// The beating heart of the daemon running in the background
    pub async fn run_daemon(&mut self, mut rx: mpsc::Receiver<MonitorEvent>) {
        println!("🚀 [DAEMON] PBFT Async Engine Started...");
        let mut interval = time::interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    self.dispatch(event);
                }
                _ = interval.tick() => {
                    self.check_timeout();
                }
            }
        }
    }
}

// ==========================================
// 🌐 ASYNC TEST SUITE
// ==========================================
#[tokio::main]
async fn main() {
    println!("========================================");
    println!(" 🌐 SOVEREIGN LATTICE (TOKIO ASYNC MODE) ");
    println!("========================================\n");
    
    let (tx, rx) = mpsc::channel(100);
    let mut engine = PBFTMonitorState::new(1, 2);
    
    tokio::spawn(async move {
        engine.run_daemon(rx).await;
    });

    time::sleep(Duration::from_millis(500)).await;
    
    println!("[*] Sending Valid Commit...");
    let valid_sig = AggregateSignature { is_valid: true };
    tx.send(MonitorEvent::Commit { seq: 1, digest: 1042, sig: valid_sig }).await.unwrap();

    println!("\n[*] Simulating network delay to trigger timeout...");
    time::sleep(Duration::from_secs(3)).await;

    println!("\n[*] Sending New View transaction to recover network...");
    let new_view_sig = AggregateSignature { is_valid: true };
    tx.send(MonitorEvent::NewView { 
        view: View { number: 1, leader: 2 }, 
        sig: new_view_sig 
    }).await.unwrap();

    time::sleep(Duration::from_millis(500)).await;
    println!("\n[*] Async Test Complete! Network survived.");
}

