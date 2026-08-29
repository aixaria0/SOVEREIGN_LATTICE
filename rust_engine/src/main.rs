use std::time::{Duration, Instant};

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
    pub fn new(initial_leader: u64, timeout: Duration) -> Self {
        Self {
            current_view: View { number: 0, leader: initial_leader },
            last_seq: 0,
            locked_digest: None,
            checkpoint: 0,
            decided: Vec::new(),
            view_change_votes: 0,
            last_progress: Instant::now(),
            timeout,
        }
    }

    pub fn on_event(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::Commit { seq, digest, cert_ok } => {
                if cert_ok && seq == self.last_seq + 1 {
                    self.last_seq = seq;
                    self.locked_digest = Some(digest);
                    self.decided.push((seq, digest));
                    self.last_progress = Instant::now();
                    self.view_change_votes = 0;
                }
            }
            MonitorEvent::Checkpoint { seq, cert_ok } => {
                if cert_ok && seq > self.checkpoint {
                    self.checkpoint = seq;
                    self.last_progress = Instant::now();
                }
            }
            MonitorEvent::Timeout => {
                if self.last_progress.elapsed() >= self.timeout {
                    self.view_change_votes += 1;
                    // In a full implementation this would broadcast a view-change message
                }
            }
            MonitorEvent::NewView { view, cert_ok } => {
                if cert_ok && view.number > self.current_view.number {
                    self.current_view = view;
                    self.view_change_votes = 0;
                    self.last_progress = Instant::now();
                }
            }
        }
    }

    pub fn check_timeout(&mut self) {
        if self.last_progress.elapsed() >= self.timeout {
            self.on_event(MonitorEvent::Timeout);
        }
    }

    pub fn can_gc(&self, seq: u64) -> bool {
        seq <= self.checkpoint
    }
}

fn main() {
    println!("🏛️ Initializing Sovereign Lattice PBFT Monitor...");
    
    // Initialize the monitor with Leader 1 and a 5-second timeout
    let mut monitor = PBFTMonitorState::new(1, Duration::from_secs(5));
    
    // Simulate a successful commit event
    monitor.on_event(MonitorEvent::Commit { 
        seq: 1, 
        digest: 42, 
        cert_ok: true 
    });
    
    // Simulate a stable checkpoint
    monitor.on_event(MonitorEvent::Checkpoint { 
        seq: 1, 
        cert_ok: true 
    });

    println!("{:#?}", monitor);
    println!("Can Garbage Collect sequence 1? {}", monitor.can_gc(1));
}
