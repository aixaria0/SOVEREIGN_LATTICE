use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration, Instant};
use std::sync::Arc;

#[derive(Debug)]
pub enum ProtocolEvent {
    Message { from: u32, payload: Vec<u8> },
    Complaint { against: u32, data: Vec<u8> },
    Timeout,
    Shutdown,
}

pub struct ParticipantState {
    pub id: u32,
    pub last_progress: Instant,
    pub timeout: Duration,
    // ... other protocol state (view, shares, nonces, etc.)
}

impl ParticipantState {
    pub fn new(id: u32, timeout: Duration) -> Self {
        Self {
            id,
            last_progress: Instant::now(),
            timeout,
        }
    }

    pub fn on_message(&mut self, _from: u32, _payload: &[u8]) {
        // parse & handle message
        self.last_progress = Instant::now();
    }

    pub fn on_timeout(&mut self) {
        // trigger view-change, complaint, or abort
        println!("Participant {} timed out – initiating recovery", self.id);
    }
}

pub async fn participant_loop(
    id: u32,
    mut rx: mpsc::Receiver<ProtocolEvent>,
    timeout: Duration,
) {
    let state = Arc::new(Mutex::new(ParticipantState::new(id, timeout)));

    loop {
        let state_clone = Arc::clone(&state);
        let timeout_dur = {
            let s = state_clone.lock().await;
            s.timeout
        };

        tokio::select! {
            biased;

            Some(event) = rx.recv() => {
                let mut s = state.lock().await;
                match event {
                    ProtocolEvent::Message { from, payload } => {
                        s.on_message(from, &payload);
                    }
                    ProtocolEvent::Complaint { against: _, data: _ } => {
                        // handle complaint
                        s.last_progress = Instant::now();
                    }
                    ProtocolEvent::Timeout => {
                        s.on_timeout();
                    }
                    ProtocolEvent::Shutdown => break,
                }
            }

            _ = sleep(timeout_dur) => {
                let mut s = state.lock().await;
                if s.last_progress.elapsed() >= s.timeout {
                    s.on_timeout();
                    // optionally send a Timeout event back into the channel
                }
            }
        }
    }
}

// Example usage in main
#[tokio::main]
async fn main() {
    let (_tx, rx) = mpsc::channel(32);
    let timeout = Duration::from_secs(5);

    let handle = tokio::spawn(participant_loop(1, rx, timeout));

    // simulate messages...
    // tx.send(ProtocolEvent::Message { ... }).await.unwrap();

    handle.await.unwrap();
}
