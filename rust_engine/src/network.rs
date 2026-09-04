use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use crate::pbft::{PbftMessage, PbftState, Phase, ViewChangePayload};

pub const MAX_FRAME_SIZE: usize = 109;
pub const MAX_CONCURRENT_CONNECTIONS: usize = 100;

pub struct NetworkNode {
    pub node_id: u32,
    pub bind_addr: SocketAddr,
    pub peers: HashMap<u32, SocketAddr>,
}

impl NetworkNode {
    pub fn new(node_id: u32, bind_addr: SocketAddr, peers: HashMap<u32, SocketAddr>) -> Self {
        Self {
            node_id,
            bind_addr,
            peers,
        }
    }
}

pub async fn start_tcp_listener(
    bind_addr: SocketAddr, 
    state: Arc<Mutex<PbftState>>, 
    allowed_peers: HashMap<u32, SocketAddr>
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    println!("🚀 TCP Listener started on {}", bind_addr);
    
    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    
    let allowed_ips: Arc<HashSet<std::net::IpAddr>> = Arc::new(
        allowed_peers.values().map(|addr| addr.ip()).collect()
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if !allowed_ips.contains(&addr.ip()) {
                    eprintln!("🛡️ SECURITY GUARD: Dropped unauthorized connection from {}", addr.ip());
                    continue;
                }

                let permit = match connection_limiter.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("🛡️ SECURITY GUARD: Max connections reached. Dropping {}", addr);
                        continue;
                    }
                };

                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(stream, state_clone).await;
                    drop(permit);
                });
            }
            Err(e) => eprintln!("Network accept error: {}", e),
        }
    }
}

pub async fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<PbftState>>) {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; 
        }

        let len = u32::from_be_bytes(len_buf) as usize;

        if len < 101 || len > MAX_FRAME_SIZE {
            eprintln!("🛡️ SECURITY GUARD: Rejecting malicious frame size: {} bytes.", len);
            break; 
        }

        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            break;
        }

        let mut locked_state = state.lock().await;
        dispatch_network_payload(&mut locked_state, &payload);
    }
}

pub fn dispatch_network_payload(state: &mut PbftState, payload: &[u8]) {
    if payload.is_empty() { return; }

    if payload.len() == 109 && payload[0] == Phase::ViewChange as u8 {
        match ViewChangePayload::from_bytes(payload) {
            Ok(vc) => {
                if let Err(e) = state.handle_view_change_payload(&vc) {
                    eprintln!("⚠️ ViewChange Rejected: {}", e);
                }
            }
            Err(e) => eprintln!("❌ ViewChange Parse Error: {}", e),
        }
    } else if payload.len() == 101 {
        match PbftMessage::from_bytes(payload) {
            Ok(msg) => {
                if let Err(e) = state.handle_message(&msg) {
                    eprintln!("⚠️ PBFT Message Rejected: {}", e);
                }
            }
            Err(e) => eprintln!("❌ PBFT Parse Error: {}", e),
        }
    } else {
        eprintln!("🛡️ SECURITY GUARD: Unrecognized frame format.");
    }
}
