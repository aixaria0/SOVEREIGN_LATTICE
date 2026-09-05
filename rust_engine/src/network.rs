use crate::pbft::{PbftMessage, PbftState, ViewChangePayload};
use crate::threshold_bls::verify_bls_signature;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const MAX_CONNECTIONS: usize = 128;
const MAX_PACKET_SIZE: usize = 4096;

pub async fn broadcast_message(
    peers: &HashMap<u32, SocketAddr>,
    self_id: u32,
    payload: &[u8],
) -> Vec<(u32, Result<(), String>)> {
    let mut results = Vec::new();

    for (&peer_id, &addr) in peers {
        if peer_id == self_id {
            continue;
        }

        let payload_vec = payload.to_vec();
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let len_bytes = (payload_vec.len() as u32).to_be_bytes();
                if let Err(e) = stream.write_all(&len_bytes).await {
                    results.push((peer_id, Err(format!("SEND_LEN_FAILED: {}", e))));
                    continue;
                }
                if let Err(e) = stream.write_all(&payload_vec).await {
                    results.push((peer_id, Err(format!("SEND_PAYLOAD_FAILED: {}", e))));
                    continue;
                }
                results.push((peer_id, Ok(())));
            }
            Err(e) => {
                results.push((peer_id, Err(format!("CONNECT_FAILED: {}", e))));
            }
        }
    }

    results
}

pub async fn start_tcp_listener(
    bind_addr: SocketAddr,
    state: Arc<Mutex<PbftState>>,
    peer_map: HashMap<u32, SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind_addr).await?;
    let connection_semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let allowed_ips: HashSet<_> = peer_map.values().map(|addr| addr.ip()).collect();

    loop {
        let (socket, peer_addr) = listener.accept().await?;

        if !allowed_ips.contains(&peer_addr.ip()) {
            eprintln!("REJECTED_UNAUTHORIZED_IP: {}", peer_addr);
            continue;
        }

        let permit = match connection_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("DROP_OVERLOAD: Semaphore capacity reached on {}", bind_addr);
                continue;
            }
        };

        let shared_state = Arc::clone(&state);

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(socket, shared_state).await {
                eprintln!("CONNECTION_PROCESSING_ERROR: {}", err);
            }
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    state: Arc<Mutex<PbftState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut len_bytes = [0u8; 4];
    socket.read_exact(&mut len_bytes).await?;
    let length = u32::from_be_bytes(len_bytes) as usize;

    if length > MAX_PACKET_SIZE || length == 0 {
        return Err("INVALID_PACKET_SIZE".into());
    }

    let mut payload = vec![0u8; length];
    socket.read_exact(&mut payload).await?;

    let public_keys = {
        let guard = state.lock().await;
        guard.public_keys.clone()
    };

    if let Ok(msg) = PbftMessage::from_bytes(&payload) {
        let pk = public_keys
            .get(&msg.sender_id)
            .ok_or("CRYPTO_AUTH_FAILED: Sender not registered")?;

        let mut canonical_msg = Vec::new();
        canonical_msg.push(msg.phase as u8);
        canonical_msg.extend_from_slice(&msg.view.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.digest);

        if !verify_bls_signature(&canonical_msg, &msg.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Invalid signature rejected before state lock".into());
        }

        let mut locked_state = state.lock().await;
        let response = locked_state.handle_message(&msg)?;
        println!("{}", response);
        return Ok(());
    }

    if let Ok(payload_vc) = ViewChangePayload::from_bytes(&payload) {
        let pk = public_keys
            .get(&payload_vc.sender_id)
            .ok_or("CRYPTO_AUTH_FAILED: Sender not registered")?;

        if !verify_bls_signature(&payload_vc.canonical_bytes(), &payload_vc.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Invalid signature rejected before state lock".into());
        }

        let mut locked_state = state.lock().await;
        locked_state.handle_view_change_payload(&payload_vc)?;
        println!(
            "📥 [VIEW_CHANGE_AUTHENTICATED]: Processed ViewChange payload from node {}",
            payload_vc.sender_id
        );
        return Ok(());
    }

    Err("UNKNOWN_PAYLOAD_TYPE".into())
}
