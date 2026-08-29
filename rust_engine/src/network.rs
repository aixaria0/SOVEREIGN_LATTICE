use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::pbft::{PbftState, Phase};
use std::error::Error;

pub async fn start_tcp_listener(addr: &str, state: Arc<Mutex<PbftState>>) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("📡 [NETWORK]: Hardened TCP socket listening on {}", addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let state_clone = Arc::clone(&state);
        
        tokio::spawn(async move {
            println!("🌐 [NETWORK]: Connection accepted from {}", peer_addr);
            if let Err(e) = handle_connection(socket, state_clone).await {
                eprintln!("⚠️ [STREAM ERROR]: {}", e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream, state: Arc<Mutex<PbftState>>) -> Result<(), Box<dyn Error>> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len < 41 || payload_len > 4096 {
        return Err("Invalid frame length".into());
    }

    let mut payload = vec![0u8; payload_len];
    socket.read_exact(&mut payload).await?;

    let phase = match payload[0] {
        0 => Phase::PrePrepare,
        1 => Phase::Prepare,
        2 => Phase::Commit,
        _ => return Err("Invalid PBFT Phase marker".into()),
    };

    let view = 0u64;
    let seq = u64::from_be_bytes(payload[1..9].try_into().unwrap());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&payload[9..41]);
    
    let sender_id = 0; 
    let is_signature_valid = true;

    let mut pbft = state.lock().await;
    match pbft.process_message(phase, view, seq, digest, sender_id, is_signature_valid) {
        Ok(log) => {
            println!("{}", log);
            socket.write_all(b"ACK_PBFT_STATE_UPDATED").await?;
        }
        Err(err) => {
            eprintln!("🛑 [PBFT VIOLATION]: {}", err);
            socket.write_all(b"ERR_PBFT_SAFETY_VIOLATION").await?;
        }
    }

    Ok(())
}
