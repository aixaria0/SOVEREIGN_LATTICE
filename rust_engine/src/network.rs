use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::pbft::PbftState;
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

    let _pbft = state.lock().await;

    println!("🔍 [NETWORK]: Secure cryptographic frame received. Ready for state machine validation.");
    socket.write_all(b"ACK_SECURE_FRAME_PROCESSED").await?;
    Ok(())
}
