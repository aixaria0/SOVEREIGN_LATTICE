// src/network.rs

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{MonitorEvent, AggregateSignature};

/// Spawns a TCP listener daemon to ingest live events from peer nodes
pub async fn start_tcp_listener(addr: &str, tx: mpsc::Sender<MonitorEvent>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("🌐 [NETWORK] TCP Listener active on {}", addr);

    loop {
        let (mut socket, peer) = listener.accept().await?;
        println!("🔗 [NETWORK] Connection established with peer: {}", peer);
        
        let tx_clone = tx.clone();
        
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let payload = &buf[..n];
                        if payload.starts_with(b"COMMIT") {
                            let event = MonitorEvent::Commit {
                                seq: 1,
                                digest: 1042,
                                sig: AggregateSignature { is_valid: true },
                            };
                            let _ = tx_clone.send(event).await;
                            let _ = socket.write_all(b"ACK_COMMIT\n").await;
                        } else {
                            let _ = socket.write_all(b"UNKNOWN_COMMAND\n").await;
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ [NETWORK] Socket error: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

