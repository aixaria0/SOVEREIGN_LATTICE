use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct NetworkNode {
    pub node_id: u32,
    pub address: SocketAddr,
    pub peers: HashMap<u32, SocketAddr>,
    outbound_connections: Arc<Mutex<HashMap<u32, TcpStream>>>,
}

impl NetworkNode {
    pub fn new(node_id: u32, address: SocketAddr, peers: HashMap<u32, SocketAddr>) -> Self {
        Self {
            node_id,
            address,
            peers,
            outbound_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start_listener<F>(&self, on_message: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(u32, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(self.address).await?;
        let handler = Arc::new(on_message);

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };

                let handler_clone = Arc::clone(&handler);
                tokio::spawn(async move {
                    loop {
                        let mut header = [0u8; 8];
                        if socket.read_exact(&mut header).await.is_err() {
                            break;
                        }

                        let sender_id = u32::from_be_bytes(header[0..4].try_into().unwrap());
                        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;

                        let mut payload = vec![0u8; len];
                        if socket.read_exact(&mut payload).await.is_err() {
                            break;
                        }

                        handler_clone(sender_id, payload);
                    }
                });
            }
        });

        Ok(())
    }

    pub async fn send_message(&self, target_id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peer_addr = self
            .peers
            .get(&target_id)
            .copied()
            .ok_or("Target node not registered in peer list")?;

        let mut conns = self.outbound_connections.lock().await;

        if !conns.contains_key(&target_id) {
            let stream = TcpStream::connect(peer_addr).await?;
            conns.insert(target_id, stream);
        }

        let stream = conns.get_mut(&target_id).unwrap();

        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&self.node_id.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        if let Err(e) = stream.write_all(&frame).await {
            conns.remove(&target_id);
            return Err(Box::new(e));
        }

        stream.flush().await?;
        Ok(())
    }

    pub async fn broadcast(&self, payload: &[u8]) -> Vec<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        let peer_ids: Vec<u32> = self.peers.keys().copied().collect();
        let mut results = Vec::new();

        for peer_id in peer_ids {
            results.push(self.send_message(peer_id, payload).await);
        }

        results
    }
}
