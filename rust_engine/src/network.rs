    use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[allow(dead_code)]
pub struct NetworkNode {
    pub node_id: u32,
    pub address: SocketAddr,
    pub peers: HashMap<u32, SocketAddr>,
}

impl NetworkNode {
    pub fn new(node_id: u32, address: SocketAddr, peers: HashMap<u32, SocketAddr>) -> Self {
        Self {
            node_id,
            address,
            peers,
        }
    }

    /// Initialize the listener server to handle incoming P2P messages asynchronously
    pub async fn start_listener(
        &self, 
        message_handler: Arc<dyn Fn(u32, Vec<u8>) + Send + Sync + 'static>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.address).await?;
        println!("🎧 [NODE {}]: Listening for P2P messages on {}", self.node_id, self.address);

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let handler = Arc::clone(&message_handler);

            tokio::spawn(async move {
                let mut len_buf = [0u8; 4];
                if socket.read_exact(&mut len_buf).await.is_ok() {
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buffer = vec![0u8; len];
                    if socket.read_exact(&mut buffer).await.is_ok() {
                        println!("📥 [NETWORK]: Received packet of {} bytes from {}", len, peer_addr);
                        handler(0, buffer);
                    }
                }
            });
        }
    }

    /// Send a payload to a specific target node in the network registry
    pub async fn send_message(&self, target_id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let peer_addr = self.peers.get(&target_id)
            .ok_or("NETWORK_ERROR: Target node address not found in peer registry!")?;

        let mut stream = TcpStream::connect(peer_addr).await?;
        
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(payload).await?;

        println!("📤 [NODE {}]: Sent {} bytes to Node {}", self.node_id, payload.len(), target_id);
        Ok(())
    }
}
