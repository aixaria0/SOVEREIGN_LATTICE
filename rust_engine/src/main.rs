use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use bls12_381::G2Projective;

use sovereign_lattice::network::{start_tcp_listener, NetworkNode};
use sovereign_lattice::pbft::PbftState;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let node_id: u32 = env::var("NODE_ID")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("Invalid NODE_ID");

    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("Invalid BIND_ADDR");

    // Standard local 4-node topology map
    let mut peers: HashMap<u32, SocketAddr> = HashMap::new();
    peers.insert(0, "127.0.0.1:8080".parse().unwrap());
    peers.insert(1, "127.0.0.1:8081".parse().unwrap());
    peers.insert(2, "127.0.0.1:8082".parse().unwrap());
    peers.insert(3, "127.0.0.1:8083".parse().unwrap());

    // Initialize dummy cryptographic keys for the 4 nodes
    let mut public_keys = HashMap::new();
    for i in 0..4 {
        public_keys.insert(i, G2Projective::generator());
    }

    // Initialize PBFT State Machine
    let state = PbftState::new(4, public_keys).expect("Failed to initialize PBFT cluster");
    let state_clone = Arc::new(Mutex::new(state));

    let _network = Arc::new(NetworkNode::new(node_id, bind_addr, peers));

    println!("🟢 Starting SOVEREIGN_LATTICE Node {}", node_id);
    
    // Synced perfectly to your green network.rs (2 arguments)
    start_tcp_listener(bind_addr, state_clone).await?;

    Ok(())
}
