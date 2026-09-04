use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use bls12_381::G2Projective;
use sovereign_lattice::network::{start_tcp_listener, NetworkNode};
use sovereign_lattice::pbft::PbftState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let node_id = std::env::var("NODE_ID")
        .unwrap_or_else(|_| "0".to_string())
        .parse::<u32>()?;

    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let total_nodes = 4usize;
    let mut public_keys: HashMap<u32, G2Projective> = HashMap::new();
    for id in 0..total_nodes as u32 {
        public_keys.insert(id, G2Projective::generator());
    }

    let mut peers: HashMap<u32, SocketAddr> = HashMap::new();
    peers.insert(0, "127.0.0.1:8080".parse()?);
    peers.insert(1, "127.0.0.1:8081".parse()?);
    peers.insert(2, "127.0.0.1:8082".parse()?);
    peers.insert(3, "127.0.0.1:8083".parse()?);

    let state = PbftState::new(total_nodes, public_keys)
        .map_err(|e| format!("Failed to init PBFT state: {}", e))?;

    let state_arc = Arc::new(Mutex::new(state));
    let network = Arc::new(NetworkNode::new(node_id, bind_addr, peers));

    println!("Node {} starting TCP listener on {}", node_id, bind_addr);

    let state_clone = Arc::clone(&state_arc);
    start_tcp_listener(bind_addr, state_clone).await?;

    println!("Consensus engine online for node {}", node_id);

    tokio::signal::ctrl_c().await?;
    println!("Node {} shutting down cleanly.", node_id);

    Ok(())
}
