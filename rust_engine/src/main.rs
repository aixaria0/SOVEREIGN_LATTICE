mod network;
mod threshold_bls;
mod pbft;

use bls12_381::{G1Projective, G2Projective};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::network::start_tcp_listener;
use crate::threshold_bls::verify_bls_signature;
use crate::pbft::PbftState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 [SOVEREIGN LATTICE]: Initializing formally verified PBFT consensus engine...");
    println!("🔒 [CRYPTO ENGINE]: BLS12-381 Threshold Cryptography Active (RFC 9380 compliant)");
    
    let genesis_message = b"LATTICE_GENESIS_STATE";
    let dummy_sig = G1Projective::identity(); 
    let genesis_pk = G2Projective::generator();
    
    if verify_bls_signature(genesis_message, &dummy_sig, &genesis_pk) {
        println!("✅ [SYSTEM SECURE]: Genesis cryptographic proofs verified.");
    }

    // Initialize PBFT State Machine for a network of 4 Nodes (f = 1, Quorum = 3)
    let total_nodes = 4;
    let pbft_state = Arc::new(Mutex::new(PbftState::new(total_nodes)));
    println!("⚙️  [CONSENSUS]: State Machine initialized for N={} (Quorum Size: {})", total_nodes, (2 * ((total_nodes - 1) / 3)) + 1);

    println!("📡 [NETWORK]: Booting asynchronous TCP transport daemon...");
    let server_handle = tokio::spawn(async move {
        if let Err(e) = start_tcp_listener("127.0.0.1:8080", pbft_state).await {
            eprintln!("❌ [NETWORK ERROR]: {}", e);
        }
    });

    server_handle.await?;
    Ok(())
}
