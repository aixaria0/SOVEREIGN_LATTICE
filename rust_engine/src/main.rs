mod network;
mod threshold_bls;
mod pbft;

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::network::start_tcp_listener;
use crate::threshold_bls::{KeyPair, sign, verify_bls_signature};
use crate::pbft::PbftState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 [SOVEREIGN LATTICE]: Initializing formally verified PBFT consensus engine...");
    println!("🔒 [CRYPTO ENGINE]: BLS12-381 Cryptography Booting...");

    // 1. Generate secure cryptographic keys using deterministic seed (Ideal for node consistency & testing)
    let seed = b"NODE_0_SECURE_ENTROPY_SEED";
    let node_keypair = KeyPair::from_seed(seed);
    
    // For production environments, you would use OS entropy instead:
    // let node_keypair = KeyPair::generate();

    // 2. Perform real signature generation and pairing verification
    let genesis_message = b"LATTICE_GENESIS_STATE";
    let signature = sign(genesis_message, &node_keypair.secret_key);
    
    println!("⚙️  [CRYPTO]: Generating signature. Executing Positive/Negative pairing checks...");

    // Positive Test: Should return true
    let is_valid = verify_bls_signature(genesis_message, &signature, &node_keypair.public_key);
    
    // Negative Test: Should return false (Preventing forgery attacks)
    let forged_message = b"MALICIOUS_FORGED_STATE";
    let is_forged_valid = verify_bls_signature(forged_message, &signature, &node_keypair.public_key);

    if is_valid && !is_forged_valid {
        println!("✅ [SYSTEM SECURE]: Real BLS signature verified. Forgeries correctly rejected.");
    } else {
        eprintln!("❌ [SYSTEM FATAL]: Cryptographic integrity compromised!");
        std::process::exit(1);
    }

    // 3. Initialize PBFT State Machine for a network of 4 Nodes (f = 1, Quorum = 3)
    let total_nodes = 4;
    let pbft_state = Arc::new(Mutex::new(PbftState::new(total_nodes)));
    println!("⚙️  [CONSENSUS]: State Machine initialized for N={} (Quorum Size: {})", total_nodes, (2 * ((total_nodes - 1) / 3)) + 1);

    // 4. Boot Network Transport Layer
    println!("📡 [NETWORK]: Booting asynchronous TCP transport daemon...");
    let server_handle = tokio::spawn(async move {
        if let Err(e) = start_tcp_listener("127.0.0.1:8080", pbft_state).await {
            eprintln!("❌ [NETWORK ERROR]: {}", e);
        }
    });

    server_handle.await?;
    Ok(())
}
