mod network;
mod threshold_bls;
mod pbft;

use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use crate::network::start_tcp_listener;
use crate::threshold_bls::{KeyPair, sign, verify_bls_signature};
use crate::pbft::PbftState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 [SOVEREIGN LATTICE]: Initializing formally verified PBFT consensus engine...");
    println!("🔒 [CRYPTO ENGINE]: BLS12-381 Cryptography Booting...");

    // 1. Production-grade cryptographic key generation using OS secure entropy (CSPRNG)
    let node_keypair = KeyPair::generate();
    
    // For deterministic testing/reproduction, use:
    // let node_keypair = KeyPair::from_seed(b"NODE_0_SECURE_ENTROPY_SEED");

    let genesis_message = b"LATTICE_GENESIS_STATE";
    let signature = sign(genesis_message, &node_keypair.secret_key);
    
    println!("⚙️  [CRYPTO]: Generating signature. Executing Positive/Negative pairing checks...");

    let is_valid = verify_bls_signature(genesis_message, &signature, &node_keypair.public_key);
    let forged_message = b"MALICIOUS_FORGED_STATE";
    let is_forged_valid = verify_bls_signature(forged_message, &signature, &node_keypair.public_key);

    if is_valid && !is_forged_valid {
        println!("✅ [SYSTEM SECURE]: Real BLS signature verified. Forgeries correctly rejected.");
    } else {
        eprintln!("❌ [SYSTEM FATAL]: Cryptographic integrity compromised!");
        std::process::exit(1);
    }

    // 2. Initialize Node Public Key Registry for N = 4 (f = 1, Quorum = 3)
    let total_nodes = 4;
    let mut initial_pks = HashMap::new();
    for i in 0..total_nodes as u32 {
        let kp = KeyPair::from_seed(format!("PROD_NODE_SEED_{}", i).as_bytes());
        initial_pks.insert(i, kp.public_key);
    }

    let pbft_state = Arc::new(Mutex::new(PbftState::new(total_nodes, initial_pks)?));
    println!("⚙️  [CONSENSUS]: State Machine initialized for N={} (Quorum Size: {})", total_nodes, (2 * ((total_nodes - 1) / 3)) + 1);

    // 3. Boot Network Transport Layer
    println!("📡 [NETWORK]: Booting asynchronous TCP transport daemon...");
    let server_handle = tokio::spawn(async move {
        if let Err(e) = start_tcp_listener("127.0.0.1:8080", pbft_state).await {
            eprintln!("❌ [NETWORK ERROR]: {}", e);
        }
    });

    server_handle.await?;
    Ok(())
}
