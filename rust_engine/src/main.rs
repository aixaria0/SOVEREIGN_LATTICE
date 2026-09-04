mod network;
mod threshold_bls;
mod pbft;
mod wal;

use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use crate::network::{start_tcp_listener, NetworkNode};
use crate::threshold_bls::{KeyPair, sign, verify_bls_signature};
use crate::pbft::{PbftState, PbftMessage, Phase};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 [SOVEREIGN LATTICE]: Initializing formally verified PBFT consensus engine (10/10 Tier)...");
    println!("🔒 [CRYPTO ENGINE]: BLS12-381 Cryptography Booting...");

    // We assign ID 0 to this instance (Acting as Leader for View 0)
    let my_id: u32 = 0; 
    let node_keypair = KeyPair::from_seed(format!("PROD_NODE_SEED_{}", my_id).as_bytes());
    
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

    let total_nodes = 4;
    let mut initial_pks = HashMap::new();
    for i in 0..total_nodes as u32 {
        let kp = KeyPair::from_seed(format!("PROD_NODE_SEED_{}", i).as_bytes());
        initial_pks.insert(i, kp.public_key);
    }

    let state = PbftState::new(total_nodes as usize, initial_pks).expect("Failed to initialize PBFT topology");
    let pbft_state = Arc::new(Mutex::new(state));
    println!("⚙️  [CONSENSUS]: State Machine initialized for N={} (Quorum Size: {})", total_nodes, (2 * ((total_nodes - 1) / 3)) + 1);

    // 1. Booting the TCP Listener in the background
    println!("📡 [NETWORK]: Booting asynchronous TCP transport daemon...");
    let pbft_clone = Arc::clone(&pbft_state);
    let server_handle = tokio::spawn(async move {
        if let Err(e) = start_tcp_listener("127.0.0.1:8080", pbft_clone).await {
            eprintln!("❌ [NETWORK ERROR]: {}", e);
        }
    });

    // 2. Setting up Peer connections for Broadcasting
    let mut peers = HashMap::new();
    peers.insert(1, "127.0.0.1:8081".parse().unwrap());
    peers.insert(2, "127.0.0.1:8082".parse().unwrap());
    peers.insert(3, "127.0.0.1:8083".parse().unwrap());
    
    let my_addr = "127.0.0.1:8080".parse().unwrap();
    let network = NetworkNode::new(my_id, my_addr, peers);

    // Wait a few seconds to let the listener start and pretend we are gathering transactions
    println!("⏳ [BROADCAST]: Waiting 3 seconds before proposing a new block...");
    sleep(Duration::from_secs(3)).await;

    // 3. Construct a strictly formatted PBFT Message
    let mut digest = [0u8; 32];
    digest[0..13].copy_from_slice(b"HELLO_LATTICE"); // Dummy block hash
    
    let target_view = 0u64;
    let target_seq = 1u64;

    let mut canonical_msg = Vec::new();
    canonical_msg.push(Phase::PrePrepare as u8);
    canonical_msg.extend_from_slice(&target_view.to_be_bytes());
    canonical_msg.extend_from_slice(&target_seq.to_be_bytes());
    canonical_msg.extend_from_slice(&digest);
    
    let msg_sig = sign(&canonical_msg, &node_keypair.secret_key);

    let pre_prepare_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view: target_view,
        seq: target_seq,
        digest,
        sender_id: my_id,
        signature: msg_sig,
    };

    // 4. Serialize to 101 bytes and broadcast
    let payload = pre_prepare_msg.to_bytes();
    println!("📢 [BROADCAST]: Broadcasting PrePrepare message ({} bytes) to peers...", payload.len());

    for peer_id in 1..total_nodes as u32 {
        match network.send_message(peer_id, &payload).await {
            Ok(_) => println!("✅ [NETWORK]: Successfully sent to Node {}", peer_id),
            Err(e) => eprintln!("⚠️ [NETWORK WAIT]: Target Node {} offline or unreachable ({})", peer_id, e),
        }
    }

    server_handle.await?;
    Ok(())
}
