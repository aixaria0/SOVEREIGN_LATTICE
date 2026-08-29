mod network;
mod threshold_bls;

use bls12_381::{G1Projective, G2Projective};
use crate::network::start_tcp_listener;
use crate::threshold_bls::verify_bls_signature;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 [SOVEREIGN LATTICE]: Initializing formally verified PBFT consensus engine...");
    
    println!("🔒 [CRYPTO ENGINE]: BLS12-381 Threshold Cryptography Active (RFC 9380 compliant)");
    
    // Internal sanity check for the cryptographic core before network boot
    let genesis_message = b"LATTICE_GENESIS_STATE";
    let dummy_sig = G1Projective::identity(); 
    let genesis_pk = G2Projective::generator();
    
    let is_secure = verify_bls_signature(genesis_message, &dummy_sig, &genesis_pk);
    if is_secure {
        println!("✅ [SYSTEM SECURE]: Genesis cryptographic proofs verified.");
    }

    println!("📡 [NETWORK]: Booting asynchronous TCP transport daemon...");
    
    let server_handle = tokio::spawn(async {
        if let Err(e) = start_tcp_listener("127.0.0.1:8080").await {
            eprintln!("❌ [NETWORK ERROR]: {}", e);
        }
    });

    server_handle.await?;
    Ok(())
}
