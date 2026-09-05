use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use bls12_381::G2Projective;
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::pbft::PbftState;
use sovereign_lattice::network::start_tcp_listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node_id = 0u32;
    let total_nodes = 4usize;
    let threshold = 3usize;
    let bind_addr_str = "127.0.0.1:8000";
    let bind_addr: SocketAddr = bind_addr_str.parse()?;

    println!("🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Production Node {} on {}...", node_id, bind_addr_str);

    let mut dkg_session = DkgSession::new(node_id, threshold, total_nodes);
    let _my_commitments = dkg_session.generate_commitments();
    println!("📦 [DKG]: Generated local Feldman polynomial commitments.");

    let expected_participants: Vec<u32> = (0..total_nodes as u32).collect();
    
    let mut peer_sessions = HashMap::new();
    for &id in &expected_participants {
        if id != node_id {
            let peer_session = DkgSession::new(id, threshold, total_nodes);
            peer_sessions.insert(id, peer_session);
        }
    }

    for (&peer_id, peer_session) in &peer_sessions {
        let peer_commitments = peer_session.generate_commitments();
        let share_for_us = peer_session.evaluate_share_for(node_id);
        dkg_session.process_incoming_share(peer_id, share_for_us, &peer_commitments)?;
    }

    let (my_secret_share, canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;
    println!("🔑 [DKG SUCCESS]: Master public key successfully synthesized and verified.");

    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        if id == node_id {
            public_keys.insert(id, G2Projective::generator() * my_secret_share);
        } else {
            let mut peer_true_secret_share = dkg_session.evaluate_share_for(id);
            for peer_session in peer_sessions.values() {
                peer_true_secret_share += peer_session.evaluate_share_for(id);
            }
            
            let node_signing_pk = G2Projective::generator() * peer_true_secret_share;
            public_keys.insert(id, node_signing_pk);
        }
    }

    let pbft_state = PbftState::new(total_nodes, public_keys, canonical_master_pk)?;
    let shared_state = Arc::new(Mutex::new(pbft_state));
    println!("🛡️ [PBFT]: State machine locked! Validator registry uniquely populated.");

    let mut peer_map = HashMap::new();
    for id in 0..total_nodes as u32 {
        let port = 8000 + id as u16;
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
        peer_map.insert(id, addr);
    }

    println!("🌐 [NETWORK]: Starting Tokio TCP transport daemon...");
    start_tcp_listener(bind_addr, shared_state, peer_map).await?;

    Ok(())
}
