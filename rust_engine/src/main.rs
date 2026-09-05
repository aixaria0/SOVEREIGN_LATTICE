use std::collections::HashMap;
use bls12_381::G2Projective;
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::pbft::PbftState;

fn main() -> Result<(), &'static str> {
    let node_id = 0u32;
    let total_nodes = 4usize;
    let threshold = 3usize;

    println!("🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Production Node {}...", node_id);

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

    // Exchange shares with Node 0
    for (&peer_id, peer_session) in &peer_sessions {
        let peer_commitments = peer_session.generate_commitments();
        let share_for_us = peer_session.evaluate_share_for(node_id);
        dkg_session.process_incoming_share(peer_id, share_for_us, &peer_commitments)?;
    }

    let (my_secret_share, _canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;
    println!("🔑 [DKG SUCCESS]: Master public key successfully synthesized and verified.");

    // Build the true, cryptographically unique public keys for each individual node
    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        if id == node_id {
            // Insert our own verified local share
            public_keys.insert(id, G2Projective::generator() * my_secret_share);
        } else {
            // Calculate the true share of other nodes using polynomial evaluation
            let mut peer_true_secret_share = dkg_session.evaluate_share_for(id);
            for peer_session in peer_sessions.values() {
                peer_true_secret_share += peer_session.evaluate_share_for(id);
            }
            
            let node_signing_pk = G2Projective::generator() * peer_true_secret_share;
            public_keys.insert(id, node_signing_pk);
        }
    }

    // Initialize state with exactly 2 arguments as defined in src/pbft.rs
    let _pbft_state = PbftState::new(total_nodes, public_keys)?;

    println!("🛡️ [PBFT]: State machine locked! Validator registry uniquely populated.");

    Ok(())
}
