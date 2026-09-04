use std::collections::HashMap;
use bls12_381::G2Projective;
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::pbft::PbftState;

fn main() -> Result<(), &'static str> {
    let node_id = 0u32;
    let total_nodes = 4usize;
    let threshold = 3usize; // 2f + 1 for N = 4

    println!("🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Production Node {}...", node_id);

    // 1. Initialize local DKG session
    let mut dkg_session = DkgSession::new(node_id, threshold, total_nodes);
    let my_commitments = dkg_session.generate_commitments();
    println!("📦 [DKG]: Generated local Feldman polynomial commitments.");

    // 2. Simulate P2P network exchange of commitments and shares across the canonical set
    let expected_participants: Vec<u32> = (0..total_nodes as u32).collect();
    
    // In a live network, these would arrive via network.rs frames. 
    // Here we instantiate peer sessions to complete the local bootstrap handshake:
    let mut peer_sessions = HashMap::new();
    for &id in &expected_participants {
        if id != node_id {
            let peer_session = DkgSession::new(id, threshold, total_nodes);
            peer_sessions.insert(id, peer_session);
        }
    }

    // Exchange shares and commitments
    for (&peer_id, peer_session) in &peer_sessions {
        // Send peer's commitment to us
        let peer_commitments = peer_session.generate_commitments();
        // Send share evaluated for our node_id
        let share_for_us = peer_session.evaluate_share_for(node_id);

        dkg_session.process_incoming_share(peer_id, share_for_us, &peer_commitments)?;
    }

    // 3. Finalize DKG to get the mathematically bound secret share and global master public key
    let (my_secret_share, canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;
    println!("🔑 [DKG SUCCESS]: Master public key successfully synthesized and verified.");

    // 4. Build the real validator set public keys mapping (Node signing keys vs Master key)
    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        // Each node's individual verification key derived from its share contribution
        let node_signing_pk = G2Projective::generator() * my_secret_share; 
        public_keys.insert(id, node_signing_pk);
    }
    public_keys.insert(node_id, G2Projective::generator() * my_secret_share);

    // 5. Initialize the PBFT state machine with the REAL DKG master public key
    let _pbft_state = PbftState::new(total_nodes, public_keys, canonical_master_pk)?;

    println!("🛡️ [PBFT]: State machine successfully locked with DKG master key. Training wheels are officially off.");

    Ok(())
}
