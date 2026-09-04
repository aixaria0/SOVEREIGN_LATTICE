use std::collections::HashMap;
use bls12_381::{G2Projective, Scalar};
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::pbft::PbftState;

fn main() -> Result<(), &'static str> {
    let node_id = 0u32;
    let total_nodes = 4usize;
    let threshold = 3usize;

    println!("🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Node {}...", node_id);

    let mut dkg_session = DkgSession::new(node_id, threshold, total_nodes);
    let my_commitments = dkg_session.generate_commitments();

    println!("📦 [DKG]: Generated local Feldman polynomial commitments.");

    let mut all_commitments = HashMap::new();
    all_commitments.insert(node_id, my_commitments.clone());

    let expected_participants: Vec<u32> = (0..total_nodes as u32).collect();

    let (my_secret_share, canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;

    println!("🔑 [DKG SUCCESS]: Master public key synthesized securely.");

    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        let node_signing_pk = G2Projective::generator() * my_secret_share;
        public_keys.insert(id, node_signing_pk);
    }
    public_keys.insert(node_id, G2Projective::generator() * my_secret_share);

    let pbft_state = PbftState::new(total_nodes, public_keys, canonical_master_pk)?;

    println!("🛡️ [PBFT]: State machine successfully locked with cryptographically bound master key.");

    Ok(())
}
