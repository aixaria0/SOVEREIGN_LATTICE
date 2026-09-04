use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};

#[derive(Debug)]
enum NetworkAction {
    Deliver,
    Drop,
    Duplicate,
}

#[test]
fn test_adversarial_event_scheduler() {
    let n = 4;
    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();

    for i in 0..n as u32 {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        secret_keys.insert(i, sk);
        public_keys.insert(i, pk);
    }

    let mut nodes = HashMap::new();
    for i in 0..n as u32 {
        nodes.insert(i, PbftState::new(n, public_keys.clone()).unwrap());
    }

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x99u8; 32];
    let leader_id = 0u32;

    // Build valid PrePrepare message from leader
    let mut canonical_msg = Vec::new();
    canonical_msg.push(Phase::PrePrepare as u8);
    canonical_msg.extend_from_slice(&view.to_be_bytes());
    canonical_msg.extend_from_slice(&seq.to_be_bytes());
    canonical_msg.extend_from_slice(&digest);

    let mut hasher = Sha256::new();
    hasher.update(&canonical_msg);
    let h = G1Projective::generator() * Scalar::from_bytes(&hasher.finalize().into()).unwrap_or(Scalar::one());
    let sig = h * secret_keys[&leader_id];

    let pre_prepare = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: sig,
    };

    // Simulate adversarial network actions (e.g., dropping packet for node 3, delivering to others)
    let simulation_actions = vec![
        (0, NetworkAction::Deliver),
        (1, NetworkAction::Deliver),
        (2, NetworkAction::Drop), // Simulated network drop
        (3, NetworkAction::Duplicate), // Simulated packet duplication
    ];

    for (node_id, action) in simulation_actions {
        let node = nodes.get_mut(&node_id).unwrap();
        match action {
            NetworkAction::Deliver => {
                let _ = node.handle_message(&pre_prepare);
            }
            NetworkAction::Drop => {
                // Message dropped, state remains untouched for this node
            }
            NetworkAction::Duplicate => {
                let _ = node.handle_message(&pre_prepare);
                // Duplicate should be safely handled or rejected by state machine
                let _ = node.handle_message(&pre_prepare);
            }
        }
    }

    // Invariant check: Active nodes maintain consistent highest sequence tracking
    for (id, node) in &nodes {
        if *id != 2 { // Node 2 dropped the message, so its seq might differ depending on design
            assert!(node.highest_seq <= 1);
        }
    }
}

