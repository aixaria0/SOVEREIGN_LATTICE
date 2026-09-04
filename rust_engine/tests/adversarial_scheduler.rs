use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};

fn hash_to_curve(msg: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, b"SOVEREIGN_LATTICE_BLS", b"BLS_SIG_G1")
}

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

    let mut canonical_msg = Vec::new();
    canonical_msg.push(Phase::PrePrepare as u8);
    canonical_msg.extend_from_slice(&view.to_be_bytes());
    canonical_msg.extend_from_slice(&seq.to_be_bytes());
    canonical_msg.extend_from_slice(&digest);

    let sig = hash_to_curve(&canonical_msg) * secret_keys[&leader_id];

    let pre_prepare = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: sig,
    };

    let simulation_actions = vec![
        (0, NetworkAction::Deliver),
        (1, NetworkAction::Deliver),
        (2, NetworkAction::Drop),
        (3, NetworkAction::Duplicate),
    ];

    for (node_id, action) in simulation_actions {
        let node = nodes.get_mut(&node_id).unwrap();
        match action {
            NetworkAction::Deliver => {
                let _ = node.handle_message(&pre_prepare);
            }
            NetworkAction::Drop => {}
            NetworkAction::Duplicate => {
                let _ = node.handle_message(&pre_prepare);
                let _ = node.handle_message(&pre_prepare);
            }
        }
    }

    for (id, node) in &nodes {
        if *id != 2 {
            assert!(node.highest_seq <= 1);
        }
    }
}
