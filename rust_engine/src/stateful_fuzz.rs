use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Digest as ShaDigest, Sha256};
use crate::pbft::{PbftMessage, PbftState, Phase};

fn generate_test_keys(n: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>) {
    let mut rng = OsRng;
    let mut privkeys = HashMap::new();
    let mut pubkeys = HashMap::new();

    for id in 0..n as u32 {
        let sk = Scalar::random(&mut rng);
        let pk = G2Projective::generator() * sk;
        pubkeys.insert(id, pk);
        privkeys.insert(id, sk);
    }

    (privkeys, pubkeys)
}

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let (privkeys, public_keys) = generate_test_keys(n);

    let mut nodes: HashMap<u32, PbftState> = HashMap::new();
    for i in 0..n as u32 {
        let state = PbftState::new(n, public_keys.clone()).expect("Failed to initialize node state");
        nodes.insert(i, state);
    }

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x11; 32];
    let leader_id = 0u32;

    let mut prep_msg_bytes = Vec::new();
    prep_msg_bytes.push(Phase::PrePrepare as u8);
    prep_msg_bytes.extend_from_slice(&view.to_be_bytes());
    prep_msg_bytes.extend_from_slice(&seq.to_be_bytes());
    prep_msg_bytes.extend_from_slice(&digest);

    let mut hasher = Sha256::new();
    hasher.update(&prep_msg_bytes);
    let hash_bytes: [u8; 32] = hasher.finalize().into();

    let s = Scalar::from_bytes(&hash_bytes).unwrap_or(Scalar::one());
    let h = G1Projective::generator() * s;
    let leader_sig = h * privkeys[&leader_id];

    let pre_prepare_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: leader_sig,
    };

    for node_id in 0..n as u32 {
        let node = nodes.get_mut(&node_id).unwrap();
        let res = node.handle_message(&pre_prepare_msg);
        assert!(res.is_ok(), "Node {} rejected valid PrePrepare", node_id);
    }
}
