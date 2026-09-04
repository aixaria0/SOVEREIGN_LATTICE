use std::collections::HashMap;
use bls12_381::{G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use crate::pbft::{PbftMessage, PbftState, Phase};
use crate::threshold_bls::KeyPair;

fn generate_test_keys(n: usize) -> (HashMap<u32, KeyPair>, HashMap<u32, G2Projective>) {
    let mut rng = OsRng;
    let mut keypairs = HashMap::new();
    let mut pubkeys = HashMap::new();

    for id in 0..n as u32 {
        let sk = Scalar::random(&mut rng);
        let kp = KeyPair {
            id,
            secret_key: sk,
            public_key: G2Projective::generator() * sk,
        };
        pubkeys.insert(id, kp.public_key);
        keypairs.insert(id, kp);
    }

    (keypairs, pubkeys)
}

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let (keypairs, public_keys) = generate_test_keys(n);

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

    let leader_kp = &keypairs[&leader_id];
    let leader_sig = leader_kp.sign(&prep_msg_bytes);

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
