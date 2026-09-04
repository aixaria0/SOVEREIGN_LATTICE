use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::pbft::{PbftMessage, PbftState, Phase};

fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar_hash = Scalar::from_bytes(&bytes).unwrap_or(Scalar::one());
    G1Projective::generator() * scalar_hash
}

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();
    for i in 0..n as u32 {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        secret_keys.insert(i, sk);
        public_keys.insert(i, pk);
    }

    let mut state = PbftState::new(n, public_keys.clone()).expect("Failed to init state");

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x55u8; 32];
    let leader_id = 0u32; // 0 % 4 = 0, so node 0 is the leader for view 0

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

    // 1. Verify that a valid PrePrepare passes through state handling and WAL logging
    let res = state.handle_message(&pre_prepare);
    assert!(res.is_ok(), "Valid PrePrepare failed: {:?}", res);

    // 2. Verify that sending the exact same message again triggers duplicate protection
    let dup_res = state.handle_message(&pre_prepare);
    assert!(dup_res.is_err(), "Security flaw: Duplicate PrePrepare was accepted!");
}
