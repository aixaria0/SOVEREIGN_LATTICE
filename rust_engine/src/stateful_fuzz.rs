use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Digest as ShaDigest, Sha256};
use crate::pbft::{PbftMessage, PbftState, Phase};

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let mut rng = OsRng;
    let mut public_keys = HashMap::new();
    let mut privkeys = HashMap::new();

    // Generate keys for the 4-node cluster
    for id in 0..n as u32 {
        let sk = Scalar::random(&mut rng);
        let pk = G2Projective::generator() * sk;
        public_keys.insert(id, pk);
        privkeys.insert(id, sk);
    }

    let mut state = PbftState::new(n, public_keys.clone()).expect("Failed to initialize PBFT state");

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x55u8; 32];
    let leader_id = 0u32;

    // Construct canonical message payload bytes
    let mut msg_bytes = Vec::new();
    msg_bytes.push(Phase::PrePrepare as u8);
    msg_bytes.extend_from_slice(&view.to_be_bytes());
    msg_bytes.extend_from_slice(&seq.to_be_bytes());
    msg_bytes.extend_from_slice(&digest);

    // Deterministic cryptographic mapping compatible with bls12_381
    let mut hasher = Sha256::new();
    hasher.update(&msg_bytes);
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let s = Scalar::from_bytes(&hash_bytes).unwrap_or(Scalar::one());
    let h = G1Projective::generator() * s;
    let sig = h * privkeys[&leader_id];

    let pre_prepare = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: sig,
    };

    // 1. Verify valid PrePrepare is accepted by the state machine
    assert!(state.handle_message(&pre_prepare).is_ok(), "Node rejected valid PrePrepare message");
    
    // 2. Verify duplicate protection rejects re-submitted messages
    let duplicate_res = state.handle_message(&pre_prepare);
    assert!(duplicate_res.is_err(), "Security flaw: Duplicate consensus message was incorrectly accepted");
}
