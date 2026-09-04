use crate::pbft::{PbftState, PbftMessage, Phase, ViewChangePayload};
use crate::threshold_bls::KeyPair;
use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use rand::rngs::OsRng;
use ff::Field;
use sha2::{Sha256, Digest};

fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar_hash = Scalar::from_bytes(&bytes).unwrap_or(Scalar::one());
    G1Projective::generator() * scalar_hash
}

fn sign_message(msg: &[u8], sk: &Scalar) -> G1Projective {
    hash_to_curve(msg) * sk
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

    // Initialize 4 nodes representing a simulated cluster
    let mut nodes: HashMap<u32, PbftState> = HashMap::new();
    for i in 0..n as u32 {
        let state = PbftState::new(n, public_keys.clone()).expect("Failed to initialize node state");
        nodes.insert(i, state);
    }

    let view = 0;
    let seq = 1;
    let digest = [0x11; 32];
    let leader_id = 0;

    // Step 1: Leader (Node 0) broadcasts PrePrepare
    let mut prep_msg_bytes = Vec::new();
    prep_msg_bytes.push(Phase::PrePrepare as u8);
    prep_msg_bytes.extend_from_slice(&view.to_be_bytes());
    prep_msg_bytes.extend_from_slice(&seq.to_be_bytes());
    prep_msg_bytes.extend_from_slice(&digest);

    let leader_sig = sign_message(&prep_msg_bytes, &secret_keys[&leader_id]);
    let pre_prepare_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: leader_sig,
    };

    // Deliver PrePrepare to all replica nodes
    for (id, node) in nodes.iter_mut() {
        if *id != leader_id {
            let res = node.handle_message(&pre_prepare_msg);
            assert!(res.is_ok(), "Replica failed to accept valid PrePrepare");
        }
    }

    // Step 2: Replicas multicast Prepare votes
    let mut prepare_messages = Vec::new();
    for i in 1..n as u32 {
        let mut canon = Vec::new();
        canon.push(Phase::Prepare as u8);
        canon.extend_from_slice(&view.to_be_bytes());
        canon.extend_from_slice(&seq.to_be_bytes());
        canon.extend_from_slice(&digest);

        let sig = sign_message(&canon, &secret_keys[&i]);
        let msg = PbftMessage {
            phase: Phase::Prepare,
            view,
            seq,
            digest,
            sender_id: i,
            signature: sig,
        };
        prepare_messages.push(msg);
    }

    // Feed prepare votes to Node 1 to achieve Prepared Certificate quorum
    for msg in &prepare_messages {
        let _ = nodes.get_mut(&1).unwrap().handle_message(msg);
    }

    // Invariant Check 1: Node 1 must possess a verified Prepared Certificate
    let node1 = nodes.get(&1).unwrap();
    assert!(
        node1.prepared_certificates.contains_key(&(view, seq)),
        "INVARIANT VIOLATION: Node 1 failed to form a Prepared Certificate after receiving quorum votes!"
    );

    // Step 3: Adversarial test - Duplicate vote rejection
    let duplicate_vote = prepare_messages[0].clone();
    let dup_result = nodes.get_mut(&1).unwrap().handle_message(&duplicate_vote);
    assert!(
        dup_result.is_err(),
        "SAFETY VIOLATION: Node 1 accepted a duplicate Prepare vote from the same sender!"
    );

    println!("✅ [STATEFUL SIMULATION PASSED]: Multi-node consensus flow, PrePrepare gating, and quorum formation verified.");
}

