use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};

fn hash_to_curve(msg: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, b"SOVEREIGN_LATTICE_BLS", b"BLS_SIG_G1")
}

#[test]
fn test_full_consensus_lifecycle() {
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
        let state = PbftState::new(n, public_keys.clone()).expect("Failed to init node state");
        nodes.insert(i, state);
    }

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x77u8; 32];
    let leader_id = 0u32;

    let mut pp_bytes = Vec::new();
    pp_bytes.push(Phase::PrePrepare as u8);
    pp_bytes.extend_from_slice(&view.to_be_bytes());
    pp_bytes.extend_from_slice(&seq.to_be_bytes());
    pp_bytes.extend_from_slice(&digest);

    let pp_sig = hash_to_curve(&pp_bytes) * secret_keys[&leader_id];
    let pre_prepare_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id: leader_id,
        signature: pp_sig,
    };

    for node in nodes.values_mut() {
        assert!(node.handle_message(&pre_prepare_msg).is_ok(), "Node failed to accept PrePrepare");
    }

    let mut prep_bytes = Vec::new();
    prep_bytes.push(Phase::Prepare as u8);
    prep_bytes.extend_from_slice(&view.to_be_bytes());
    prep_bytes.extend_from_slice(&seq.to_be_bytes());
    prep_bytes.extend_from_slice(&digest);

    for i in 0..n as u32 {
        let sig = hash_to_curve(&prep_bytes) * secret_keys[&i];
        let prepare_msg = PbftMessage {
            phase: Phase::Prepare,
            view,
            seq,
            digest,
            sender_id: i,
            signature: sig,
        };

        let _ = nodes.get_mut(&1).unwrap().handle_message(&prepare_msg);
    }

    let target_node = nodes.get(&1).unwrap();
    assert!(
        target_node.prepared_certificates.contains_key(&(view, seq)),
        "Node 1 failed to form PreparedCertificate after receiving quorum votes!"
    );
}
