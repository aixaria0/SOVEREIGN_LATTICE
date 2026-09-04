use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use rand::rngs::OsRng;
use ff::Field;
// FIXED: Changed pbft_state to pbft
use sovereign_lattice::pbft::{PbftState, Phase, PbftMessage, ViewChangePayload};
use sovereign_lattice::threshold_bls::hash_to_scalar;

fn generate_test_keys(n: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>) {
    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();
    for i in 0..n as u32 {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        secret_keys.insert(i, sk);
        public_keys.insert(i, pk);
    }
    (secret_keys, public_keys)
}

fn sign_message(msg: &[u8], sk: &Scalar) -> G1Projective {
    // FIXED: Matched the exact argument order (domain, msg) from threshold_bls
    let scalar_hash = hash_to_scalar(b"TEST_SUITE_DOMAIN", msg);
    G1Projective::generator() * (scalar_hash * sk)
}

#[test]
fn test_new_view_certificate_rejects_unbacked_claims() {
    let n = 4;
    let (secret_keys, public_keys) = generate_test_keys(n);
    
    // FIXED: Generated a mock master public key to satisfy the new hardened PbftState::new signature
    let master_pk = G2Projective::generator() * Scalar::random(&mut OsRng);
    let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Init failed");

    // Attack Scenario: Byzantine node attempts to force View Change with an unbacked prepared_seq
    let create_forged_view_change = |sender_id: u32, sk: &Scalar| {
        let vc = ViewChangePayload {
            target_view: 1,
            prepared_view: 0,
            prepared_seq: 999, // Unbacked high sequence
            digest: [0xbb; 32],
            sender_id,
            signature: G1Projective::identity(),
        };
        let canonical = vc.canonical_bytes();
        let sig = sign_message(&canonical, sk);
        ViewChangePayload { signature: sig, ..vc }
    };

    let vc1 = create_forged_view_change(1, &secret_keys[&1]);
    let vc2 = create_forged_view_change(2, &secret_keys[&2]);
    let vc3 = create_forged_view_change(3, &secret_keys[&3]);

    let _ = state.handle_view_change_payload(&vc1);
    let _ = state.handle_view_change_payload(&vc2);
    let res = state.handle_view_change_payload(&vc3);

    assert!(res.is_err(), "Integration Test Failed: Engine accepted ViewChange without valid local QC verification!");
    assert_eq!(state.current_view, 0, "State transition occurred despite missing QC!");
}
