use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use crate::pbft::{PbftMessage, PbftState, Phase};

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let mut rng = OsRng;
    let mut public_keys = HashMap::new();

    for id in 0..n as u32 {
        let sk = Scalar::random(&mut rng);
        let pk = G2Projective::generator() * sk;
        public_keys.insert(id, pk);
    }

    let state_res = PbftState::new(n, public_keys);
    assert!(state_res.is_ok(), "PBFT cluster initialization failed");
    
    let mut state = state_res.unwrap();
    assert_eq!(state.total_nodes, 4);
    assert_eq!(state.f, 1);
}
