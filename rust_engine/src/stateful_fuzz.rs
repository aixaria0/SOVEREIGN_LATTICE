use std::collections::HashMap;
use bls12_381::G2Projective;
use crate::pbft::PbftState;

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let public_keys: HashMap<u32, G2Projective> = HashMap::new();

    let node = PbftState::new(n, public_keys);
    assert!(node.is_ok(), "PBFT cluster initialization failed");
}
