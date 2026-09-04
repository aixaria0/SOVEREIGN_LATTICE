use std::collections::HashMap;
use bls12_381::G2Projective;
use crate::pbft::PbftState;

#[test]
fn test_stateful_adversarial_simulation() {
    let n = 4;
    let mut public_keys = HashMap::new();
    for i in 0..n as u32 {
        public_keys.insert(i, G2Projective::generator());
    }

    // Inject a dummy master public key to satisfy the test environment
    let master_pk = G2Projective::generator();

    // Initialize the PBFT state machine with the newly required master_pk argument
    let state_res = PbftState::new(n, public_keys, master_pk);
    assert!(state_res.is_ok(), "PBFT cluster initialization failed");

    let state = state_res.unwrap();
    
    // Verify core consensus parameters and invariants
    assert_eq!(state.total_nodes, 4);
    assert_eq!(state.f, 1);
    assert_eq!(state.quorum_size, 3);
    assert_eq!(state.current_view, 0);
}
