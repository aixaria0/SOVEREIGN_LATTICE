use std::collections::HashMap;
use bls12_381::G2Projective;
use sovereign_lattice::pbft::{PbftMessage, PbftState};

#[test]
fn test_adversarial_event_scheduler() {
    let n = 4;
    let mut public_keys = HashMap::new();
    for i in 0..n as u32 {
        public_keys.insert(i, G2Projective::generator());
    }

    // Inject dummy master_pk for the test environment
    let master_pk = G2Projective::generator();

    // Invariant: Topology must strictly satisfy N = 3f + 1
    assert!(PbftState::new(3, public_keys.clone(), master_pk).is_err());
    assert!(PbftState::new(5, public_keys.clone(), master_pk).is_err());

    let state = PbftState::new(n, public_keys, master_pk).expect("Cluster failed to initialize");

    // Adversarial: Truncated frame must be rejected
    let malformed_bytes = vec![0u8; 50];
    assert!(PbftMessage::from_bytes(&malformed_bytes).is_err());

    // Adversarial: Undefined phase code must be rejected
    let mut invalid_phase_bytes = vec![0u8; 101];
    invalid_phase_bytes[0] = 99;
    assert!(PbftMessage::from_bytes(&invalid_phase_bytes).is_err());

    // Invariant: Quorum safety bounds
    assert_eq!(state.quorum_size, 2 * state.f + 1);
    assert!(state.quorum_size > state.total_nodes / 2);
}
