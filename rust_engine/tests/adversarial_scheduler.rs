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

    // 1. Invariant: Topology must strictly adhere to N = 3f + 1
    assert!(PbftState::new(3, public_keys.clone()).is_err());
    assert!(PbftState::new(5, public_keys.clone()).is_err());

    let state = PbftState::new(n, public_keys).expect("Cluster failed to initialize");

    // 2. Adversarial payload: Truncated wire frame
    let malformed_bytes = vec![0u8; 50]; // Expected 101 bytes
    assert!(PbftMessage::from_bytes(&malformed_bytes).is_err());

    // 3. Adversarial payload: Corrupted phase discriminator byte
    let mut invalid_phase_bytes = vec![0u8; 101];
    invalid_phase_bytes[0] = 99; // Undefined consensus phase
    assert!(PbftMessage::from_bytes(&invalid_phase_bytes).is_err());

    // 4. Invariant: Strict BFT quorum safety bound
    assert_eq!(state.quorum_size, 2 * state.f + 1);
    assert!(state.quorum_size > state.total_nodes / 2);
}
