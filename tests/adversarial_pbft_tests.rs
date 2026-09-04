use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective};
use sovereign_lattice::pbft::{PbftState, PbftMessage, Phase};

#[test]
fn test_adversarial_leader_equivocation_rejection() {
    let n = 4;
    let mut public_keys = HashMap::new();
    let master_pk = G2Projective::generator();

    for id in 0..n as u32 {
        public_keys.insert(id, G2Projective::generator());
    }

    let mut pbft = PbftState::new(n, public_keys, master_pk).unwrap();

    let digest_a = [0x11u8; 32];
    let digest_b = [0x22u8; 32];

    let proposal_a = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: digest_a,
        sender_id: 0,
        signature: G1Projective::identity(),
    };

    assert!(pbft.handle_message(&proposal_a).is_ok());

    let proposal_b = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: digest_b,
        sender_id: 0,
        signature: G1Projective::identity(),
    };

    let result = pbft.handle_message(&proposal_b);
    assert!(result.is_err(), "Safety violation: Leader equivocation was incorrectly accepted by state machine!");
}

