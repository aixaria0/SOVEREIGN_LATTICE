use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective};
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};

#[test]
fn test_full_consensus_lifecycle() {
    let n = 4;
    let mut public_keys = HashMap::new();
    for i in 0..n as u32 {
        public_keys.insert(i, G2Projective::generator());
    }

    // 1. Verify cluster initialization under N = 3f + 1
    let mut state = PbftState::new(n, public_keys.clone()).expect("Failed to initialize cluster");
    assert_eq!(state.total_nodes, 4);
    assert_eq!(state.f, 1);
    assert_eq!(state.quorum_size, 3);
    assert_eq!(state.current_view, 0);

    // 2. Verify wire format serialization roundtrip (exactly 101 bytes)
    let msg = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: [0x42u8; 32],
        sender_id: 0,
        signature: G1Projective::generator(),
    };

    let wire_bytes = msg.to_bytes();
    assert_eq!(wire_bytes.len(), 101);

    let decoded = PbftMessage::from_bytes(&wire_bytes).expect("Failed to deserialize PbftMessage");
    assert_eq!(decoded.phase, Phase::PrePrepare);
    assert_eq!(decoded.view, 0);
    assert_eq!(decoded.seq, 1);
    assert_eq!(decoded.digest, [0x42u8; 32]);
    assert_eq!(decoded.sender_id, 0);

    // 3. Verify adversarial input: unregistered sender must be rejected immediately
    let unreg_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: [0x42u8; 32],
        sender_id: 999,
        signature: G1Projective::generator(),
    };
    let res = state.handle_message(&unreg_msg);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), "AUTH_FAILED: Sender ID is not part of the active node registry!");
}
