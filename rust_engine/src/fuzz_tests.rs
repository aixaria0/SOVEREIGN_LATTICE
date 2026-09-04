use proptest::prelude::*;
use crate::pbft::{PbftState, PbftMessage, Phase};
use crate::threshold_bls::KeyPair;
use std::collections::HashMap;

proptest! {
    #[test]
    fn fuzz_wire_parser(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = PbftMessage::from_bytes(&bytes);
    }

    #[test]
    fn fuzz_state_machine_resilience(
        phase_byte in 0u8..10u8,
        view in any::<u64>(),
        seq in any::<u64>(),
        digest in proptest::array::uniform32(any::<u8>()),
        sender_id in 0u32..10u32
    ) {
        let mut initial_pks = HashMap::new();
        for i in 0..4u32 {
            let kp = KeyPair::from_seed(format!("FUZZ_NODE_SEED_{}", i).as_bytes());
            initial_pks.insert(i, kp.public_key);
        }

        if let Ok(mut state) = PbftState::new(4, initial_pks) {
            let phase = match phase_byte % 4 {
                0 => Phase::PrePrepare,
                1 => Phase::Prepare,
                2 => Phase::Commit,
                _ => Phase::ViewChange,
            };

            let signature = bls12_381::G1Projective::generator();

            let msg = PbftMessage {
                phase,
                view,
                seq,
                digest,
                sender_id,
                signature,
            };

            let _ = state.handle_message(&msg);
        }
    }
}
