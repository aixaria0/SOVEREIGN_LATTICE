use proptest::prelude::*;
use crate::pbft::{PbftState, PbftMessage, ViewChangePayload, Phase};
use std::collections::HashMap;

proptest! {
    #[test]
    fn fuzz_wire_parser(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = PbftMessage::from_bytes(&bytes);
        let _ = ViewChangePayload::from_bytes(&bytes);
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
            let sk = bls12_381::Scalar::from(i as u64 + 1);
            let pk = bls12_381::G2Projective::generator() * sk;
            initial_pks.insert(i, pk);
        }

        if let Ok(mut state) = PbftState::new(4, initial_pks) {
            let phase = match phase_byte % 4 {
                0 => Phase::PrePrepare,
                1 => Phase::Prepare,
                2 => Phase::Commit,
                _ => Phase::ViewChange,
            };

            let signature = bls12_381::G1Projective::generator();

            if phase == Phase::ViewChange {
                let vc = ViewChangePayload {
                    target_view: view,
                    prepared_view: view,
                    prepared_seq: seq,
                    digest,
                    sender_id,
                    signature,
                };
                let _ = state.handle_view_change_payload(&vc);
            } else {
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
}
