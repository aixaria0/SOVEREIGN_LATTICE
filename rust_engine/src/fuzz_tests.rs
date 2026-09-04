use proptest::prelude::*;
use crate::pbft::{PbftState, PbftMessage, Phase};
use crate::threshold_bls::KeyPair;
use std::collections::HashMap;

proptest! {
    /// Test 1: Wire Protocol Fuzzing
    /// Passing arbitrary byte streams (0 to 300 bytes) to the 101-byte fixed-size parser.
    /// Invariant: The parser must NEVER panic. It must safely return an Err on malformed input.
    #[test]
    fn fuzz_wire_parser(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = PbftMessage::from_bytes(&bytes);
    }

    /// Test 2: State Machine Adversarial Fuzzing
    /// Injecting completely random or malformed consensus messages into a live N=4 PBFT state machine.
    /// Invariant: The state machine must handle arbitrary adversarial inputs gracefully, 
    /// rejecting invalid signatures, wrong views, or malformed sequences without panicking.
    #[test]
    fn fuzz_state_machine_resilience(
        phase_byte in 0u8..10u8,
        view in any::<u64>(),
        seq in any::<u64>(),
        digest in proptest::array::uniform32(any::<u8>()),
        sender_id in 0u32..10u32
    ) {
        // Initialize minimal valid topology for N=4 (f=1)
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

            // Use generator as dummy signature (will trigger cryptographic auth failure safely)
            let signature = bls12_381::G1Projective::generator();

            let msg = PbftMessage {
                phase,
                view,
                seq,
                digest,
                sender_id,
                signature,
            };

            // Execute message handling under fuzzed inputs. 
            // It is completely expected to return Err(...), but it MUST NOT panic.
            let _ = state.handle_message(&msg);
        }
    }
}

