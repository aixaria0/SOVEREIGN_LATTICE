use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective};
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase, ViewChangePayload};

#[test]
fn test_four_node_cluster_topology_and_leader_rotation() {
    let n = 4;
    let mut public_keys = HashMap::new();
    for id in 0..n as u32 {
        public_keys.insert(id, G2Projective::generator());
    }

    // Initialize 4 independent cluster nodes
    let mut cluster = Vec::new();
    for _ in 0..n {
        let node = PbftState::new(n, public_keys.clone()).expect("Failed to initialize cluster node");
        cluster.push(node);
    }

    // 1. Verify PBFT cluster topology invariants across all nodes
    for node in &cluster {
        assert_eq!(node.total_nodes, 4);
        assert_eq!(node.f, 1);
        assert_eq!(node.quorum_size, 3);
        assert_eq!(node.current_view, 0);
    }

    // 2. Verify deterministic round-robin leader schedule
    let reference_node = &cluster[0];
    assert_eq!(reference_node.get_expected_leader(0), 0);
    assert_eq!(reference_node.get_expected_leader(1), 1);
    assert_eq!(reference_node.get_expected_leader(2), 2);
    assert_eq!(reference_node.get_expected_leader(3), 3);
    assert_eq!(reference_node.get_expected_leader(4), 0); // Cycles back to node 0
}

#[test]
fn test_view_change_wire_protocol_roundtrip() {
    let payload = ViewChangePayload {
        target_view: 2,
        prepared_view: 1,
        prepared_seq: 10,
        digest: [0xAA; 32],
        sender_id: 3,
        signature: G1Projective::generator(),
    };

    // 1. Verify exact 109-byte ViewChange wire format
    let wire_bytes = payload.to_bytes();
    assert_eq!(wire_bytes.len(), 109);
    assert_eq!(wire_bytes[0], Phase::ViewChange as u8);

    // 2. Verify accurate deserialization
    let decoded = ViewChangePayload::from_bytes(&wire_bytes)
        .expect("Failed to decode valid ViewChange wire format");

    assert_eq!(decoded.target_view, 2);
    assert_eq!(decoded.prepared_view, 1);
    assert_eq!(decoded.prepared_seq, 10);
    assert_eq!(decoded.digest, [0xAA; 32]);
    assert_eq!(decoded.sender_id, 3);
}

#[test]
fn test_network_message_dispatcher_guardrails() {
    let n = 4;
    let mut public_keys = HashMap::new();
    for id in 0..n as u32 {
        public_keys.insert(id, G2Projective::generator());
    }

    let mut node = PbftState::new(n, public_keys).expect("Failed to initialize node");

    // 1. Dispatching malformed short frame must be caught safely without panicking
    let corrupt_payload = vec![0x00, 0x01, 0x02];
    node.process_network_message(&corrupt_payload);

    // 2. Dispatching 101-byte message with invalid sender must be caught safely
    let dummy_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: [0x11; 32],
        sender_id: 999, // Unregistered node
        signature: G1Projective::generator(),
    };
    node.process_network_message(&dummy_msg.to_bytes());

    // 3. Node state must remain uncorrupted
    assert_eq!(node.current_view, 0);
    assert_eq!(node.highest_seq, 0);
}

