use std::collections::HashMap;
use bls12_381::G2Projective;
use sovereign_lattice::pbft::PbftState;
use sovereign_lattice::pbft_state::{Digest, NodeState, View};

#[test]
fn test_node_state_lifecycle() {
    let mut state = NodeState::new();
    let view = View(0);
    let seq = 1u64;
    let digest: Digest = [0xabu8; 32];

    assert!(!state.is_committed(view, seq, &digest));

    let prep_res = state.mark_prepared(view, seq, digest);
    assert!(prep_res.is_ok());
    assert_eq!(state.prepared.get(&(view, seq)), Some(&digest));

    let commit_res = state.mark_committed(view, seq, digest);
    assert!(commit_res.is_ok());
    assert!(state.is_committed(view, seq, &digest));
}

#[test]
fn test_cluster_quorum_initialization() {
    let total_nodes = 4usize;
    let mut public_keys = HashMap::new();
    for id in 0..total_nodes as u32 {
        public_keys.insert(id, G2Projective::generator());
    }

    let node = PbftState::new(total_nodes, public_keys);
    assert!(node.is_ok());

    let state = node.unwrap();
    assert_eq!(state.total_nodes, 4);
    assert_eq!(state.f, 1);
}
