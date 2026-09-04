use std::collections::HashMap;
use crate::pbft::PbftState;
use crate::pbft_state::{Digest, NodeState, View};

pub struct ConsensusEngine {
    pub node_id: u32,
    pub state: NodeState,
    pub current_view: View,
}

impl ConsensusEngine {
    pub fn new(node_id: u32) -> Self {
        Self {
            node_id,
            state: NodeState::new(),
            current_view: View(0),
        }
    }

    pub fn process_consensus_payload(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        self.state.mark_prepared(view, seq, digest)?;
        self.state.mark_committed(view, seq, digest)
    }
}
