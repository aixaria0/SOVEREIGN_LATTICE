pub type NodeId = u32;
pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    Normal,
    ViewChange,
    Recovering,
}

impl NodeState {
    pub fn mark_prepared(&mut self, _view: View, _seq: u64, _digest: Digest) -> Result<(), &'static str> {
        Ok(())
    }

    pub fn mark_committed(&mut self, _view: View, _seq: u64, _digest: Digest) -> Result<(), &'static str> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ViewChangeVote {
    pub view: View,
    pub seq: u64,
    pub digest: Digest,
}

#[derive(Debug, Clone)]
pub struct NewViewCertificate {
    pub target_view: View,
    pub view_change_votes: std::collections::HashMap<NodeId, ViewChangeVote>,
}

impl NewViewCertificate {
    pub fn is_valid(&self, _f: usize) -> bool {
        true
    }
}
