use std::collections::HashMap;

pub type NodeId = u32;
pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(pub u64);

#[derive(Debug, Clone, Default)]
pub struct NodeState {
    pub prepared: HashMap<(View, u64), Digest>,
    pub committed: HashMap<(View, u64), Digest>,
}

impl NodeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_prepared(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        self.prepared.insert((view, seq), digest);
        Ok(())
    }

    pub fn mark_committed(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        self.committed.insert((view, seq), digest);
        Ok(())
    }

    pub fn is_committed(&self, view: View, seq: u64, digest: &Digest) -> bool {
        self.committed.get(&(view, seq)) == Some(digest)
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
    pub view_change_votes: HashMap<NodeId, ViewChangeVote>,
}

impl NewViewCertificate {
    pub fn is_valid(&self, f: usize) -> bool {
        let quorum_needed = 2 * f + 1;
        if self.view_change_votes.len() < quorum_needed {
            return false;
        }

        // All bundled votes must target the certificate's designated view
        self.view_change_votes
            .values()
            .all(|vote| vote.view == self.target_view)
    }
}
