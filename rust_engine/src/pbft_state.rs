use std::collections::HashMap;

pub type NodeId = u32;
pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(pub u64);

#[derive(Debug, Clone, Default)]
pub struct NodeState {
    pub prepared: HashMap<(View, u64), Digest>,
    pub committed: HashMap<(View, u64), Digest>,
    // Persistent lock to prevent cross-view equivocation
    pub locked_digests: HashMap<u64, Digest>, 
}

impl NodeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_prepared(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        // Critical safety check: if this sequence is already locked, the new digest must match exactly
        if let Some(locked_digest) = self.locked_digests.get(&seq) {
            if locked_digest != &digest {
                return Err("Safety Violation: Sequence is already locked to a different digest in a previous view");
            }
        }

        self.prepared.insert((view, seq), digest);
        // Once prepared, we lock it to this digest permanently
        self.locked_digests.insert(seq, digest);
        Ok(())
    }

    pub fn mark_committed(&mut self, view: View, seq: u64, digest: Digest) -> Result<(), &'static str> {
        self.committed.insert((view, seq), digest);
        Ok(())
    }

    pub fn is_committed(&self, view: View, seq: u64, digest: &Digest) -> bool {
        self.committed.get(&(view, seq)) == Some(digest)
    }

    // Added this method so we can firmly lock inherited digests later in pbft.rs
    // when we verify the NewView certificate
    pub fn inherit_lock(&mut self, seq: u64, digest: Digest) {
        self.locked_digests.insert(seq, digest);
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
