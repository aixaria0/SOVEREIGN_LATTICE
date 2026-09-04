use std::collections::HashMap;

pub type NodeId = u32;
pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(pub u64);

#[derive(Debug, Clone, Default)]
pub struct NodeState {
    pub prepared: HashMap<(u64, u64), [u8; 32]>,
    pub committed: HashMap<(u64, u64), [u8; 32]>,
    pub locked_digests: HashMap<u64, [u8; 32]>, 
}

impl NodeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_prepared(&mut self, view: u64, seq: u64, digest: [u8; 32]) -> Result<(), &'static str> {
        if let Some(locked_digest) = self.locked_digests.get(&seq) {
            if locked_digest != &digest {
                return Err("SAFETY_VIOLATION");
            }
        }
        self.prepared.insert((view, seq), digest);
        self.locked_digests.insert(seq, digest);
        Ok(())
    }

    pub fn mark_committed(&mut self, view: u64, seq: u64, digest: [u8; 32]) {
        self.committed.insert((view, seq), digest);
    }

    pub fn inherit_lock(&mut self, seq: u64, digest: [u8; 32]) {
        self.locked_digests.insert(seq, digest);
    }
}
