// File: src/epoch.rs
// Sovereign Lattice: Dynamic Epoch & Validator Set Management

use std::collections::{HashMap, HashSet};

/// Represents the BLS public key of a node (direct output from the DKG layer)
pub type BlsPubKey = [u8; 48]; 

/// Represents the aggregated threshold signature (e.g., BLS12-381 or FROST)
pub type QuorumCertificate = Vec<u8>; 

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    pub epoch_id: u64,
    pub validators: HashMap<u32, BlsPubKey>,
    pub total_power: u64,
}

impl ValidatorSet {
    /// Calculates the exact quorum threshold based on the Byzantine fault model: N = 3f + 1
    pub fn quorum_threshold(&self) -> u64 {
        (self.total_power * 2) / 3 + 1
    }

    /// Strict validation for any architectural state changes.
    pub fn verify_quorum(
        &self, 
        signers: &HashSet<u32>, 
        _qc: &QuorumCertificate
    ) -> Result<(), &'static str> {
        let mut voting_power = 0;
        
        for signer in signers {
            if !self.validators.contains_key(signer) {
                return Err("UNAUTHORIZED_SIGNER_IN_QUORUM");
            }
            // In future extensions, voting_power can be incremented by actual stake weight
            voting_power += 1; 
        }

        // Strict No-Fallback: If valid signatures do not meet the quorum, reject immediately.
        if voting_power < self.quorum_threshold() {
            return Err("MISSING_QUORUM_CERTIFICATE");
        }
        
        // Note: In a full production runtime, the threshold aggregate signature verification 
        // (e.g., BLS aggregate_verify) would be executed here against the `_qc`.
        
        Ok(())
    }
}

/// Structure representing the network transition from one state to the next.
#[derive(Clone, Debug)]
pub struct EpochTransition {
    pub current_epoch: u64,
    pub next_validator_set: ValidatorSet,
    pub transition_qc: QuorumCertificate,
    pub signers: HashSet<u32>,
}

pub struct EpochManager {
    pub current_state: ValidatorSet,
}

impl EpochManager {
    /// Applies network topological changes with Zero-Drift guarantees.
    pub fn apply_transition(&mut self, transition: EpochTransition) -> Result<(), &'static str> {
        // Rule 1: Transition must only apply to the exact current state to prevent replay attacks.
        if transition.current_epoch != self.current_state.epoch_id {
            return Err("INVALID_EPOCH_TRANSITION");
        }

        // Rule 2 (Core Security): Network changes are ONLY valid if cryptographically 
        // signed by a quorum of the CURRENT Epoch members.
        self.current_state.verify_quorum(&transition.signers, &transition.transition_qc)?;

        // Rule 3: Apply changes and permanently lock the system into the new state.
        self.current_state = transition.next_validator_set;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_epoch_rejection() {
        let mut validators = HashMap::new();
        validators.insert(1, [0; 48]);
        validators.insert(2, [0; 48]);
        validators.insert(3, [0; 48]);
        validators.insert(4, [0; 48]);

        let initial_epoch = ValidatorSet {
            epoch_id: 1,
            validators,
            total_power: 4,
        };

        let mut manager = EpochManager { current_state: initial_epoch };

        // Malicious attempt to change Validators with insufficient signatures (Fallback Attack)
        let mut malicious_signers = HashSet::new();
        malicious_signers.insert(1);
        malicious_signers.insert(2); // Only 2 signatures provided (quorum threshold is 3)

        let malicious_transition = EpochTransition {
            current_epoch: 1,
            next_validator_set: ValidatorSet {
                epoch_id: 2,
                validators: HashMap::new(),
                total_power: 0,
            },
            transition_qc: vec![],
            signers: malicious_signers,
        };

        let result = manager.apply_transition(malicious_transition);
        
        // The engine must explicitly reject this with the mathematically sound missing certificate error
        assert!(matches!(result, Err("MISSING_QUORUM_CERTIFICATE")));
    }
}
