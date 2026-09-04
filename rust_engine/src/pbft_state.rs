// File: src/pbft_state.rs (Refactored Certificate Verification using True Threshold BLS)

use crate::threshold_bls::verify_threshold_signature;
// ... (keep existing imports)

impl PreparedCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        // Uses the cryptographically sound Threshold BLS Lagrange interpolation
        verify_threshold_signature(
            &canonical_msg, 
            b"PBFT_PREPARED_CERT_V1", 
            &self.signatures, 
            public_keys, 
            quorum_size
        )
    }
}

impl CommitCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Commit as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        // Uses the cryptographically sound Threshold BLS Lagrange interpolation
        verify_threshold_signature(
            &canonical_msg, 
            b"PBFT_COMMIT_CERT_V1", 
            &self.signatures, 
            public_keys, 
            quorum_size
        )
    }
}
