// tests/byzantine_cluster.rs

#[cfg(test)]
mod tests {
    // Import sovereign lattice consensus types
    // use sovereign_lattice::pbft::{NewViewCertificate, PreparedCertificate, ViewChangeVote, PbftError};

    #[test]
    fn test_strict_no_fallback_rejection() {
        // Simulate a Byzantine leader attempting to push a NewView with max_seq > 0 
        // but omitting the required PreparedCertificate (Fallback attack).
        let quorum_size = 3;
        let target_view = 2;
        
        // Mock votes claiming a maximum sequence of 5
        let votes = vec![
            ViewChangeVote { sender: 1, seq: 5, digest: 100 },
            ViewChangeVote { sender: 2, seq: 5, digest: 100 },
            ViewChangeVote { sender: 3, seq: 2, digest: 50 },
        ];
        
        let invalid_nc = NewViewCertificate {
            target_view,
            votes,
            selected_cert: None, // Violation: max_seq is 5 (> 0), but no certificate is provided.
        };

        let result = invalid_nc.verify(quorum_size);
        
        // The engine must explicitly reject this with a missing certificate error
        assert!(matches!(result, Err(PbftError::MissingQuorumCertificate)));
    }

    #[test]
    fn test_mismatched_sequence_rejection() {
        // Simulate a leader attempting to inject a prepared certificate whose sequence 
        // does not match the actual highest sequence claimed by the quorum.
        let quorum_size = 3;
        let target_view = 2;
        
        let votes = vec![
            ViewChangeVote { sender: 1, seq: 5, digest: 100 },
            ViewChangeVote { sender: 2, seq: 5, digest: 100 },
            ViewChangeVote { sender: 3, seq: 5, digest: 100 },
        ];
        
        // Mismatched certificate: claims seq 3, whereas quorum max_seq is 5
        let mismatched_cert = PreparedCertificate {
            view: 1,
            seq: 3, 
            digest: 100,
            signers: vec![1, 2, 3],
        };

        let invalid_nc = NewViewCertificate {
            target_view,
            votes,
            selected_cert: Some(mismatched_cert),
        };

        let result = invalid_nc.verify(quorum_size);
        
        // The verification must fail due to sequence divergence
        assert!(matches!(result, Err(PbftError::InvalidCertificateSequence)));
    }
}

