use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::threshold_bls::{
    evaluation_point, lagrange_coefficient_at_zero, reconstruct_threshold_signature,
    verify_bound_threshold_signature,
};
use sovereign_lattice::pbft::{PbftState, PbftMessage, Phase};

#[test]
fn test_dkg_to_pbft_end_to_end_integration() {
    let n = 4;
    let threshold = 3; // quorum size for N=4 (2f + 1)

    // Step 1: Initialize DKG sessions for all N nodes
    let mut sessions: HashMap<u32, DkgSession> = HashMap::new();
    for id in 0..n as u32 {
        sessions.insert(id, DkgSession::new(id, threshold, n));
    }

    // Step 2: Generate and broadcast Feldman public commitments
    let mut all_commitments = HashMap::new();
    for (&id, session) in &sessions {
        all_commitments.insert(id, session.generate_commitments());
    }

    // Step 3: P2P share distribution and Feldman VSS verification
    // Each node evaluates its polynomial for every peer using the canonical evaluation domain
    for i in 0..n as u32 {
        for j in 0..n as u32 {
            if i == j {
                continue;
            }
            let share_val = sessions.get(&i).unwrap().evaluate_share_for(j);
            let commitments = all_commitments.get(&i).unwrap();
            
            sessions.get_mut(&j)
                .unwrap()
                .process_incoming_share(i, share_val, commitments)
                .expect("Feldman VSS validation failed during DKG share exchange!");
        }
    }

    // Step 4: Finalize DKG sessions and extract aggregated secret shares and master public key
    let expected_participants: Vec<u32> = (0..n as u32).collect();
    let mut aggregated_shares = HashMap::new();
    let mut master_pks = HashMap::new();
    let mut public_keys = HashMap::new();

    for (&id, session) in &sessions {
        let (secret_share, master_pk) = session.finalize_dkg(&expected_participants)
            .expect("DKG finalization failed!");
        
        aggregated_shares.insert(id, secret_share);
        master_pks.insert(id, master_pk);
        
        // Each node's public key derived from its secret share for basic auth
        public_keys.insert(id, G2Projective::generator() * secret_share);
    }

    // Assert that all nodes independently synthesized the exact same global master public key
    let canonical_master_pk = master_pks[&0];
    for (&id, pk) in &master_pks {
        assert_eq!(*pk, canonical_master_pk, "Split-brain detected: Node {} derived a mismatched master public key!", id);
    }

    // Step 5: Algebraic Identity Check
    // Reconstruct the master secret scalar from the shares using Lagrange interpolation at x = 0,
    // and verify that G2 * reconstructed_secret == canonical_master_pk.
    let mut participant_indices: Vec<u32> = aggregated_shares.keys().copied().collect();
    participant_indices.sort_unstable();
    participant_indices.truncate(threshold);

    let mut reconstructed_secret = Scalar::zero();
    for &idx in &participant_indices {
        let coeff = lagrange_coefficient_at_zero(idx, &participant_indices);
        reconstructed_secret += aggregated_shares[&idx] * coeff;
    }
    let derived_pk_from_secret = G2Projective::generator() * reconstructed_secret;
    assert_eq!(
        derived_pk_from_secret, canonical_master_pk,
        "Algebraic mismatch: Reconstructed secret scalar does not match master public key!"
    );

    // Step 6: Threshold Signing & PBFT Integration Test
    // Construct a canonical proposal payload for the Prepare phase
    let view = 0u64;
    let seq = 1u64;
    let digest = [0x77u8; 32];

    let mut canonical_msg = Vec::new();
    canonical_msg.push(Phase::Prepare as u8);
    canonical_msg.extend_from_slice(&view.to_be_bytes());
    canonical_msg.extend_from_slice(&seq.to_be_bytes());
    canonical_msg.extend_from_slice(&digest);

    // Nodes sign the canonical message using their DKG-derived secret shares
    let mut threshold_signatures = HashMap::new();
    let h_msg = sovereign_lattice::threshold_bls::hash_to_curve(&canonical_msg);
    
    for &id in &participant_indices {
        let sig = h_msg * aggregated_shares[&id];
        threshold_signatures.insert(id, sig);
    }

    // Verify the bound threshold signature directly against the DKG-derived canonical master PK
    let is_valid_threshold_sig = verify_bound_threshold_signature(
        &canonical_msg,
        &threshold_signatures,
        &canonical_master_pk,
        threshold,
    );
    assert!(
        is_valid_threshold_sig,
        "DKG-derived threshold signature failed bound verification against canonical master PK!"
    );

    // Step 7: Feed into PBFT State Engine
    let mut pbft_state = PbftState::new(n, public_keys, canonical_master_pk)
        .expect("Failed to initialize PBFT state with DKG keys");

    assert_eq!(pbft_state.master_public_key, canonical_master_pk);
}

