pub fn finalize_dkg(&self, expected_participants: &[u32]) -> Result<(Scalar, G2Projective), &'static str> {
    if self.received_shares.len() < self.threshold {
        return Err("INSUFFICIENT_SHARES: DKG session lacks enough verified shares to finalize.");
    }

    let mut aggregated_secret_share = self.my_secret_share;
    let mut master_pk = G2Projective::identity();

    // Add our own constant coefficient commitment (C_0)
    if let Some(my_c0) = self.generate_commitments().first() {
        master_pk += *my_c0;
    } else {
        return Err("INVALID_LOCAL_COMMITMENTS: Missing local C_0 constant coefficient.");
    }

    // Strictly aggregate ONLY from the canonical participant set
    for &participant_id in expected_participants {
        if participant_id == self.node_id {
            continue;
        }

        let share = self.received_shares.get(&participant_id)
            .ok_or("CANONICAL_VIOLATION: Missing verified share from canonical participant.")?;
        let commitments = self.public_commitments.get(&participant_id)
            .ok_or("CANONICAL_VIOLATION: Missing Feldman commitments from canonical participant.")?;

        aggregated_secret_share += *share;
        
        if let Some(c0) = commitments.first() {
            master_pk += *c0;
        } else {
            return Err("INVALID_PEER_COMMITMENTS: Peer commitment vector is empty.");
        }
    }

    Ok((aggregated_secret_share, master_pk))
}
