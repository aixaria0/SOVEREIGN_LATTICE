use std::collections::HashMap;
use bls12_381::{G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use crate::pedersen_vss::{verify_feldman_share, evaluation_point};

pub struct DkgSession {
    pub node_id: u32,
    pub threshold: usize,
    pub total_nodes: usize,
    pub my_secret_polynomial_coefficients: Vec<Scalar>,
    pub my_secret_share: Scalar,
    pub received_shares: HashMap<u32, Scalar>,
    pub public_commitments: HashMap<u32, Vec<G2Projective>>,
}

impl DkgSession {
    pub fn new(node_id: u32, threshold: usize, total_nodes: usize) -> Self {
        let mut coefficients = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            coefficients.push(Scalar::random(&mut OsRng));
        }

        let eval_pt = evaluation_point(node_id);
        let mut my_secret_share = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &coefficients {
            my_secret_share += *coeff * x_pow;
            x_pow *= eval_pt;
        }

        Self {
            node_id,
            threshold,
            total_nodes,
            my_secret_polynomial_coefficients: coefficients,
            my_secret_share,
            received_shares: HashMap::new(),
            public_commitments: HashMap::new(),
        }
    }

    pub fn generate_commitments(&self) -> Vec<G2Projective> {
        self.my_secret_polynomial_coefficients
            .iter()
            .map(|coeff| G2Projective::generator() * coeff)
            .collect()
    }

    pub fn evaluate_share_for(&self, recipient_id: u32) -> Scalar {
        let eval_pt = evaluation_point(recipient_id);
        let mut evaluation = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &self.my_secret_polynomial_coefficients {
            evaluation += *coeff * x_pow;
            x_pow *= eval_pt;
        }
        evaluation
    }

    pub fn process_incoming_share(
        &mut self,
        sender_id: u32,
        secret_share: Scalar,
        commitments: &[G2Projective],
    ) -> Result<(), &'static str> {
        if commitments.len() != self.threshold {
            return Err("INVALID_COMMITMENT_LENGTH: Feldman commitment vector length does not match threshold.");
        }

        if !verify_feldman_share(self.node_id, &secret_share, commitments) {
            return Err("FELDMAN_VERIFICATION_FAILED: Received share violates cryptographic polynomial commitments.");
        }

        self.received_shares.insert(sender_id, secret_share);
        self.public_commitments.insert(sender_id, commitments.to_vec());
        Ok(())
    }

    pub fn finalize_dkg(&self, expected_participants: &[u32]) -> Result<(Scalar, G2Projective), &'static str> {
        if self.received_shares.len() < self.threshold {
            return Err("INSUFFICIENT_SHARES: DKG session lacks enough verified shares to finalize.");
        }

        for &participant_id in expected_participants {
            if participant_id != self.node_id && !self.received_shares.contains_key(&participant_id) {
                return Err("DTS_MISMATCH: Missing verified share from an expected network participant.");
            }
        }

        let mut aggregated_secret_share = self.my_secret_share;
        for share in self.received_shares.values() {
            aggregated_secret_share += *share;
        }

        let mut master_pk = G2Projective::identity();
        for commitments in self.public_commitments.values() {
            if let Some(c0) = commitments.first() {
                master_pk += *c0;
            }
        }
        if let Some(my_c0) = self.generate_commitments().first() {
            master_pk += *my_c0;
        }

        Ok((aggregated_secret_share, master_pk))
    }
}
