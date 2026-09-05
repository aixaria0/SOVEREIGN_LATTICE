use bls12_381::{G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct DkgShareMessage {
    pub from_node: u32,
    pub to_node: u32,
    pub share: Scalar,
    pub commitments: Vec<G2Projective>,
}

impl DkgShareMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.from_node.to_be_bytes());
        buf.extend_from_slice(&self.to_node.to_be_bytes());
        buf.extend_from_slice(&self.share.to_bytes());

        let num_commits = self.commitments.len() as u32;
        buf.extend_from_slice(&num_commits.to_be_bytes());
        for commit in &self.commitments {
            buf.extend_from_slice(&commit.to_affine().to_compressed());
        }
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 + 4 + 32 + 4 {
            return Err("BYTE_LENGTH_TOO_SHORT");
        }
        let from_node = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let to_node = u32::from_be_bytes(bytes[4..8].try_into().unwrap());

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[8..40]);
        let s_opt: Option<Scalar> = Scalar::from_bytes(&s_bytes).into();
        let share = s_opt.ok_or("INVALID_SCALAR_BYTES")?;

        let num_commits = u32::from_be_bytes(bytes[40..44].try_into().unwrap()) as usize;
        let mut offset = 44;
        let mut commitments = Vec::with_capacity(num_commits);

        for _ in 0..num_commits {
            if offset + 96 > bytes.len() {
                return Err("COMMITMENT_BYTES_OUT_OF_BOUNDS");
            }
            let mut c_bytes = [0u8; 96];
            c_bytes.copy_from_slice(&bytes[offset..offset + 96]);
            let aff_opt: Option<G2Affine> = G2Affine::from_compressed(&c_bytes).into();
            let aff = aff_opt.ok_or("INVALID_G2_AFFINE_POINT")?;
            commitments.push(G2Projective::from(aff));
            offset += 96;
        }

        Ok(Self {
            from_node,
            to_node,
            share,
            commitments,
        })
    }
}

pub struct DkgSession {
    pub node_id: u32,
    pub threshold: usize,
    pub total_nodes: usize,
    pub secret_polynomial: Vec<Scalar>,
    pub commitments: Vec<G2Projective>,
    pub received_shares: HashMap<u32, Scalar>,
    pub received_commitments: HashMap<u32, Vec<G2Projective>>,
}

impl DkgSession {
    pub fn new(node_id: u32, threshold: usize, total_nodes: usize) -> Self {
        let mut rng = OsRng;
        let mut secret_polynomial = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            secret_polynomial.push(Scalar::random(&mut rng));
        }

        Self {
            node_id,
            threshold,
            total_nodes,
            secret_polynomial,
            commitments: Vec::new(),
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
        }
    }

    pub fn generate_commitments(&mut self) -> Vec<G2Projective> {
        if self.commitments.is_empty() {
            let g2 = G2Projective::generator();
            self.commitments = self
                .secret_polynomial
                .iter()
                .map(|coeff| g2 * coeff)
                .collect();
        }
        self.commitments.clone()
    }

    pub fn evaluate_share_for(&self, receiver_id: u32) -> Scalar {
        let x = Scalar::from((receiver_id + 1) as u64);
        let mut result = Scalar::zero();
        let mut x_pow = Scalar::one();

        for coeff in &self.secret_polynomial {
            result += *coeff * x_pow;
            x_pow *= x;
        }
        result
    }

    pub fn verify_share(
        receiver_id: u32,
        share: &Scalar,
        commitments: &[G2Projective],
    ) -> bool {
        let x = Scalar::from((receiver_id + 1) as u64);
        let lhs = G2Projective::generator() * share;

        let mut rhs = G2Projective::identity();
        let mut x_pow = Scalar::one();

        for c in commitments {
            rhs += *c * x_pow;
            x_pow *= x;
        }

        lhs == rhs
    }

    pub fn process_incoming_share(
        &mut self,
        sender_id: u32,
        share: Scalar,
        commitments: &[G2Projective],
    ) -> Result<(), &'static str> {
        if !Self::verify_share(self.node_id, &share, commitments) {
            return Err("INVALID_FELDMAN_COMMITMENT_SHARE");
        }
        self.received_shares.insert(sender_id, share);
        self.received_commitments.insert(sender_id, commitments.to_vec());
        Ok(())
    }

    pub fn finalize_dkg(
        &self,
        participants: &[u32],
    ) -> Result<(Scalar, G2Projective), &'static str> {
        if self.received_shares.len() + 1 < self.threshold {
            return Err("INSUFFICIENT_SHARES_FOR_FINALIZATION");
        }

        let mut total_share = self.evaluate_share_for(self.node_id);
        for &id in participants {
            if id == self.node_id {
                continue;
            }
            if let Some(sh) = self.received_shares.get(&id) {
                total_share += *sh;
            }
        }

        let mut master_pk = self.commitments[0];
        for &id in participants {
            if id == self.node_id {
                continue;
            }
            if let Some(commits) = self.received_commitments.get(&id) {
                master_pk += commits[0];
            }
        }

        Ok((total_share, master_pk))
    }
}
