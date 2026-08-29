use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::rngs::OsRng;
use std::collections::HashMap;

#[derive(Clone)]
pub struct DKGShare {
    pub index: u32,
    pub secret_share: Scalar,
}

#[derive(Clone)]
pub struct DKGCommitment {
    pub index: u32,
    pub commitments: Vec<G2Projective>, // Feldman commitments: g^{a0}, g^{a1}, ...
}

pub struct DKGOutput {
    pub secret_share: Scalar, // party's own share
    pub public_key: G2Projective, // group public key
    pub verification_points: Vec<G2Projective>, // for later share verification
}

/// Each party runs this locally (simplified single-threaded simulation)
pub fn run_feldman_dkg(n: u32, t: u32) -> Vec<DKGOutput> {
    let mut rng = OsRng;

    // Each party generates a random polynomial of degree t-1
    let mut all_commits: Vec<DKGCommitment> = Vec::new();
    let mut all_shares: HashMap<(u32, u32), Scalar> = HashMap::new(); // (from, to) -> share

    for i in 1..=n {
        // Generate polynomial coefficients
        let mut coeffs = Vec::with_capacity(t as usize);
        for _ in 0..t {
            coeffs.push(Scalar::random(&mut rng));
        }

        // Feldman commitments: C_k = g^{a_k}
        let commits: Vec<G2Projective> = coeffs
            .iter()
            .map(|a| G2Projective::generator() * a)
            .collect();

        all_commits.push(DKGCommitment {
            index: i,
            commitments: commits,
        });

        // Evaluate shares for every party j
        for j in 1..=n {
            let x = Scalar::from(j as u64);
            let mut y = Scalar::zero();
            let mut pow = Scalar::one();
            for &c in &coeffs {
                y += c * pow;
                pow *= x;
            }
            all_shares.insert((i, j), y);
        }
    }

    // Each party i sums the shares it received
    let mut outputs = Vec::new();
    for i in 1..=n {
        let mut my_share = Scalar::zero();
        for j in 1..=n {
            my_share += all_shares[&(j, i)];
        }

        // Group public key = product of all C_0 commitments
        let mut pk = G2Projective::identity();
        for c in &all_commits {
            pk += c.commitments[0];
        }

        outputs.push(DKGOutput {
            secret_share: my_share,
            public_key: pk,
            verification_points: all_commits.iter().map(|c| c.commitments[0]).collect(),
        });
    }

    outputs
}
