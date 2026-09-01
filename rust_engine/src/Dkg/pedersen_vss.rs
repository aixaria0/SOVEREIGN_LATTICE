// Same dependencies as previous Feldman example:
// bls12_381, ff, group, rand, sha2

use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const DST: &[u8] = b"PEDERSEN_VSS_V1";

#[derive(Clone)]
pub struct PedersenCommitment {
    pub dealer: u32,
    // C_k = g^{a_k} * h^{b_k}
    pub commitments: Vec<G2Projective>,
}

#[derive(Clone)]
pub struct PedersenShare {
    pub index: u32,
    pub value: Scalar,   // f(i) = a-share
    pub blind: Scalar,   // corresponding blinding share
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(DST);
    hasher.update(data);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide)
}

/// Derive a second independent generator h from g (simplified educational method)
pub fn independent_generator() -> G2Projective {
    let g = G2Projective::generator();
    // In production use a proper nothing-up-my-sleeve or hash-to-curve derivation
    g * hash_to_scalar(b"PEDERSEN_SECOND_GENERATOR")
}

/// Deal: generate polynomial + blinding polynomial, commitments, and shares
pub fn pedersen_deal(n: u32, t: u32, dealer_id: u32) -> (PedersenCommitment, Vec<PedersenShare>) {
    let mut rng = OsRng;
    let g = G2Projective::generator();
    let h = independent_generator();

    // Secret polynomial coefficients a0..a_{t-1}
    let mut a_coeffs = Vec::with_capacity(t as usize);
    // Blinding polynomial coefficients b0..b_{t-1}
    let mut b_coeffs = Vec::with_capacity(t as usize);

    for _ in 0..t {
        a_coeffs.push(Scalar::random(&mut rng));
        b_coeffs.push(Scalar::random(&mut rng));
    }

    // Commitments C_k = g^{a_k} * h^{b_k}
    let mut commitments = Vec::new();
    for k in 0..t as usize {
        let c = g * a_coeffs[k] + h * b_coeffs[k];
        commitments.push(c);
    }

    // Evaluate shares for every party
    let mut shares = Vec::new();
    for i in 1..=n {
        let x = Scalar::from(i as u64);

        let mut a_val = Scalar::ZERO;
        let mut b_val = Scalar::ZERO;
        let mut pow = Scalar::ONE;

        for k in 0..t as usize {
            a_val += a_coeffs[k] * pow;
            b_val += b_coeffs[k] * pow;
            pow *= x;
        }

        shares.push(PedersenShare {
            index: i,
            value: a_val,
            blind: b_val,
        });
    }

    (
        PedersenCommitment {
            dealer: dealer_id,
            commitments,
        },
        shares,
    )
}

/// Verify a Pedersen share against the public commitments
pub fn verify_pedersen_share(
    commitment: &PedersenCommitment,
    share: &PedersenShare,
) -> Result<(), &'static str> {
    let g = G2Projective::generator();
    let h = independent_generator();

    // Right-hand side: Π C_k^{i^k}
    let mut rhs = G2Projective::identity();
    let mut pow = Scalar::ONE;
    let x = Scalar::from(share.index as u64);

    for cmt in &commitment.commitments {
        rhs += cmt * pow;
        pow *= x;
    }

    // Left-hand side: g^{s_i} * h^{r_i}
    let lhs = g * share.value + h * share.blind;

    if lhs == rhs {
        Ok(())
    } else {
        Err("Pedersen share inconsistent with commitments")
    }
}
