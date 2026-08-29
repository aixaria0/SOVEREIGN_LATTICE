// src/threshold_bls.rs

use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use ff::Field;
use group::{Curve, Group};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Share {
    pub index: u32,
    pub secret: Scalar,
}

#[derive(Clone, Debug)]
pub struct PublicKey(pub G2Projective);

#[derive(Clone, Debug)]
pub struct PartialSignature {
    pub index: u32,
    pub sig: G1Projective,
}

#[derive(Clone, Debug)]
pub struct AggregateSignature(pub G1Projective);

/// Hashes a simple message to the G1 group
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    
    // Convert hash to a point on the curve (simplified for demo purposes)
    G1Projective::generator() * Scalar::from_bytes_wide(&{
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash);
        wide
    })
}

/// Signs a message using the share of a specific node
pub fn partial_sign(share: &Share, msg: &[u8]) -> PartialSignature {
    let h = hash_to_g1(msg);
    PartialSignature {
        index: share.index,
        sig: h * share.secret,
    }
}

/// Calculates the Lagrange coefficient for signature combination
fn lagrange_coefficient(indices: &[u32], i: u32) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    let xi = Scalar::from(i as u64);

    for &j in indices {
        if j != i {
            let xj = Scalar::from(j as u64);
            num *= xj;
            den *= xj - xi;
        }
    }
    num * den.invert().unwrap()
}

/// Aggregates all partial signatures into a single, valid signature
pub fn aggregate(partials: &[PartialSignature]) -> AggregateSignature {
    let indices: Vec<u32> = partials.iter().map(|p| p.index).collect();
    let mut sig = G1Projective::identity();

    for p in partials {
        let lambda = lagrange_coefficient(&indices, p.index);
        sig += p.sig * lambda;
    }
    AggregateSignature(sig)
}

/// Verifies the aggregated signature against the group's public key
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &AggregateSignature) -> bool {
    let h = hash_to_g1(msg);
    // The magic of Pairing: e(sig, G2) == e(H(msg), pk)
    pairing(&sig.0.to_affine(), &G2Projective::generator().to_affine())
        == pairing(&h.to_affine(), &pk.0.to_affine())
}
