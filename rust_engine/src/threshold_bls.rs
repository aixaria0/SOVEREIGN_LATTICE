use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn evaluation_point(index: u32) -> Scalar {
    Scalar::from((index + 1) as u64)
}

pub fn lagrange_coefficient_at_zero(i: u32, indices: &[u32]) -> Scalar {
    let xi = evaluation_point(i);
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    for &j in indices {
        if i == j {
            continue;
        }
        let xj = evaluation_point(j);
        num *= xj;
        den *= xj - xi;
    }

    let den_inv = den.invert();
    if bool::from(den_inv.is_some()) {
        num * den_inv.unwrap()
    } else {
        Scalar::zero()
    }
}

pub fn reconstruct_threshold_signature(
    signatures: &HashMap<u32, G1Projective>,
) -> G1Projective {
    let indices: Vec<u32> = signatures.keys().copied().collect();
    let mut reconstructed = G1Projective::identity();
    for (&idx, &sig) in signatures {
        let coeff = lagrange_coefficient_at_zero(idx, &indices);
        reconstructed += sig * coeff;
    }
    reconstructed
}

pub fn verify_bound_threshold_signature(
    msg: &[u8],
    signatures: &HashMap<u32, G1Projective>,
    master_pk: &G2Projective,
    threshold: usize,
) -> bool {
    if signatures.len() < threshold {
        return false;
    }
    let reconstructed_sig = reconstruct_threshold_signature(signatures);
    verify_bls_signature(msg, &reconstructed_sig, master_pk)
}

pub fn hash_to_scalar(domain: &[u8], data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let result = hasher.finalize();

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&result);
    buf[32..].copy_from_slice(&result);

    Scalar::from_bytes_wide(&buf)
}

pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_BLS_CURVE_HASH", msg);
    G1Projective::generator() * scalar
}

pub fn sign_bls_message(msg: &[u8], sk: &Scalar) -> G1Projective {
    let point = hash_to_curve(msg);
    point * sk
}

pub fn verify_bls_signature(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    let h = hash_to_curve(msg);
    let left = pairing(&sig.to_affine(), &G2Projective::generator().to_affine());
    let right = pairing(&h.to_affine(), &pk.to_affine());
    left == right
}

pub fn aggregate_signatures(sigs: &[G1Projective]) -> G1Projective {
    let mut sum = G1Projective::identity();
    for s in sigs {
        sum += s;
    }
    sum
}

pub fn aggregate_public_keys(pks: &[G2Projective]) -> G2Projective {
    let mut sum = G2Projective::identity();
    for p in pks {
        sum += p;
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_bls_sign_and_verify() {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        let msg = b"Sovereign-Lattice PBFT Message Payload";

        let sig = sign_bls_message(msg, &sk);
        assert!(verify_bls_signature(msg, &sig, &pk));

        let wrong_msg = b"Tampered Message";
        assert!(!verify_bls_signature(wrong_msg, &sig, &pk));
    }

    #[test]
    fn test_signature_aggregation() {
        let msg = b"Consensus Quorum Proposal";
        let sk1 = Scalar::random(&mut OsRng);
        let pk1 = G2Projective::generator() * sk1;
        let sk2 = Scalar::random(&mut OsRng);
        let pk2 = G2Projective::generator() * sk2;

        let sig1 = sign_bls_message(msg, &sk1);
        let sig2 = sign_bls_message(msg, &sk2);

        let agg_sig = aggregate_signatures(&[sig1, sig2]);
        let agg_pk = aggregate_public_keys(&[pk1, pk2]);

        let h = hash_to_curve(msg);
        let left = pairing(&agg_sig.to_affine(), &G2Projective::generator().to_affine());
        let right = pairing(&h.to_affine(), &agg_pk.to_affine());
        assert_eq!(left, right);
    }
}
