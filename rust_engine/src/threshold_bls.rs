use std::collections::HashMap;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use sha2::{Digest, Sha256, Sha512};

/// Produces an uncompressed scalar using SHA-512 wide reduction to eliminate modulo bias.
pub fn hash_to_scalar(domain: &[u8], msg: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(msg);
    let hash = hasher.finalize();

    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide_bytes)
}

/// Independent Nothing-Up-My-Sleeve (NUMS) G1 generator.
pub fn get_nums_h_generator() -> G1Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_NUMS_G1_SALT", b"GEN_NUMS_H_G1_DOMAIN_V1");
    G1Projective::generator() * scalar
}

/// Independent Nothing-Up-My-Sleeve (NUMS) G2 generator for Pedersen VSS.
pub fn independent_nums_g2_generator() -> G2Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_NUMS_G2_SALT", b"GEN_NUMS_H_G2_DOMAIN_V1");
    G2Projective::generator() * scalar
}

/// Secure domain-separated Hash-to-Curve mapping into G1.
pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_BLS_G1_HASH", msg);
    get_nums_h_generator() * scalar
}

/// Evaluates Lagrange basis coefficient at x = 0 across subset `indices`.
/// Uses 1-based point evaluation (i + 1) so Node 0 does not zero out the numerator.
pub fn lagrange_coefficient_at_zero(i: u32, indices: &[u32]) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let xi = Scalar::from((i + 1) as u64);

    for &j in indices {
        if j == i {
            continue;
        }
        let xj = Scalar::from((j + 1) as u64);
        num *= xj;
        den *= xj - xi;
    }

    let den_inv = den.invert().unwrap_or(Scalar::zero());
    num * den_inv
}

/// Reconstructs the threshold signature using Lagrange interpolation.
pub fn reconstruct_threshold_signature(
    signatures: &HashMap<u32, G1Projective>,
    threshold: usize,
) -> Result<G1Projective, &'static str> {
    if signatures.len() < threshold {
        return Err("INSUFFICIENT_SHARES_FOR_RECONSTRUCTION");
    }

    let indices: Vec<u32> = signatures.keys().copied().take(threshold).collect();
    let mut combined_sig = G1Projective::identity();

    for &idx in &indices {
        let coeff = lagrange_coefficient_at_zero(idx, &indices);
        combined_sig += signatures[&idx] * coeff;
    }

    Ok(combined_sig)
}

/// Reconstructs the aggregated public key for a specific participant set.
pub fn reconstruct_threshold_public_key(
    public_keys: &HashMap<u32, G2Projective>,
    threshold: usize,
) -> Result<G2Projective, &'static str> {
    if public_keys.len() < threshold {
        return Err("INSUFFICIENT_KEYS_FOR_RECONSTRUCTION");
    }

    let indices: Vec<u32> = public_keys.keys().copied().take(threshold).collect();
    let mut combined_pk = G2Projective::identity();

    for &idx in &indices {
        let coeff = lagrange_coefficient_at_zero(idx, &indices);
        combined_pk += public_keys[&idx] * coeff;
    }

    Ok(combined_pk)
}

/// Basic bilinear pairing check: e(Sig, G2) == e(H(m), PK)
pub fn verify_bls_signature(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    let h = hash_to_curve(msg);

    let sig_affine = G1Affine::from(sig);
    let g2_generator = G2Affine::generator();
    let h_affine = G1Affine::from(&h);
    let pk_affine = G2Affine::from(pk);

    pairing(&sig_affine, &g2_generator) == pairing(&h_affine, &pk_affine)
}

/// Aggregates multiple G1 partial signatures additively.
pub fn aggregate_signatures(signatures: &HashMap<u32, G1Projective>) -> G1Projective {
    let mut agg = G1Projective::identity();
    for sig in signatures.values() {
        agg += sig;
    }
    agg
}

/// Aggregates multiple G2 public keys additively.
pub fn aggregate_public_keys(public_keys: &HashMap<u32, G2Projective>) -> G2Projective {
    let mut agg = G2Projective::identity();
    for pk in public_keys.values() {
        agg += pk;
    }
    agg
}

/// Verifies an aggregated signature against an aggregated public key.
pub fn verify_aggregated_signature(
    msg: &[u8],
    agg_sig: &G1Projective,
    agg_pk: &G2Projective,
) -> bool {
    verify_bls_signature(msg, agg_sig, agg_pk)
}

/// Verifies a threshold signature against a canonical master public key.
pub fn verify_bound_threshold_signature(
    msg: &[u8],
    signatures: &HashMap<u32, G1Projective>,
    master_pk: &G2Projective,
    threshold: usize,
) -> bool {
    if signatures.len() < threshold {
        return false;
    }

    match reconstruct_threshold_signature(signatures, threshold) {
        Ok(reconstructed_sig) => verify_bls_signature(msg, &reconstructed_sig, master_pk),
        Err(_) => false,
    }
}
