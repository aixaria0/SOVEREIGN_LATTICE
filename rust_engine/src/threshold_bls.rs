use std::collections::HashMap;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use sha2::{Digest, Sha512};

/// Derives a scalar without canonical modulo bias using SHA-512 wide reduction.
pub fn hash_to_scalar(domain: &[u8], msg: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(msg);
    let hash = hasher.finalize();

    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide_bytes)
}

/// Unbiasable Nothing-Up-My-Sleeve (NUMS) G2 generator for Pedersen VSS commitments.
pub fn get_nums_h_g2_generator() -> G2Projective {
    let scalar = hash_to_scalar(
        b"SOVEREIGN_LATTICE_NUMS_G2_DOMAIN_V1",
        b"NUMS_G2_TRANSPARENT_CONSTANT_982451653",
    );
    G2Projective::generator() * scalar
}

/// Alias export for pedersen_vss.rs compatibility.
pub fn independent_nums_g2_generator() -> G2Projective {
    get_nums_h_g2_generator()
}

/// Unbiasable Nothing-Up-My-Sleeve (NUMS) G1 generator.
pub fn get_nums_h_generator() -> G1Projective {
    let scalar = hash_to_scalar(
        b"SOVEREIGN_LATTICE_NUMS_G1_DOMAIN_V1",
        b"NUMS_G1_TRANSPARENT_CONSTANT_104729",
    );
    G1Projective::generator() * scalar
}

/// Maps a byte slice message into a G1 curve point using domain-separated hashing.
pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_BLS_SIG_DOMAIN", msg);
    G1Projective::generator() * scalar
}

/// Computes the Lagrange basis polynomial coefficient at x = 0 for node `i` over a set of participant indices.
pub fn lagrange_coefficient_at_zero(i: u32, indices: &[u32]) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let xi = Scalar::from(i as u64);

    for &j in indices {
        if j == i {
            continue;
        }
        let xj = Scalar::from(j as u64);
        num *= xj;
        den *= xj - xi;
    }

    let den_inv = den.invert().unwrap_or(Scalar::zero());
    num * den_inv
}

/// Reconstructs a threshold signature using deterministic Lagrange interpolation at x = 0.
pub fn reconstruct_threshold_signature(
    signatures: &HashMap<u32, G1Projective>,
    threshold: usize,
) -> Result<G1Projective, &'static str> {
    if signatures.len() < threshold {
        return Err("INSUFFICIENT_SHARES_FOR_RECONSTRUCTION");
    }

    let mut indices: Vec<u32> = signatures.keys().copied().collect();
    indices.sort_unstable();
    indices.truncate(threshold);

    let mut combined_sig = G1Projective::identity();

    for &idx in &indices {
        let coeff = lagrange_coefficient_at_zero(idx, &indices);
        combined_sig += signatures[&idx] * coeff;
    }

    Ok(combined_sig)
}

/// Reconstructs a threshold public key for a deterministic subset of participants.
pub fn reconstruct_threshold_public_key(
    public_keys: &HashMap<u32, G2Projective>,
    threshold: usize,
) -> Result<G2Projective, &'static str> {
    if public_keys.len() < threshold {
        return Err("INSUFFICIENT_KEYS_FOR_RECONSTRUCTION");
    }

    let mut indices: Vec<u32> = public_keys.keys().copied().collect();
    indices.sort_unstable();
    indices.truncate(threshold);

    let mut combined_pk = G2Projective::identity();

    for &idx in &indices {
        let coeff = lagrange_coefficient_at_zero(idx, &indices);
        combined_pk += public_keys[&idx] * coeff;
    }

    Ok(combined_pk)
}

/// Verifies a single BLS signature via pairing equality: e(sig, G2) == e(H(m), pk)
pub fn verify_bls_signature(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    let h = hash_to_curve(msg);

    let sig_affine = G1Affine::from(sig);
    let g2_generator = G2Affine::generator();
    let h_affine = G1Affine::from(&h);
    let pk_affine = G2Affine::from(pk);

    pairing(&sig_affine, &g2_generator) == pairing(&h_affine, &pk_affine)
}

/// Verifies a threshold signature directly against an explicit master public key.
/// Prevents sub-threshold ephemeral public key substitution attacks.
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
        Ok(sig) => verify_bls_signature(msg, &sig, master_pk),
        Err(_) => false,
    }
}

/// Aggregates individual G1 signatures via elliptic curve addition.
pub fn aggregate_signatures(signatures: &HashMap<u32, G1Projective>) -> G1Projective {
    let mut agg_sig = G1Projective::identity();
    for sig in signatures.values() {
        agg_sig += sig;
    }
    agg_sig
}

/// Aggregates individual G2 public keys via elliptic curve addition.
pub fn aggregate_public_keys(public_keys: &HashMap<u32, G2Projective>) -> G2Projective {
    let mut agg_pk = G2Projective::identity();
    for pk in public_keys.values() {
        agg_pk += pk;
    }
    agg_pk
}

/// Verifies an aggregated signature against an aggregated public key.
pub fn verify_aggregated_signature(
    msg: &[u8],
    agg_sig: &G1Projective,
    agg_pk: &G2Projective,
) -> bool {
    verify_bls_signature(msg, agg_sig, agg_pk)
}
