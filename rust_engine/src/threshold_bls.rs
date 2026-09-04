use std::collections::HashMap;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use sha2::{Digest, Sha256, Sha512};

/// Canonical evaluation domain mapping ensuring strict synchronization across
/// DKG share generation, Feldman VSS verification, and Lagrange interpolation
/// (1-indexed to protect secret constant coefficient a_0 at x = 0).
#[inline]
pub fn evaluation_point(node_id: u32) -> Scalar {
    Scalar::from((node_id + 1) as u64)
}

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

/// Generates a strict Nothing-Up-My-Sleeve (NUMS) G2 point via Try-and-Increment.
pub fn get_nums_h_g2_generator() -> G2Projective {
    for counter in 0u32..10000 {
        let mut hasher = Sha256::new();
        hasher.update(b"SOVEREIGN_LATTICE_NUMS_G2_DERIVATION_V2");
        hasher.update(&counter.to_be_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 96];
        bytes[0..32].copy_from_slice(&hash);
        bytes[32..64].copy_from_slice(&hash);
        bytes[64..96].copy_from_slice(&hash);
        
        bytes[0] |= 0x80;

        let opt_affine: Option<G2Affine> = G2Affine::from_compressed(&bytes).into();
        if let Some(affine) = opt_affine {
            let point = G2Projective::from(affine);
            if !bool::from(point.is_identity()) {
                return point;
            }
        }
    }
    panic!("CRYPTOGRAPHIC_FAILURE: Failed to derive independent NUMS G2 generator within iteration bounds.");
}

/// Domain-separated G1 hash mapping using SHA-512 wide scalar reduction.
pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_BLS_G1_HASH", msg);
    G1Projective::generator() * scalar
}

/// Computes the Lagrange basis polynomial coefficient at x = 0 for node `i` over a set of participant indices
/// using the canonical 1-indexed evaluation domain.
pub fn lagrange_coefficient_at_zero(i: u32, indices: &[u32]) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let xi = evaluation_point(i);

    for &j in indices {
        if j == i {
            continue;
        }
        let xj = evaluation_point(j);
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
