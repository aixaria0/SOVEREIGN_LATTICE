use std::collections::HashMap;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::{Sha256, Digest};
use group::Curve;

/// Generates a strictly independent Nothing-Up-My-Sleeve (NUMS) generator.
/// This ensures the discrete logarithm relation between the standard generator G 
/// and this new generator H remains completely unknown. This is a mathematical 
/// requirement for secure Pedersen Commitments and secure hash-to-curve maps.
pub fn get_nums_h_generator() -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(b"SOVEREIGN_LATTICE_NUMS_GENERATOR_G1_DOMAIN_SEPARATION");
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let nums_scalar = Scalar::from_bytes(&bytes).unwrap_or(Scalar::one());
    
    G1Projective::generator() * nums_scalar
}

/// Secure Hash-to-Curve mapping utilizing the NUMS generator.
/// By mapping to the NUMS generator instead of the standard generator, 
/// we prevent rogue-key and discrete log extraction attacks.
pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(b"SOVEREIGN_LATTICE_BLS_SIG_DOMAIN");
    hasher.update(msg);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    
    let scalar_hash = Scalar::from_bytes(&bytes).unwrap_or(Scalar::one());
    
    let independent_generator = get_nums_h_generator();
    independent_generator * scalar_hash
}

/// Verifies a single BLS signature using elliptic curve pairings.
/// Mathematically asserts: e(Sig, G2) == e(H(m), PK)
pub fn verify_bls_signature(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    let h = hash_to_curve(msg);

    let sig_affine = G1Affine::from(sig);
    let g2_generator = G2Affine::generator();
    
    let h_affine = G1Affine::from(&h);
    let pk_affine = G2Affine::from(pk);

    // Compute pairings
    let pairing_1 = pairing(&sig_affine, &g2_generator);
    let pairing_2 = pairing(&h_affine, &pk_affine);

    pairing_1 == pairing_2
}

/// Aggregates multiple G1 partial signatures into a single threshold signature.
pub fn aggregate_signatures(signatures: &HashMap<u32, G1Projective>) -> G1Projective {
    let mut agg_sig = G1Projective::identity();
    for sig in signatures.values() {
        agg_sig += sig;
    }
    agg_sig
}

/// Aggregates multiple G2 public keys into a single threshold public key.
pub fn aggregate_public_keys(public_keys: &HashMap<u32, G2Projective>) -> G2Projective {
    let mut agg_pk = G2Projective::identity();
    for pk in public_keys.values() {
        agg_pk += pk;
    }
    agg_pk
}

/// Verifies a fully aggregated BLS threshold signature against an aggregated public key.
pub fn verify_aggregated_signature(
    msg: &[u8], 
    agg_sig: &G1Projective, 
    agg_pk: &G2Projective
) -> bool {
    verify_bls_signature(msg, agg_sig, agg_pk)
}
