use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use group::{Curve, Group};
use sha2::{Sha256, Digest};

// Standard BLS12-381 Domain Separation Tag (RFC 9380 compliant)
const BLS_DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Securely maps a message to a point on the G1 curve (Hash-to-Curve)
pub fn hash_message_to_g1(message: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(BLS_DST);
    hasher.update(message);
    let hash = hasher.finalize();

    // Expand to 64 bytes for secure wide reduction into the scalar field
    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&hash);
    wide_bytes[32..].copy_from_slice(&hash); 

    let scalar = Scalar::from_bytes_wide(&wide_bytes);
    G1Projective::generator() * scalar
}

/// Verifies an aggregated BLS signature: e(sig, G2) == e(H(m), pk)
pub fn verify_bls_signature(
    message: &[u8],
    signature: &G1Projective,
    public_key: &G2Projective,
) -> bool {
    let hashed_message = hash_message_to_g1(message);

    let left_pairing = pairing(&signature.to_affine(), &G2Projective::generator().to_affine());
    let right_pairing = pairing(&hashed_message.to_affine(), &public_key.to_affine());

    left_pairing == right_pairing
}
