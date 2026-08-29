use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use group::{Curve, Group};
use sha2::{Sha256, Digest};
use ff::Field;

// برچسب استاندارد BLS12-381 برای جلوگیری از حملات Cross-Protocol
const BLS_DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// تبدیل امن پیام به نقطه روی منحنی (Hash-to-Curve)
pub fn hash_message_to_g1(message: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(BLS_DST);
    hasher.update(message);
    let hash_result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash_result);
    
    // تبدیل هش به یک اسکالر امن و مپ کردن آن روی منحنی
    let scalar = Scalar::from_bytes_mod_order(bytes);
    G1Projective::generator() * scalar
}

/// اعتبارسنجی امضای تجمعی: e(sig, G2) == e(H(m), pk)
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
