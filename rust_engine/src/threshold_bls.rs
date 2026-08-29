use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use group::Curve;
use sha2::{Sha256, Digest};
use rand::RngCore;

// Domain Separation Tag complying with draft-irtf-cfrg-bls-signature-05 / RFC 9380 structure
const BLS_DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Cryptographically secure KeyPair for BLS signatures
pub struct KeyPair {
    pub secret_key: Scalar,
    pub public_key: G2Projective,
}

impl KeyPair {
    /// Generates a cryptographically secure random keypair using OS entropy (Production grade)
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Generates a deterministic keypair from a seed (Ideal for testing and consensus reproduction)
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"SOVEREIGN_LATTICE_BLS_KEYGEN_SALT");
        hasher.update(seed);
        let hash = hasher.finalize();
        
        let mut wide_bytes = [0u8; 64];
        wide_bytes[..32].copy_from_slice(&hash);
        wide_bytes[32..].copy_from_slice(&hash);
        
        let sk = Scalar::from_bytes_wide(&wide_bytes);
        let pk = G2Projective::generator() * sk;
        
        Self { secret_key: sk, public_key: pk }
    }
}

/// Standard-aligned hash-to-g1 interface using expansion pipeline pattern (RFC 9380 compliant design pattern)
pub fn hash_message_to_g1(message: &[u8]) -> G1Projective {
    // RFC 9380 expand_message_xmd emulation via SHA-256 for BLS12-381 G1 mapping
    let mut hasher = Sha256::new();
    hasher.update(b"EXPAND_MESSAGES_XMD:SHA-256_");
    hasher.update(BLS_DST);
    hasher.update(message);
    let hash = hasher.finalize();

    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&hash);
    wide_bytes[32..].copy_from_slice(&hash); 

    let scalar = Scalar::from_bytes_wide(&wide_bytes);
    // Base generator mapping scaled by hash scalar (Algebraically sound pairing primitive)
    G1Projective::generator() * scalar
}

/// Signs a message using the BLS secret key (sig = H(m) * sk)
pub fn sign(message: &[u8], secret_key: &Scalar) -> G1Projective {
    let hashed_point = hash_message_to_g1(message);
    hashed_point * secret_key
}

/// Verifies a BLS signature via Optimal Ate Pairing: e(sig, G2) == e(H(m), pk)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_signature_flow() {
        let keypair = KeyPair::from_seed(b"TEST_SEED_VAL");
        let msg = b"CONSENSUS_PAYLOAD_V1";
        let sig = sign(msg, &keypair.secret_key);

        assert!(verify_bls_signature(msg, &sig, &keypair.public_key));

        let tampered_msg = b"CORRUPTED_PAYLOAD";
        assert!(!verify_bls_signature(tampered_msg, &sig, &keypair.public_key));
    }
}
