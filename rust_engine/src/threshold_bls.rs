use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use group::Curve;
use sha2::{Sha256, Digest};
use rand::RngCore;

// Custom Domain Separation for Prototype Signature (Explicitly NOT claiming RFC 9380 compliance)
const PROTOTYPE_DST: &[u8] = b"SOVEREIGN_LATTICE_PROTOTYPE_BLS_G1";

pub struct KeyPair {
    pub secret_key: Scalar,
    pub public_key: G2Projective,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

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

/// Prototype hash-to-curve wrapper (Algebraically sound pairing check, but lacks full SSWU map-to-curve pipeline)
pub fn hash_message_to_g1(message: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(PROTOTYPE_DST);
    hasher.update(message);
    let hash = hasher.finalize();

    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&hash);
    wide_bytes[32..].copy_from_slice(&hash); 

    let scalar = Scalar::from_bytes_wide(&wide_bytes);
    G1Projective::generator() * scalar
}

pub fn sign(message: &[u8], secret_key: &Scalar) -> G1Projective {
    let hashed_point = hash_message_to_g1(message);
    hashed_point * secret_key
}

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
    fn test_prototype_bls_pairing_sanity() {
        let keypair = KeyPair::from_seed(b"PROTOTYPE_SEED");
        let msg = b"LATTICE_TEST_MSG";
        let sig = sign(msg, &keypair.secret_key);

        assert!(verify_bls_signature(msg, &sig, &keypair.public_key));

        let tampered = b"TAMPERED_MSG";
        assert!(!verify_bls_signature(tampered, &sig, &keypair.public_key));
    }
}
