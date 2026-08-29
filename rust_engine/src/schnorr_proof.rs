use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct SchnorrProof {
    pub R: G2Projective, // commitment / nonce point
    pub s: Scalar, // response
}

/// Domain-separation tag to avoid cross-protocol attacks
const DST: &[u8] = b"FELDMAN_VSS_SCHNORR_PROOF_V1";

fn challenge(base: &G2Projective, commitment: &G2Projective, R: &G2Projective) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(DST);
    hasher.update(base.to_affine().to_bytes());
    hasher.update(commitment.to_affine().to_bytes());
    hasher.update(R.to_affine().to_bytes());
    let hash = hasher.finalize();
    // Wide reduction into scalar field
    Scalar::from_bytes_wide(&{
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash);
        wide
    })
}

/// Prove knowledge of secret such that commitment = base * secret
pub fn schnorr_prove(base: G2Projective, secret: Scalar) -> (G2Projective, SchnorrProof) {
    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);
    let R = base * r;
    let commitment = base * secret;

    let c = challenge(&base, &commitment, &R);
    let s = r + c * secret;

    (commitment, SchnorrProof { R, s })
}

/// Verify the proof
pub fn schnorr_verify(
    base: G2Projective,
    commitment: G2Projective,
    proof: &SchnorrProof,
) -> bool {
    let c = challenge(&base, &commitment, &proof.R);
    let lhs = base * proof.s;
    let rhs = proof.R + commitment * c;
    lhs == rhs
}

