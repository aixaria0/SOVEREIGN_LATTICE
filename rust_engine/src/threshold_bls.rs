use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use group::Curve;
use sha2::{Digest, Sha256};

pub const BLS_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

pub fn hash_to_curve(msg: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, BLS_SIG_DST, &[])
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

pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&result);
    buf[32..].copy_from_slice(&result);

    Scalar::from_bytes_wide(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
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
