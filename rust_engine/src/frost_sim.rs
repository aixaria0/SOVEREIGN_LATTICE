use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

// Simplified types
type Point = RistrettoPoint;
type Fr = Scalar;

#[derive(Clone)]
struct FrostShare {
    index: u32,
    secret: Fr,
}

#[derive(Clone)]
struct NoncePair {
    d: Fr, // first nonce
    e: Fr, // second nonce
    D: Point, // g^d
    E: Point, // g^e
}

#[derive(Clone)]
struct PartialSig {
    index: u32,
    z: Fr,
}

fn hash_to_scalar(data: &[u8]) -> Fr {
    let mut h = Sha512::new();
    h.update(data);
    let res = h.finalize();
    Fr::from_bytes_mod_order_wide(&res.try_into().unwrap())
}

/// Round 1: each participant generates a nonce pair (in real FROST this is done carefully)
fn generate_nonce() -> NoncePair {
    let mut rng = OsRng;
    let d = Fr::random(&mut rng);
    let e = Fr::random(&mut rng);
    NoncePair {
        d,
        e,
        D: &d * &RISTRETTO_BASEPOINT_POINT,
        E: &e * &RISTRETTO_BASEPOINT_POINT,
    }
}

/// Compute binding value and group commitment (simplified)
fn compute_group_commitment(
    nonces: &[(u32, NoncePair)],
    msg: &[u8],
) -> (Point, Vec<Fr>) {
    let mut rho = Vec::new();
    let mut R = Point::identity();

    for (i, nonce) in nonces {
        let mut data = Vec::new();
        data.extend_from_slice(&i.to_le_bytes());
        data.extend_from_slice(msg);
        data.extend_from_slice(nonce.D.compress().as_bytes());
        data.extend_from_slice(nonce.E.compress().as_bytes());
        let r = hash_to_scalar(&data);
        rho.push(r);
        R += nonce.D + (nonce.E * r);
    }
    (R, rho)
}

/// Each party produces a partial signature
fn frost_partial_sign(
    share: &FrostShare,
    nonce: &NoncePair,
    rho: Fr,
    R: &Point,
    pk: &Point,
    msg: &[u8],
) -> PartialSig {
    let mut data = Vec::new();
    data.extend_from_slice(R.compress().as_bytes());
    data.extend_from_slice(pk.compress().as_bytes());
    data.extend_from_slice(msg);
    let c = hash_to_scalar(&data); // challenge

    let z = nonce.d + (nonce.e * rho) + (share.secret * c);
    PartialSig {
        index: share.index,
        z,
    }
}

/// Aggregate partial signatures
fn frost_aggregate(partials: &[PartialSig]) -> Fr {
    let mut z = Fr::zero();
    for p in partials {
        z += p.z;
    }
    z
}
