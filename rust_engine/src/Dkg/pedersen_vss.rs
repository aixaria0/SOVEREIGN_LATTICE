// File: src/pedersen_vss.rs

use bls12_381::{G2Projective, Scalar};
use rand::rngs::OsRng;
use ff::Field;
use crate::threshold_bls::independent_nums_g2_generator;

pub struct PedersenCommitment {
    pub g: G2Projective,
    pub h: G2Projective,
}

impl PedersenCommitment {
    pub fn new() -> Self {
        Self {
            g: G2Projective::generator(),
            // Securely uses the true NUMS generator without exposing the discrete log
            h: independent_nums_g2_generator(),
        }
    }

    pub fn commit(&self, secret: &Scalar, blinding_factor: &Scalar) -> G2Projective {
        (self.g * secret) + (self.h * blinding_factor)
    }

    pub fn generate_blinding_factor() -> Scalar {
        Scalar::random(&mut OsRng)
    }
}
